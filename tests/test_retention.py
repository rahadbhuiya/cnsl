"""
tests/test_retention.py -- data retention (cnsl/retention.py) and its
wiring into the dashboard and validator.

Run:
    pytest tests/test_retention.py -v
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import time

from cnsl.retention import RetentionPolicy
from cnsl.store import Store


def _policy(**overrides) -> RetentionPolicy:
    cfg = {"retention": {
        "enabled": True,
        "incidents_max_age_days": 90,
        "audit_log_max_age_days": 0,
        "archive_before_delete": False,
        **overrides,
    }}
    return RetentionPolicy(cfg)


async def _make_store(tmp_path, name="test.db") -> Store:
    store = Store({"store": {"db_path": str(tmp_path / name)}})
    ok = await store.init()
    assert ok, "store failed to initialize -- is aiosqlite installed?"
    return store


async def _insert_incident(store: Store, ts: float, src_ip: str) -> None:
    await store.db_execute(
        "INSERT INTO incidents (ts, time, src_ip, severity, reasons, fail_count, uniq_users, kind) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (ts, "t", src_ip, "HIGH", "[]", 5, 1, "SSH_FAIL"),
    )


def _run(coro):
    return asyncio.run(coro)


#  Config


class TestConfig:
    def test_defaults(self):
        p = RetentionPolicy({})
        assert p.enabled is False
        assert p.run_interval_hours == 24
        assert p.incidents_max_age_days == 90
        assert p.audit_log_max_age_days == 0  # compliance-safe default: never purge

    def test_reads_config(self):
        p = _policy(incidents_max_age_days=30, run_interval_hours=6)
        assert p.incidents_max_age_days == 30
        assert p.run_interval_hours == 6

    def test_status_shape(self):
        p = _policy()
        status = p.status()
        assert set(status.keys()) == {
            "enabled", "run_interval_hours", "incidents_max_age_days",
            "audit_log_max_age_days", "archive_before_delete", "archive_dir",
            "last_run_at", "last_result",
        }


#  run_once against a real Store


class TestRunOnce:
    def test_noop_when_disabled(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            p = _policy(enabled=False)
            result = await p.run_once(store)
            assert result["ran"] is False
            await store.close()
        _run(go())

    def test_noop_when_store_unavailable(self):
        async def go():
            p = _policy()
            result = await p.run_once(None)
            assert result["ran"] is False
        _run(go())

    def test_purges_old_incidents_only(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            now = time.time()
            await _insert_incident(store, now - 100 * 86400, "1.1.1.1")  # old
            await _insert_incident(store, now - 1 * 86400, "2.2.2.2")    # recent
            p = _policy(incidents_max_age_days=90)
            result = await p.run_once(store)
            assert result["incidents"]["purged"] == 1
            rows = await store.db_fetchall("SELECT * FROM incidents")
            assert len(rows) == 1
            assert rows[0]["src_ip"] == "2.2.2.2"
            await store.close()
        _run(go())

    def test_disabled_max_age_skips_purge(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            await _insert_incident(store, time.time() - 1000 * 86400, "1.1.1.1")
            p = _policy(incidents_max_age_days=0)
            result = await p.run_once(store)
            assert result["incidents"]["purged"] == 0
            assert result["incidents"].get("skipped")
            rows = await store.db_fetchall("SELECT * FROM incidents")
            assert len(rows) == 1  # untouched
            await store.close()
        _run(go())

    def test_second_run_is_idempotent(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            await _insert_incident(store, time.time() - 100 * 86400, "1.1.1.1")
            p = _policy(incidents_max_age_days=90)
            r1 = await p.run_once(store)
            assert r1["incidents"]["purged"] == 1
            r2 = await p.run_once(store)
            assert r2["incidents"]["purged"] == 0
            await store.close()
        _run(go())

    def test_updates_last_run_state(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            p = _policy()
            assert p.last_run_at is None
            await p.run_once(store)
            assert p.last_run_at is not None
            assert p.last_result["ran"] is True
            await store.close()
        _run(go())

    def test_logs_retention_run_event(self, tmp_path):
        from unittest.mock import AsyncMock
        async def go():
            store = await _make_store(tmp_path)
            await _insert_incident(store, time.time() - 100 * 86400, "1.1.1.1")
            logger = AsyncMock()
            logger.log = AsyncMock()
            p = _policy(incidents_max_age_days=90)
            await p.run_once(store, logger=logger)
            logger.log.assert_any_call("retention_run", {
                "incidents_purged": 1,
                "incidents_archived_to": None,
                "audit_log_purged": 0,
                "audit_log_archived_to": None,
            })
            await store.close()
        _run(go())


#  Archival


class TestArchival:
    def test_archives_before_deleting(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            await _insert_incident(store, time.time() - 100 * 86400, "9.9.9.9")
            archive_dir = tmp_path / "archives"
            p = _policy(incidents_max_age_days=90, archive_before_delete=True,
                        archive_dir=str(archive_dir))
            result = await p.run_once(store)
            path = result["incidents"]["archived_to"]
            assert path is not None
            assert os.path.exists(path)
            with gzip.open(path, "rt") as f:
                lines = [json.loads(l) for l in f]
            assert len(lines) == 1
            assert lines[0]["src_ip"] == "9.9.9.9"
            await store.close()
        _run(go())

    def test_no_archive_file_when_nothing_to_purge(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            archive_dir = tmp_path / "archives"
            p = _policy(incidents_max_age_days=90, archive_before_delete=True,
                        archive_dir=str(archive_dir))
            result = await p.run_once(store)
            assert result["incidents"]["archived_to"] is None
            await store.close()
        _run(go())

    def test_purge_count_correct_without_archiving(self, tmp_path):
        """archive_before_delete=False must still report an accurate purge count."""
        async def go():
            store = await _make_store(tmp_path)
            now = time.time()
            for i in range(3):
                await _insert_incident(store, now - 100 * 86400, f"1.1.1.{i}")
            p = _policy(incidents_max_age_days=90, archive_before_delete=False)
            result = await p.run_once(store)
            assert result["incidents"]["purged"] == 3
            assert result["incidents"]["archived_to"] is None
            rows = await store.db_fetchall("SELECT * FROM incidents")
            assert len(rows) == 0
            await store.close()
        _run(go())


#  audit_log opt-in


class TestAuditLogRetention:
    def test_not_purged_by_default(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            from cnsl.audit import AuditLog
            audit = AuditLog(store)
            await audit.init()
            await audit.record(actor="tester", action="test.action")
            p = _policy()  # audit_log_max_age_days defaults to 0
            result = await p.run_once(store, audit_log=audit)
            assert result["audit_log"]["purged"] == 0
            assert result["audit_log"].get("skipped") == "not configured"
            await store.close()
        _run(go())

    def test_purged_when_explicitly_configured(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            from cnsl.audit import AuditLog
            audit = AuditLog(store)
            await audit.init()
            old_ts = time.time() - 1000 * 86400
            await store.db_execute(
                "INSERT INTO audit_log (ts, time, actor, action, target, details, source_ip) "
                "VALUES (?,?,?,?,?,?,?)",
                (old_ts, "t", "tester", "old.action", None, "{}", None),
            )
            p = _policy(audit_log_max_age_days=365)
            result = await p.run_once(store, audit_log=audit)
            assert result["audit_log"]["purged"] == 1
            await store.close()
        _run(go())


#  Background loop


class TestRunLoop:
    def test_loop_noop_when_disabled(self):
        from unittest.mock import AsyncMock
        async def go():
            p = _policy(enabled=False)
            logger = AsyncMock()
            await asyncio.wait_for(p.run_loop(None, None, logger), timeout=1.0)
            logger.log.assert_not_called()
        _run(go())


#  Validator


class TestValidator:
    def test_disabled_config_is_noop(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({"enabled": False, "incidents_max_age_days": 1}, issues)
        assert issues == []  # disabled -> most checks skipped

    def test_clean_enabled_config_no_issues(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({
            "enabled": True, "incidents_max_age_days": 90,
            "archive_before_delete": True, "archive_dir": "/var/lib/cnsl/archives",
        }, issues)
        assert issues == []

    def test_aggressive_incidents_retention_warns(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({"enabled": True, "incidents_max_age_days": 2,
                              "archive_before_delete": False}, issues)
        assert len(issues) == 1
        assert issues[0].level == "warning"

    def test_short_audit_retention_warns(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({"enabled": True, "audit_log_max_age_days": 30,
                              "archive_before_delete": False}, issues)
        assert len(issues) == 1
        assert issues[0].level == "warning"
        assert "compliance" in issues[0].message

    def test_archive_enabled_without_dir_errors(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({"enabled": True, "archive_before_delete": True,
                              "archive_dir": ""}, issues)
        assert len(issues) == 1
        assert issues[0].level == "error"

    def test_negative_max_age_flagged(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({"enabled": True, "incidents_max_age_days": -5}, issues)
        assert len(issues) == 1

    def test_empty_config_is_noop(self):
        from cnsl.validator import _validate_retention
        issues = []
        _validate_retention({}, issues)
        assert issues == []


#  Dashboard wiring


class TestDashboardWiring:
    async def _client(self, retention=None, store=None, audit_log=None, rbac=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_retention import register_retention_routes
        from unittest.mock import AsyncMock, MagicMock

        logger = AsyncMock()
        logger.log = AsyncMock()
        if rbac is None:
            rbac = MagicMock()
            rbac.require.return_value = None  # permission granted

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_retention_routes(router, retention, store, audit_log, logger, rbac, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_status_reports_disabled_when_not_wired(self):
        async def go():
            client = await self._client(retention=None)
            r = await client.get("/api/retention/status")
            data = await r.json()
            assert data == {"enabled": False}
            await client.close()
        _run(go())

    def test_status_reflects_policy(self):
        async def go():
            p = _policy()
            client = await self._client(retention=p)
            r = await client.get("/api/retention/status")
            data = await r.json()
            assert data["enabled"] is True
            await client.close()
        _run(go())

    def test_run_endpoint_errors_when_not_enabled(self):
        async def go():
            client = await self._client(retention=None)
            r = await client.post("/api/retention/run")
            assert r.status == 400
            await client.close()
        _run(go())

    def test_run_endpoint_errors_when_store_unavailable(self):
        from unittest.mock import MagicMock
        async def go():
            p = _policy()
            store = MagicMock()
            store.available = False
            client = await self._client(retention=p, store=store)
            r = await client.post("/api/retention/run")
            assert r.status == 400
            await client.close()
        _run(go())

    def test_run_endpoint_triggers_a_pass(self, tmp_path):
        async def go():
            store = await _make_store(tmp_path)
            await _insert_incident(store, time.time() - 100 * 86400, "1.1.1.1")
            p = _policy(incidents_max_age_days=90)
            client = await self._client(retention=p, store=store)
            r = await client.post("/api/retention/run")
            assert r.status == 200
            data = await r.json()
            assert data["incidents"]["purged"] == 1
            await store.close()
            await client.close()
        _run(go())

    def test_run_endpoint_denied_without_permission(self):
        from unittest.mock import MagicMock
        from aiohttp import web
        async def go():
            rbac = MagicMock()
            rbac.require.return_value = web.json_response({"error": "forbidden"}, status=403)
            p = _policy()
            client = await self._client(retention=p, rbac=rbac)
            r = await client.post("/api/retention/run")
            assert r.status == 403
            await client.close()
        _run(go())