"""
tests/test_case_sla.py -- case SLA tracking and escalation
(cnsl/case_sla.py), plus wiring into cnsl/cases.py, the dashboard, and
the validator.

Run:
    pytest tests/test_case_sla.py -v
"""

from __future__ import annotations

import asyncio
import time

from cnsl.case_sla import CaseSLA
from cnsl.cases import CaseManager
from cnsl.store import Store


def _sla(**overrides) -> CaseSLA:
    cfg = {"case_sla": {
        "enabled": True,
        "escalate_on_breach": True,
        "bump_severity": True,
        **overrides,
    }}
    return CaseSLA(cfg)


async def _make_case_manager(tmp_path, name="test.db") -> CaseManager:
    store = Store({"store": {"db_path": str(tmp_path / name)}})
    ok = await store.init()
    assert ok, "store failed to initialize -- is aiosqlite installed?"
    cm = CaseManager(store)
    await cm.init()
    return cm


def _run(coro):
    return asyncio.run(coro)


#  Config


class TestConfig:
    def test_defaults(self):
        s = CaseSLA({})
        assert s.enabled is False
        assert s.check_interval_sec == 300
        assert s.targets["HIGH"]["response_minutes"] == 30
        assert s.targets["HIGH"]["resolution_minutes"] == 240

    def test_reads_partial_target_override(self):
        s = _sla(targets={"HIGH": {"response_minutes": 15}})
        assert s.targets["HIGH"]["response_minutes"] == 15
        assert s.targets["HIGH"]["resolution_minutes"] == 240

    def test_status_shape(self):
        s = _sla()
        status = s.status()
        assert set(status.keys()) == {
            "enabled", "check_interval_sec", "targets", "escalate_on_breach",
            "bump_severity", "notify_on_breach", "last_check_at", "last_result",
        }


#  evaluate_case -- pure function, no I/O


class TestEvaluateCase:
    def test_fresh_case_not_breached(self):
        s = _sla()
        case = {"id": 1, "severity": "HIGH", "status": "open",
                "created_at": time.time(), "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["breached"] is False

    def test_response_breach_when_unassigned_past_target(self):
        s = _sla()
        old = time.time() - 3600
        case = {"id": 1, "severity": "HIGH", "status": "open",
                "created_at": old, "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["response_breached"] is True
        assert report["breached"] is True

    def test_no_response_breach_once_assigned(self):
        s = _sla()
        old = time.time() - 3600
        case = {"id": 1, "severity": "HIGH", "status": "open",
                "created_at": old, "assigned_to": "alice"}
        report = s.evaluate_case(case)
        assert report["response_breached"] is False

    def test_no_response_breach_once_status_moved(self):
        s = _sla()
        old = time.time() - 3600
        case = {"id": 1, "severity": "HIGH", "status": "investigating",
                "created_at": old, "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["response_breached"] is False

    def test_resolution_breach_past_target(self):
        s = _sla()
        old = time.time() - 5 * 3600
        case = {"id": 1, "severity": "HIGH", "status": "investigating",
                "created_at": old, "assigned_to": "alice"}
        report = s.evaluate_case(case)
        assert report["resolution_breached"] is True

    def test_no_resolution_breach_once_resolved(self):
        s = _sla()
        old = time.time() - 100 * 3600
        case = {"id": 1, "severity": "HIGH", "status": "closed",
                "created_at": old, "assigned_to": "alice"}
        report = s.evaluate_case(case)
        assert report["resolution_breached"] is False
        assert report["response_breached"] is False
        assert report["breached"] is False

    def test_false_positive_status_counts_as_resolved(self):
        s = _sla()
        old = time.time() - 100 * 3600
        case = {"id": 1, "severity": "HIGH", "status": "false_positive",
                "created_at": old, "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["breached"] is False

    def test_unknown_severity_falls_back_to_medium_target(self):
        s = _sla()
        case = {"id": 1, "severity": "WEIRD", "status": "open",
                "created_at": time.time(), "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["response_target_sec"] == s.targets["MEDIUM"]["response_minutes"] * 60

    def test_missing_created_at_defaults_to_now_ts(self):
        s = _sla()
        now = time.time()
        case = {"id": 1, "severity": "HIGH", "status": "open", "assigned_to": None}
        report = s.evaluate_case(case, now_ts=now)
        assert report["age_sec"] == 0.0

    def test_custom_targets_respected(self):
        s = _sla(targets={"LOW": {"response_minutes": 5, "resolution_minutes": 10}})
        old = time.time() - 600
        case = {"id": 1, "severity": "LOW", "status": "open",
                "created_at": old, "assigned_to": None}
        report = s.evaluate_case(case)
        assert report["response_breached"] is True
        assert report["resolution_breached"] is True


#  check_once / escalation -- against a real CaseManager + Store


class TestCheckOnce:
    def test_noop_when_disabled(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            s = _sla(enabled=False)
            result = await s.check_once(cm)
            assert result["ran"] is False
            await cm._store.close()
        _run(go())

    def test_noop_when_case_manager_unavailable(self):
        async def go():
            s = _sla()
            result = await s.check_once(None)
            assert result["ran"] is False
        _run(go())

    def test_detects_and_escalates_breached_case(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla()
            result = await s.check_once(cm)
            assert result["breached"] == 1
            assert result["escalated"] == 1
            assert result["breaches"][0]["case_id"] == cid

            case = await cm.get(cid)
            notes = [n["body"] for n in case["notes"]]
            assert any(n.startswith("[SLA BREACH]") for n in notes)
            await cm._store.close()
        _run(go())

    def test_fresh_case_not_flagged(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            await cm.create_manual(title="new", severity="HIGH", src_ip="2.2.2.2")
            s = _sla()
            result = await s.check_once(cm)
            assert result["breached"] == 0
            assert result["escalated"] == 0
            await cm._store.close()
        _run(go())

    def test_resolved_case_excluded_from_check(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old resolved", severity="HIGH", src_ip="3.3.3.3")
            old = time.time() - 100 * 3600
            await cm._db.execute("UPDATE cases SET created_at=?, status='closed' WHERE id=?", (old, cid))
            await cm._db.commit()
            s = _sla()
            result = await s.check_once(cm)
            assert result["checked"] == 0
            await cm._store.close()
        _run(go())

    def test_second_check_does_not_re_escalate(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla()
            r1 = await s.check_once(cm)
            assert r1["escalated"] == 1
            r2 = await s.check_once(cm)
            assert r2["breached"] == 1
            assert r2["escalated"] == 0
            await cm._store.close()
        _run(go())

    def test_severity_bumped_on_escalation(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="MEDIUM", src_ip="1.1.1.1")
            old = time.time() - 30 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla(bump_severity=True)
            await s.check_once(cm)
            case = await cm.get(cid)
            assert case["severity"] == "HIGH"
            await cm._store.close()
        _run(go())

    def test_severity_not_bumped_when_disabled(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="MEDIUM", src_ip="1.1.1.1")
            old = time.time() - 30 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla(bump_severity=False)
            await s.check_once(cm)
            case = await cm.get(cid)
            assert case["severity"] == "MEDIUM"
            await cm._store.close()
        _run(go())

    def test_high_severity_bump_is_a_noop_terminal_case(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla(bump_severity=True)
            result = await s.check_once(cm)
            assert result["escalated"] == 1
            case = await cm.get(cid)
            assert case["severity"] == "HIGH"
            await cm._store.close()
        _run(go())

    def test_escalate_on_breach_disabled_skips_notes(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla(escalate_on_breach=False)
            result = await s.check_once(cm)
            assert result["breached"] == 1
            assert result["escalated"] == 0
            case = await cm.get(cid)
            assert not any(n["body"].startswith("[SLA BREACH]") for n in case["notes"])
            await cm._store.close()
        _run(go())

    def test_logs_breach_event(self, tmp_path):
        from unittest.mock import AsyncMock
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            logger = AsyncMock()
            logger.log = AsyncMock()
            s = _sla()
            await s.check_once(cm, logger=logger)
            assert logger.log.call_args.args[0] == "case_sla_breach"
            assert logger.log.call_args.args[1]["case_ids"] == [cid]
            await cm._store.close()
        _run(go())

    def test_no_log_event_when_nothing_breached(self, tmp_path):
        from unittest.mock import AsyncMock
        async def go():
            cm = await _make_case_manager(tmp_path)
            await cm.create_manual(title="new", severity="HIGH", src_ip="1.1.1.1")
            logger = AsyncMock()
            logger.log = AsyncMock()
            s = _sla()
            await s.check_once(cm, logger=logger)
            logger.log.assert_not_called()
            await cm._store.close()
        _run(go())


#  set_severity (cnsl/cases.py) -- added for case_sla's use


class TestSetSeverity:
    def test_changes_severity_and_notes(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="x", severity="LOW", src_ip="1.1.1.1")
            err = await cm.set_severity(cid, "HIGH", actor="tester")
            assert err is None
            case = await cm.get(cid)
            assert case["severity"] == "HIGH"
            assert any("Severity changed: LOW → HIGH" in n["body"] for n in case["notes"])
            await cm._store.close()
        _run(go())

    def test_invalid_severity_rejected(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="x", severity="LOW", src_ip="1.1.1.1")
            err = await cm.set_severity(cid, "CRITICAL")
            assert err is not None
            await cm._store.close()
        _run(go())

    def test_same_severity_is_noop(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="x", severity="HIGH", src_ip="1.1.1.1")
            err = await cm.set_severity(cid, "HIGH")
            assert err is None
            case = await cm.get(cid)
            assert not any("Severity changed" in n["body"] for n in case["notes"])
            await cm._store.close()
        _run(go())

    def test_unknown_case_errors(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            err = await cm.set_severity(99999, "HIGH")
            assert err is not None
            await cm._store.close()
        _run(go())


#  Background loop


class TestRunLoop:
    def test_loop_noop_when_disabled(self):
        from unittest.mock import AsyncMock
        async def go():
            s = _sla(enabled=False)
            logger = AsyncMock()
            await asyncio.wait_for(s.run_loop(None, logger), timeout=1.0)
            logger.log.assert_not_called()
        _run(go())


#  Validator


class TestValidator:
    def test_empty_config_is_noop(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({}, issues)
        assert issues == []

    def test_clean_config_no_issues(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({
            "enabled": True,
            "targets": {"HIGH": {"response_minutes": 30, "resolution_minutes": 240}},
        }, issues)
        assert issues == []

    def test_response_exceeding_resolution_warns(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({
            "enabled": True,
            "targets": {"HIGH": {"response_minutes": 500, "resolution_minutes": 100}},
        }, issues)
        assert len(issues) == 1
        assert issues[0].level == "warning"

    def test_unknown_severity_warns(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({"enabled": True, "targets": {"CRITICAL": {}}}, issues)
        assert len(issues) == 1
        assert issues[0].level == "warning"

    def test_negative_target_errors(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({
            "enabled": True,
            "targets": {"HIGH": {"response_minutes": -1, "resolution_minutes": 240}},
        }, issues)
        assert len(issues) == 1
        assert issues[0].level == "error"

    def test_targets_not_a_dict_errors(self):
        from cnsl.validator import _validate_case_sla
        issues = []
        _validate_case_sla({"enabled": True, "targets": ["nope"]}, issues)
        assert len(issues) == 1


#  Dashboard wiring


class TestDashboardWiring:
    async def _client(self, case_sla=None, case_manager=None, rbac=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_case_sla import register_case_sla_routes
        from unittest.mock import AsyncMock, MagicMock

        logger = AsyncMock()
        logger.log = AsyncMock()
        if rbac is None:
            rbac = MagicMock()
            rbac.require.return_value = None

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_case_sla_routes(router, case_sla, case_manager, logger, rbac, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_status_reports_disabled_when_not_wired(self):
        async def go():
            client = await self._client(case_sla=None)
            r = await client.get("/api/case-sla/status")
            data = await r.json()
            assert data == {"enabled": False}
            await client.close()
        _run(go())

    def test_status_reflects_policy(self):
        async def go():
            s = _sla()
            client = await self._client(case_sla=s)
            r = await client.get("/api/case-sla/status")
            data = await r.json()
            assert data["enabled"] is True
            await client.close()
        _run(go())

    def test_check_endpoint_errors_when_not_enabled(self):
        async def go():
            client = await self._client(case_sla=None)
            r = await client.post("/api/case-sla/check")
            assert r.status == 400
            await client.close()
        _run(go())

    def test_check_endpoint_errors_when_case_manager_unavailable(self):
        from unittest.mock import MagicMock
        async def go():
            s = _sla()
            cm = MagicMock()
            cm.available = False
            client = await self._client(case_sla=s, case_manager=cm)
            r = await client.post("/api/case-sla/check")
            assert r.status == 400
            await client.close()
        _run(go())

    def test_check_endpoint_triggers_a_pass(self, tmp_path):
        async def go():
            cm = await _make_case_manager(tmp_path)
            cid = await cm.create_manual(title="old", severity="HIGH", src_ip="1.1.1.1")
            old = time.time() - 10 * 3600
            await cm._db.execute("UPDATE cases SET created_at=? WHERE id=?", (old, cid))
            await cm._db.commit()

            s = _sla()
            client = await self._client(case_sla=s, case_manager=cm)
            r = await client.post("/api/case-sla/check")
            assert r.status == 200
            data = await r.json()
            assert data["breached"] == 1
            await cm._store.close()
            await client.close()
        _run(go())

    def test_check_endpoint_denied_without_permission(self):
        from unittest.mock import MagicMock
        from aiohttp import web
        async def go():
            rbac = MagicMock()
            rbac.require.return_value = web.json_response({"error": "forbidden"}, status=403)
            s = _sla()
            client = await self._client(case_sla=s, rbac=rbac)
            r = await client.post("/api/case-sla/check")
            assert r.status == 403
            await client.close()
        _run(go())