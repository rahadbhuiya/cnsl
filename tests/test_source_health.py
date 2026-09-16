"""
tests/test_source_health.py -- log source health monitoring
(cnsl/source_health.py) and its wiring into log_sources.py and the
dashboard.

Run:
    pytest tests/test_source_health.py -v
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

from cnsl.source_health import SourceHealthTracker


def _tracker(**overrides) -> SourceHealthTracker:
    cfg = {"source_health": {
        "enabled": True,
        "check_interval_sec": 60,
        "default_silence_threshold_sec": 900,
        **overrides,
    }}
    return SourceHealthTracker(cfg)


class TestConfig:
    def test_defaults(self):
        t = SourceHealthTracker({})
        assert t.enabled is True
        assert t.check_interval_sec == 60
        assert t.default_threshold == 900

    def test_reads_config(self):
        t = _tracker(check_interval_sec=30, default_silence_threshold_sec=120)
        assert t.check_interval_sec == 30
        assert t.default_threshold == 120

    def test_disabled(self):
        t = _tracker(enabled=False)
        assert t.enabled is False


class TestThresholds:
    def test_default_threshold_applies_when_no_override(self):
        t = _tracker(default_silence_threshold_sec=500)
        assert t.threshold_for("nginx") == 500

    def test_per_source_override(self):
        t = _tracker(default_silence_threshold_sec=500, per_source_thresholds={"mysql": 3600})
        assert t.threshold_for("mysql") == 3600
        assert t.threshold_for("nginx") == 500


class TestRegisterAndRecord:
    def test_register_source_appears_in_snapshot(self):
        t = _tracker()
        t.register_source("nginx")
        snap = t.status_snapshot(now_ts=1000.0)
        assert len(snap) == 1
        assert snap[0]["source"] == "nginx"

    def test_unregistered_source_not_in_snapshot(self):
        t = _tracker()
        t.record_activity("nginx", ts=1000.0)  # activity without registering
        snap = t.status_snapshot(now_ts=1000.0)
        assert snap == []

    def test_registering_does_not_reset_existing_last_seen(self):
        t = _tracker()
        t.record_activity("nginx", ts=1000.0)
        t.register_source("nginx")  # register after activity already recorded
        snap = t.status_snapshot(now_ts=1000.0)
        # setdefault should not clobber the existing timestamp
        assert snap[0]["silent_for_sec"] == 0.0

    def test_freshly_registered_source_seeds_last_seen_at_registration_time(self):
        # register_source() seeds last_seen to "now" -- a freshly-started
        # tailer for a naturally low-volume source (e.g. mysql's error
        # log, which may not write anything for hours) must not be
        # immediately flagged silent just because it hasn't produced a
        # line yet.
        t = _tracker()
        t.register_source("mysql")
        snap = t.status_snapshot(now_ts=t._last_seen["mysql"])
        assert snap[0]["last_seen"] is not None
        assert snap[0]["healthy"] is True
        assert snap[0]["silent_for_sec"] == 0.0


class TestStatusSnapshot:
    def test_healthy_within_threshold(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.record_activity("nginx", ts=1000.0)
        snap = t.status_snapshot(now_ts=1050.0)
        assert snap[0]["healthy"] is True
        assert snap[0]["silent_for_sec"] == 50.0

    def test_unhealthy_beyond_threshold(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.record_activity("nginx", ts=1000.0)
        snap = t.status_snapshot(now_ts=1200.0)
        assert snap[0]["healthy"] is False
        assert snap[0]["silent_for_sec"] == 200.0

    def test_snapshot_sorted_by_source_name(self):
        t = _tracker()
        for s in ("zeek_conn", "apache", "mysql"):
            t.register_source(s)
        snap = t.status_snapshot(now_ts=1000.0)
        assert [s["source"] for s in snap] == ["apache", "mysql", "zeek_conn"]


class TestTransitions:
    def test_no_transition_while_healthy(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.record_activity("nginx", ts=1000.0)
        assert t.check_transitions(now_ts=1050.0) == []

    def test_silent_transition_fires_once(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.record_activity("nginx", ts=1000.0)
        first = t.check_transitions(now_ts=1200.0)
        assert len(first) == 1
        assert first[0]["event"] == "source_silent"
        assert first[0]["source"] == "nginx"
        # Checking again with no new activity -- must not re-fire.
        second = t.check_transitions(now_ts=1250.0)
        assert second == []

    def test_recovery_transition_fires_once(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.record_activity("nginx", ts=1000.0)
        t.check_transitions(now_ts=1200.0)  # goes silent
        t.record_activity("nginx", ts=1300.0)  # recovers
        rec = t.check_transitions(now_ts=1301.0)
        assert len(rec) == 1
        assert rec[0]["event"] == "source_recovered"
        # No further transition on the next check.
        assert t.check_transitions(now_ts=1350.0) == []

    def test_multiple_sources_independent_transitions(self):
        t = _tracker(default_silence_threshold_sec=100)
        t.register_source("nginx")
        t.register_source("mysql")
        t.record_activity("nginx", ts=1000.0)
        t.record_activity("mysql", ts=1000.0)
        # Only nginx recovers activity; mysql goes silent.
        t.record_activity("nginx", ts=1150.0)
        transitions = t.check_transitions(now_ts=1200.0)
        assert len(transitions) == 1
        assert transitions[0]["source"] == "mysql"
        assert transitions[0]["event"] == "source_silent"

    def test_per_source_threshold_respected_in_transitions(self):
        t = _tracker(default_silence_threshold_sec=100, per_source_thresholds={"mysql": 1000})
        t.register_source("mysql")
        t.record_activity("mysql", ts=1000.0)
        # 200s of silence: would trip the default (100s) but not mysql's own (1000s).
        assert t.check_transitions(now_ts=1200.0) == []


class TestHealthLoop:
    def test_loop_noop_when_disabled(self):
        t = _tracker(enabled=False)
        logger = AsyncMock()
        # Should return immediately without sleeping or logging.
        asyncio.run(asyncio.wait_for(t.run_health_loop(logger), timeout=1.0))
        logger.log.assert_not_called()

    def test_loop_logs_transitions(self):
        t = _tracker(check_interval_sec=0, default_silence_threshold_sec=1)
        logger = AsyncMock()
        t.register_source("nginx")
        t.record_activity("nginx", ts=time.time() - 100)  # already silent

        async def go():
            task = asyncio.create_task(t.run_health_loop(logger))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        asyncio.run(go())
        logger.log.assert_any_call("source_silent", {
            "source": "nginx",
            "last_seen": logger.log.call_args_list[0].args[1]["last_seen"],
            "threshold_sec": 1,
            "healthy": False,
            "silent_for_sec": logger.log.call_args_list[0].args[1]["silent_for_sec"],
        })


class TestLogSourcesWiring:
    def test_get_log_tasks_registers_sources_with_tracker(self, tmp_path):
        import asyncio as _asyncio
        from cnsl.log_sources import get_log_tasks

        log_file = tmp_path / "access.log"
        log_file.write_text("")
        cfg = {"log_sources": {"nginx": str(log_file)}}
        queue = _asyncio.Queue()
        logger = AsyncMock()
        logger.log = AsyncMock()
        tracker = _tracker()

        async def go():
            tasks = get_log_tasks(cfg, queue, logger, health_tracker=tracker)
            await asyncio.sleep(0.05)  # let the tailer task start and register
            for task in tasks:
                task.cancel()
            for task in tasks:
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        asyncio.run(go())
        assert "nginx" in tracker._registered

    def test_tail_log_file_records_activity_on_each_line(self, tmp_path):
        import asyncio as _asyncio
        from cnsl.log_sources import tail_log_file

        log_file = tmp_path / "test.log"
        log_file.write_text("line one\nline two\n")
        queue = _asyncio.Queue()
        logger = AsyncMock()
        logger.log = AsyncMock()
        tracker = _tracker()

        def parser(line):
            return None  # doesn't matter for this test -- activity is tracked either way

        async def go():
            task = asyncio.create_task(
                tail_log_file(queue, str(log_file), parser, logger, "testsrc", tracker)
            )
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        asyncio.run(go())
        assert "testsrc" in tracker._registered
        assert tracker._last_seen.get("testsrc") is not None

    def test_tail_log_file_backward_compatible_without_tracker(self, tmp_path):
        """health_tracker defaults to None -- existing callers must keep working unchanged."""
        import asyncio as _asyncio
        from cnsl.log_sources import tail_log_file

        log_file = tmp_path / "test.log"
        log_file.write_text("a line\n")
        queue = _asyncio.Queue()
        logger = AsyncMock()
        logger.log = AsyncMock()

        async def go():
            task = asyncio.create_task(
                tail_log_file(queue, str(log_file), lambda l: None, logger, "testsrc")
            )
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        asyncio.run(go())  # must not raise


class TestDashboardWiring:
    async def _client(self, source_health=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_source_health import register_source_health_routes

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_source_health_routes(router, source_health, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_reports_disabled_when_not_wired(self):
        async def go():
            client = await self._client(source_health=None)
            r = await client.get("/api/source-health")
            data = await r.json()
            assert data == {"enabled": False, "sources": []}
            await client.close()
        asyncio.run(go())

    def test_reports_status_snapshot(self):
        async def go():
            t = _tracker()
            t.register_source("nginx")
            t.record_activity("nginx", ts=time.time())
            client = await self._client(source_health=t)
            r = await client.get("/api/source-health")
            data = await r.json()
            assert data["enabled"] is True
            assert len(data["sources"]) == 1
            assert data["sources"][0]["source"] == "nginx"
            await client.close()
        asyncio.run(go())


class TestValidator:
    def test_valid_config_no_errors(self):
        from cnsl.validator import _validate_source_health
        issues = []
        _validate_source_health({
            "enabled": True, "check_interval_sec": 60,
            "default_silence_threshold_sec": 900, "per_source_thresholds": {"mysql": 3600},
        }, issues)
        assert issues == []

    def test_check_interval_exceeding_threshold_warns(self):
        from cnsl.validator import _validate_source_health
        issues = []
        _validate_source_health({
            "enabled": True, "check_interval_sec": 1000,
            "default_silence_threshold_sec": 900,
        }, issues)
        assert len(issues) == 1
        assert "check_interval_sec" in issues[0].path

    def test_invalid_per_source_threshold_type_flagged(self):
        from cnsl.validator import _validate_source_health
        issues = []
        _validate_source_health({
            "enabled": True, "per_source_thresholds": {"mysql": "not-a-number"},
        }, issues)
        assert len(issues) == 1

    def test_per_source_thresholds_not_a_dict_flagged(self):
        from cnsl.validator import _validate_source_health
        issues = []
        _validate_source_health({"enabled": True, "per_source_thresholds": ["nope"]}, issues)
        assert len(issues) == 1

    def test_empty_config_is_noop(self):
        from cnsl.validator import _validate_source_health
        issues = []
        _validate_source_health({}, issues)
        assert issues == []