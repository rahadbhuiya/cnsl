"""
tests/test_cnsl.py — Unit tests for CNSL.

Run:
    pytest tests/ -v
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from cnsl.config import DEFAULT_CONFIG, load_config, safe_int
from cnsl.models import Event, EventKind, Severity, iso_time, now
from cnsl.parsers import parse_auth_event, parse_tcpdump_hint
from cnsl.detector import Detector, IPState, _prune, _unique_users



# Helpers


def make_cfg(**overrides):
    import json
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    for k, v in overrides.items():
        cfg["thresholds"][k] = v
    return cfg


def make_detector(cfg=None, **th_overrides):
    if cfg is None:
        cfg = make_cfg(**th_overrides)
    logger = AsyncMock()
    logger.log = AsyncMock()
    blocker = AsyncMock()
    blocker.is_blocked = MagicMock(return_value=False)
    blocker.block_ip = AsyncMock(return_value=True)
    return Detector(cfg, logger, blocker)



# Parser tests


class TestParseAuthEvent:
    def test_failed_password(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "1.2.3.4"

    def test_failed_password_invalid_user(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for invalid user admin from 5.6.7.8 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "5.6.7.8"
        assert ev.user == "admin"

    def test_accepted_password(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.src_ip == "10.0.0.1"
        assert ev.user == "alice"

    def test_accepted_publickey(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Accepted publickey for bob from 192.168.1.1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.user == "bob"

    def test_non_sshd_line_ignored(self):
        line = "Apr 15 10:00:00 srv kernel: Something else happened"
        assert parse_auth_event(line) is None

    def test_empty_line(self):
        assert parse_auth_event("") is None

    def test_authentication_failure(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: authentication failure; logname= uid=0 rhost=9.9.9.9"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "9.9.9.9"

    def test_ipv6_address(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from ::ffff:1.2.3.4 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert "::" in ev.src_ip


class TestParseTcpdumpHint:
    def test_arp_discovery(self):
        line = "10:00:00.000000 ARP, Request who-has 192.168.1.1 tell 192.168.1.2"
        ev = parse_tcpdump_hint(line)
        assert ev is not None
        assert ev.meta["hint"] == "DISCOVERY"

    def test_smb_enum_hint(self):
        line = "10:00:00.000000 IP 1.2.3.4.445 > 10.0.0.1.12345: Flags [S]"
        ev = parse_tcpdump_hint(line)
        assert ev is not None
        assert ev.meta["hint"] == "ENUM_HINT"

    def test_ntp_ignored(self):
        line = "10:00:00.000000 IP 10.0.0.1.123 > 8.8.8.8.123: NTPv4, Client"
        ev = parse_tcpdump_hint(line)
        assert ev is None

    def test_https_ignored(self):
        line = "10:00:00.000000 IP 10.0.0.1.54321 > 1.1.1.1.443: Flags [P]"
        ev = parse_tcpdump_hint(line)
        assert ev is None



# Config tests


class TestConfig:
    def test_defaults_loaded(self):
        cfg = load_config(None)
        assert cfg["thresholds"]["fails_threshold"] == 8
        assert cfg["actions"]["dry_run"] is True
        assert "127.0.0.1" in cfg["allowlist"]

    def test_safe_int(self):
        assert safe_int("8", 0) == 8
        assert safe_int("bad", 5) == 5
        assert safe_int(None, 3) == 3


# Detector tests


def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


class TestIPState:
    def test_prune_removes_old(self):
        dq = __import__('collections').deque()
        old = time.time() - 100
        recent = time.time()
        dq.append((old, 1))
        dq.append((recent, 1))
        _prune(dq, 60, time.time())
        assert len(dq) == 1

    def test_unique_users(self):
        from collections import deque
        dq = deque()
        t = time.time()
        dq.append((t, "root"))
        dq.append((t, "admin"))
        dq.append((t, "root"))   # duplicate
        assert _unique_users(dq) == 2


class TestDetector:
    def _make_fail_event(self, ip: str, user: str = "root") -> Event:
        return Event(ts=now(), source="auth", kind=EventKind.SSH_FAIL, src_ip=ip, user=user)

    def _make_success_event(self, ip: str) -> Event:
        return Event(ts=now(), source="auth", kind=EventKind.SSH_SUCCESS, src_ip=ip)

    def test_brute_force_detected(self):
        det = make_detector(fails_threshold=3, fails_window_sec=60)

        async def _go():
            ip = "1.2.3.4"
            for _ in range(3):
                await det.handle(self._make_fail_event(ip))

        _run(_go())
        det.logger.log.assert_awaited()
        calls = [c.args[0] for c in det.logger.log.await_args_list]
        assert "incident" in calls

    def test_no_alert_below_threshold(self):
        det = make_detector(fails_threshold=8, fails_window_sec=60)

        async def _go():
            ip = "2.2.2.2"
            for _ in range(5):
                await det.handle(self._make_fail_event(ip))

        _run(_go())
        calls = [c.args[0] for c in det.logger.log.await_args_list]
        assert "incident" not in calls

    def test_credential_breach_high_severity(self):
        # fails_threshold=99 so brute-force rule never fires during the test;
        # breach fires when success arrives after >=3 failures.
        det = make_detector(fails_threshold=99, success_after_fails_threshold=3, fails_window_sec=60)
        incident_payloads = []

        async def log_side_effect(event_type, payload):
            if event_type == "incident":
                incident_payloads.append(payload)

        det.logger.log = AsyncMock(side_effect=log_side_effect)

        async def _go():
            ip = "3.3.3.3"
            for _ in range(3):
                await det.handle(self._make_fail_event(ip))
            await det.handle(self._make_success_event(ip))

        _run(_go())
        high = [p for p in incident_payloads if p.get("severity") == Severity.HIGH]
        assert len(high) >= 1

    def test_credential_stuffing_detected(self):
        det = make_detector(fails_threshold=99, unique_users_threshold=3, fails_window_sec=60)
        incident_payloads = []

        async def log_side_effect(event_type, payload):
            if event_type == "incident":
                incident_payloads.append(payload)

        det.logger.log = AsyncMock(side_effect=log_side_effect)

        async def _go():
            ip = "4.4.4.4"
            for user in ["alice", "bob", "charlie"]:
                await det.handle(self._make_fail_event(ip, user=user))

        _run(_go())
        assert len(incident_payloads) >= 1
        assert "credential_stuffing" in incident_payloads[0]["reasons"][0]

    def test_cooldown_suppresses_repeated_alerts(self):
        det = make_detector(fails_threshold=2, fails_window_sec=60, incident_cooldown_sec=999)
        incident_count = [0]

        async def log_side_effect(event_type, payload):
            if event_type == "incident":
                incident_count[0] += 1

        det.logger.log = AsyncMock(side_effect=log_side_effect)

        async def _go():
            ip = "5.5.5.5"
            for _ in range(10):
                await det.handle(self._make_fail_event(ip))

        _run(_go())
        # Should only fire once due to cooldown
        assert incident_count[0] == 1

    def test_net_hint_not_counted_as_auth(self):
        det = make_detector()
        ev = Event(ts=now(), source="net", kind=EventKind.NET_HINT,
                   src_ip="6.6.6.6", meta={"hint": "DISCOVERY"})

        async def _go():
            await det.handle(ev)

        _run(_go())
        # No SSH state should be created
        assert "6.6.6.6" not in det._state or len(det._state["6.6.6.6"].fails) == 0

    def test_allowlisted_ip_not_blocked(self):
        det = make_detector(fails_threshold=2, success_after_fails_threshold=2)
        det.blocker.allowlist = {"7.7.7.7"}

        async def _go():
            ip = "7.7.7.7"
            for _ in range(3):
                await det.handle(self._make_fail_event(ip))
            await det.handle(self._make_success_event(ip))

        _run(_go())
        det.blocker.block_ip.assert_not_awaited()

    def test_get_stats_returns_tracked_ips(self):
        det = make_detector()

        async def _go():
            await det.handle(self._make_fail_event("8.8.8.8"))

        _run(_go())
        stats = det.get_stats()
        ips = [s["ip"] for s in stats]
        assert "8.8.8.8" in ips



# Models


class TestModels:
    def test_event_to_dict_has_time(self):
        ev = Event(ts=time.time(), source="auth", kind=EventKind.SSH_FAIL, src_ip="1.2.3.4")
        d = ev.to_dict()
        assert "time" in d
        assert "T" in d["time"]  # ISO format

    def test_iso_time_format(self):
        s = iso_time()
        assert s.endswith("Z")
        assert "T" in s


# v1.0.3 — sshd-session parser fix


class TestSshdSessionParser:
    """Modern OpenSSH uses sshd-session[PID] instead of sshd[PID].
    These tests verify the _SSHD_PREFIX regex matches both variants."""

    def test_sshd_session_fail(self):
        line = "2026-05-01T05:06:33-04:00 kali sshd-session[23017]: Failed password for oro from 1.2.3.4 port 43568 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session fail line not parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "1.2.3.4"

    def test_sshd_session_success(self):
        line = "2026-05-01T05:06:46-04:00 kali sshd-session[23135]: Accepted password for oro from 1.2.3.4 port 52710 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session success line not parsed"
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.src_ip == "1.2.3.4"

    def test_sshd_session_invalid_user(self):
        line = "2026-05-01T09:00:00-04:00 kali sshd-session[9999]: Failed password for invalid user admin from 5.6.7.8 port 12345 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session invalid user line not parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.user == "admin"
        assert ev.src_ip == "5.6.7.8"

    def test_classic_sshd_still_works(self):
        """Original sshd[PID] format must still be matched."""
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from 9.9.9.9 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "classic sshd line no longer parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "9.9.9.9"

    def test_sshd_session_ipv6_loopback(self):
        """Kali localhost SSH uses ::1 — must be parsed correctly."""
        line = "2026-05-01T05:06:33-04:00 kali sshd-session[23017]: Failed password for oro from ::1 port 43568 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session ::1 line not parsed"
        assert ev.src_ip == "::1"


# v1.0.2 — Telegram escaping fix


class TestTelegramEscape:
    """_tg_escape must neutralise Markdown v1 special chars in dynamic content."""

    def test_escape_underscore(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("Verizon_Business") == "Verizon\\_Business"

    def test_escape_asterisk(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("score*98") == "score\\*98"

    def test_escape_backtick(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("cmd`exec`") == "cmd\\`exec\\`"

    def test_escape_bracket(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("[link]") == "\\[link]"

    def test_no_change_plain(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("Hello World 123") == "Hello World 123"

    def test_escape_combined(self):
        from cnsl.notify import _tg_escape
        result = _tg_escape("AS12345_ISP*provider")
        assert "\\_" in result
        assert "\\*" in result


# v1.0.2 — LOW severity count fix


class TestStoreLowCount:
    """store.stats() must count LOW incidents, not hardcode 0."""

    def test_stats_counts_low(self):
        import asyncio, aiosqlite, tempfile, os
        from cnsl.store import Store

        async def _go():
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name
            try:
                store = Store(db_path)
                await store.init()

                # Insert one LOW incident directly
                async with aiosqlite.connect(db_path) as db:
                    await db.execute(
                        "INSERT INTO incidents (src_ip, severity, reasons, fail_count, ts) "
                        "VALUES (?, ?, ?, ?, ?)",
                        ("1.2.3.4", "LOW", '["test"]', 1, time.time())
                    )
                    await db.commit()

                stats = await store.stats()
                assert stats.get("low", 0) == 1, f"LOW count was {stats.get('low')} — expected 1"
            finally:
                os.unlink(db_path)

        try:
            asyncio.run(_go())
        except ImportError:
            pytest.skip("aiosqlite not installed")

    def test_stats_all_severities(self):
        import asyncio, tempfile, os
        from cnsl.store import Store

        async def _go():
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name
            try:
                store = Store(db_path)
                await store.init()

                import aiosqlite
                async with aiosqlite.connect(db_path) as db:
                    for sev in ["HIGH", "MEDIUM", "LOW"]:
                        await db.execute(
                            "INSERT INTO incidents (src_ip, severity, reasons, fail_count, ts) "
                            "VALUES (?, ?, ?, ?, ?)",
                            ("1.2.3.4", sev, '["test"]', 1, time.time())
                        )
                    await db.commit()

                stats = await store.stats()
                assert stats["high"]   == 1
                assert stats["medium"] == 1
                assert stats["low"]    == 1
                assert stats["total"]  == 3
            finally:
                os.unlink(db_path)

        try:
            asyncio.run(_go())
        except ImportError:
            pytest.skip("aiosqlite not installed")


# v1.0.4 — FIM directory scanning fix


class TestFIMDirectoryScanning:
    """_collect_paths must recurse into directories, not only check isfile()."""

    def test_directory_in_watch_paths_is_scanned(self):
        import tempfile, os
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file inside the temp directory
            test_file = os.path.join(tmpdir, "test_file.conf")
            with open(test_file, "w") as f:
                f.write("test content")

            # Build a minimal FIMEngine-like object using _collect_paths logic directly
            # (avoids needing a full DB / logger for a unit test)
            from cnsl.fim import FIMEngine
            logger = AsyncMock()
            cfg = {
                "fim": {
                    "enabled": True,
                    "watch_paths": [tmpdir],   # a DIRECTORY, not a file
                    "watch_dirs": [],
                    "scan_interval_sec": 60,
                }
            }
            fim = FIMEngine(cfg, logger)
            paths = fim._collect_paths()

            assert test_file in paths, (
                f"File inside watched directory not found in collected paths. "
                f"Got: {paths}"
            )

    def test_file_in_watch_paths_still_works(self):
        """Individual files in watch_paths must still be collected."""
        import tempfile, os
        from cnsl.fim import FIMEngine

        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_file = f.name

        try:
            logger = AsyncMock()
            cfg = {
                "fim": {
                    "enabled": True,
                    "watch_paths": [test_file],
                    "watch_dirs": [],
                    "scan_interval_sec": 60,
                }
            }
            fim = FIMEngine(cfg, logger)
            paths = fim._collect_paths()
            assert test_file in paths
        finally:
            os.unlink(test_file)

    def test_nonexistent_path_ignored(self):
        """Missing paths must not crash _collect_paths."""
        from cnsl.fim import FIMEngine
        logger = AsyncMock()
        cfg = {
            "fim": {
                "enabled": True,
                "watch_paths": ["/nonexistent/path/cnsl_test"],
                "watch_dirs": [],
                "scan_interval_sec": 60,
            }
        }
        fim = FIMEngine(cfg, logger)
        paths = fim._collect_paths()
        assert isinstance(paths, list)


# v1.0.2 — ML retrain timer fix


class TestMLRetrain:
    """_retrain must not update _last_train when data is insufficient,
    so the interval check keeps firing until enough samples arrive."""

    def test_last_train_not_updated_below_min_samples(self):
        import asyncio, sys
        try:
            import sklearn  # noqa: F401
        except ImportError:
            pytest.skip("scikit-learn not installed")

        sys.path.insert(0, '/home/claude/cnsl_project')
        from cnsl.ml_detector import MLDetector
        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 100, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)

        assert ml._last_train == 0.0

        async def _go():
            await ml._retrain()   # called with 0 samples

        asyncio.run(_go())
        # _last_train must stay 0.0 — no data to train on
        assert ml._last_train == 0.0, (
            "_last_train was updated even though there was no training data"
        )

    def test_last_train_updated_after_successful_train(self):
        import asyncio
        try:
            import sklearn  # noqa: F401
        except ImportError:
            pytest.skip("scikit-learn not installed")

        from cnsl.ml_detector import MLDetector, FeatureWindow
        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 3, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)

        # Inject enough training data
        fw = FeatureWindow()
        for _ in range(5):
            ml._training_data.append(fw.to_vector())

        async def _go():
            await ml._retrain()

        asyncio.run(_go())
        assert ml._trained is True
        assert ml._last_train > 0.0


# v1.0.2 — dashboard signature fix


class TestDashboardSignature:
    """start_dashboard must accept ml_detector and fim kwargs
    — if it doesn't, engine.py silently passes None and both tabs show disabled."""

    def test_start_dashboard_accepts_ml_and_fim(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        params = list(sig.parameters.keys())
        assert "ml_detector" in params, \
            "start_dashboard missing ml_detector param — ML tab will always show disabled"
        assert "fim" in params, \
            "start_dashboard missing fim param — FIM tab will always show disabled"

    def test_start_dashboard_ml_fim_default_none(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert sig.parameters["ml_detector"].default is None
        assert sig.parameters["fim"].default is None