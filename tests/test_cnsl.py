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

# Pre-import sklearn at module load time so individual tests don't timeout.
# If sklearn is not installed or broken, ML tests will be skipped gracefully.
try:
    import sklearn  # noqa: F401
    _SKLEARN_AVAILABLE = True
except Exception:
    _SKLEARN_AVAILABLE = False



# Helpers


def make_cfg(**overrides):
    import json
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    # Legacy: put overrides in thresholds (for correlator/baseline compat)
    for k, v in overrides.items():
        cfg["thresholds"][k] = v
    # Also propagate to rules engine so detector sees the new thresholds
    _THRESH_TO_RULE = {
        "fails_threshold":              ("ssh.brute_force",         "threshold"),
        "unique_users_threshold":       ("ssh.credential_stuffing", "threshold"),
        "success_after_fails_threshold":("ssh.credential_breach",   "threshold"),
        "web_scan_threshold":           ("web.scan_flood",           "threshold"),
        "web_auth_fail_threshold":      ("web.auth_flood",           "threshold"),
        "db_fail_threshold":            ("db.brute_force",           "threshold"),
    }
    if "rules" not in cfg:
        cfg["rules"] = {}
    for k, v in overrides.items():
        if k in _THRESH_TO_RULE:
            rule_id, field = _THRESH_TO_RULE[k]
            if rule_id not in cfg["rules"]:
                cfg["rules"][rule_id] = {}
            cfg["rules"][rule_id][field] = v
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
        # ::ffff:1.2.3.4 is IPv6-mapped IPv4 — _clean_ip strips the prefix
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from ::ffff:1.2.3.4 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.src_ip == "1.2.3.4", f"Expected 1.2.3.4 got {ev.src_ip}"

    def test_ipv6_loopback(self):
        # Pure IPv6 like ::1 should stay as-is
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from ::1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.src_ip == "::1", f"Expected ::1 got {ev.src_ip}"


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
        # DEFAULT_CONFIG always has the built-in defaults regardless of system config
        assert DEFAULT_CONFIG["thresholds"]["fails_threshold"] == 8
        assert DEFAULT_CONFIG["actions"]["dry_run"] is True
        assert "127.0.0.1" in DEFAULT_CONFIG["allowlist"]

    def test_safe_int(self):
        assert safe_int("8", 0) == 8
        assert safe_int("bad", 5) == 5
        assert safe_int(None, 3) == 3

    def test_load_config_merges_with_defaults(self):
        # load_config() may load /etc/cnsl/config.json if it exists —
        # verify it still returns a complete config with all required keys
        cfg = load_config(None)
        assert "thresholds" in cfg
        assert "fails_threshold" in cfg["thresholds"]
        assert "actions" in cfg
        assert "allowlist" in cfg


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

                async with aiosqlite.connect(db_path) as db:
                    await db.execute(
                        "INSERT INTO incidents "
                        "(src_ip, severity, reasons, fail_count, uniq_users, ts, time) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ("1.2.3.4", "LOW", '["test"]', 1, 1, time.time(), "2026-01-01T00:00:00Z")
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
                            "INSERT INTO incidents "
                            "(src_ip, severity, reasons, fail_count, uniq_users, ts, time) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            ("1.2.3.4", sev, '["test"]', 1, 1, time.time(), "2026-01-01T00:00:00Z")
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
    """_retrain must not update _last_train when data is insufficient."""

    def test_last_train_not_updated_below_min_samples(self):
        """Does not import sklearn — tests pure timer logic only."""
        import asyncio
        from cnsl.ml_detector import MLDetector
        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 100, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)
        assert ml._last_train == 0.0

        async def _go():
            await ml._retrain()   # 0 samples — must be a no-op

        asyncio.run(_go())
        assert ml._last_train == 0.0, (
            "_last_train was updated even though there was no training data"
        )

    def test_last_train_updated_after_successful_train(self):
        """Train with enough samples — _trained becomes True, _last_train > 0."""
        import asyncio
        if not _SKLEARN_AVAILABLE:
            pytest.skip("scikit-learn not installed")

        try:
            from cnsl.ml_detector import MLDetector, FeatureWindow
        except Exception as e:
            pytest.skip(f"ml_detector import failed: {e}")

        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 3, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)

        fw = FeatureWindow(ip="1.2.3.4", ts=time.time())
        fw.ssh_fail_count = 5
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

# v1.2.0 — country blocking + email notification


class TestCountryBlockConfig:
    """country_block config section is loaded with correct defaults."""

    def test_country_block_defaults(self):
        from cnsl.config import DEFAULT_CONFIG
        cb = DEFAULT_CONFIG.get("country_block", {})
        assert cb.get("enabled") is False
        assert cb.get("countries") == []
        assert cb.get("allowlist") == []

    def test_country_block_accessor(self):
        from cnsl.config import get_country_block_cfg, DEFAULT_CONFIG
        cfg = {"country_block": {"enabled": True, "countries": ["CN", "RU"], "allowlist": []}}
        result = get_country_block_cfg(cfg)
        assert result["enabled"] is True
        assert "CN" in result["countries"]

    def test_country_block_missing_key_uses_default(self):
        from cnsl.config import get_country_block_cfg
        # When key absent, falls back to DEFAULT_CONFIG value (enabled=False)
        result = get_country_block_cfg({})
        assert result["enabled"] is False


class TestCountryBlockDetector:
    """Detector correctly loads country_block settings and builds the blocked set."""

    def _make_detector(self, countries=None, enabled=True):
        from unittest.mock import MagicMock
        from cnsl.detector import Detector
        from cnsl.blocker import Blocker
        from cnsl.logger import JsonLogger

        logger = MagicMock()
        blocker = MagicMock(spec=Blocker)
        blocker.dry_run = True
        blocker.is_blocked = MagicMock(return_value=False)

        cfg = {
            "country_block": {
                "enabled": enabled,
                "countries": countries or ["CN", "RU", "KP"],
                "allowlist": ["203.0.113.5"],
            }
        }
        return Detector(cfg, logger, blocker)

    def test_blocked_countries_loaded(self):
        d = self._make_detector(countries=["CN", "RU"])
        assert "CN" in d.blocked_countries
        assert "RU" in d.blocked_countries

    def test_country_block_allowlist_loaded(self):
        d = self._make_detector()
        assert "203.0.113.5" in d.country_block_allowlist

    def test_country_block_disabled(self):
        d = self._make_detector(enabled=False)
        assert d.country_block_enabled is False

    def test_country_codes_uppercased(self):
        """Lowercase codes in config are normalised to uppercase."""
        d = self._make_detector(countries=["cn", "ru"])
        assert "CN" in d.blocked_countries
        assert "RU" in d.blocked_countries


class TestEmailNotifyConfig:
    """Email notification config section is present in DEFAULT_CONFIG and notify.py."""

    def test_default_config_has_notifications(self):
        from cnsl.config import DEFAULT_CONFIG
        n = DEFAULT_CONFIG.get("notifications", {})
        assert "telegram" in n
        assert "discord" in n
        assert "slack" in n

    def test_notifier_email_skipped_when_disabled(self):
        """Notifier.send must not crash when email is configured but disabled."""
        import asyncio
        from cnsl.notify import Notifier
        from cnsl.models import Detection

        cfg = {
            "notifications": {
                "min_severity": "LOW",
                "email": {
                    "enabled": False,
                    "smtp_host": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "u",
                    "password": "p",
                    "to": ["admin@example.com"],
                },
            }
        }
        notifier = Notifier(cfg)
        d = Detection(src_ip="1.2.3.4", severity="HIGH",
                      reasons=["test"], fail_count=1,
                      uniq_users=1, window_sec=60)
        # Must not raise
        asyncio.run(notifier.send(d, None))

    def test_smtp_send_swallows_connection_errors(self):
        """_smtp_send must not raise even if the SMTP server is unreachable."""
        from cnsl.notify import _smtp_send
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "test"
        msg["From"] = "a@example.com"
        msg["To"] = "b@example.com"

        # 127.0.0.1:1 — nothing listening, ConnectionRefusedError expected internally
        _smtp_send(
            host="127.0.0.1", port=1,
            username="", password="",
            from_addr="a@example.com",
            to_addrs=["b@example.com"],
            msg=msg,
            use_tls=False, use_ssl=False,
        )
        # If we reach here the function swallowed the error correctly


# v1.3.0 — TOTP 2FA


class TestTOTPHelpers:
    """Low-level TOTP helper functions."""

    def test_generate_secret_is_base32(self):
        from cnsl.auth import generate_totp_secret
        import base64
        secret = generate_totp_secret()
        # Should not raise — valid base32
        base64.b32decode(secret)
        assert len(secret) >= 16

    def test_verify_totp_correct_code(self):
        import pyotp
        from cnsl.auth import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        code   = pyotp.TOTP(secret).now()
        assert verify_totp(secret, code)

    def test_verify_totp_wrong_code(self):
        from cnsl.auth import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        assert not verify_totp(secret, "000000")

    def test_verify_totp_empty_inputs(self):
        from cnsl.auth import verify_totp
        assert not verify_totp("", "123456")
        assert not verify_totp("SECRET", "")

    def test_get_totp_uri_format(self):
        from cnsl.auth import generate_totp_secret, get_totp_uri
        secret = generate_totp_secret()
        uri    = get_totp_uri(secret, "admin")
        assert uri.startswith("otpauth://totp/CNSL")
        assert "admin" in uri
        assert secret in uri


class TestBackupCodes:
    """Backup code generation and verification."""

    def test_generates_eight_codes(self):
        from cnsl.auth import generate_backup_codes
        plain, hashed = generate_backup_codes()
        assert len(plain) == 8
        assert len(hashed) == 8

    def test_codes_formatted_with_dash(self):
        from cnsl.auth import generate_backup_codes
        plain, _ = generate_backup_codes()
        for code in plain:
            assert "-" in code
            assert len(code) == 9   # XXXX-XXXX

    def test_backup_code_matches(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        matched, remaining = verify_backup_code(plain[3], hashed)
        assert matched
        assert len(remaining) == 7

    def test_backup_code_single_use(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        _, remaining = verify_backup_code(plain[0], hashed)
        matched2, _ = verify_backup_code(plain[0], remaining)
        assert not matched2

    def test_invalid_code_no_match(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        _, hashed = generate_backup_codes()
        matched, remaining = verify_backup_code("0000-0000", hashed)
        assert not matched
        assert len(remaining) == 8   # unchanged

    def test_case_insensitive_match(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        matched, _ = verify_backup_code(plain[0].lower(), hashed)
        assert matched

    def test_dash_optional(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        no_dash = plain[0].replace("-", "")
        matched, _ = verify_backup_code(no_dash, hashed)
        assert matched


class TestAuthManager2FA:
    """AuthManager 2FA setup, confirm, verify, and disable flows."""

    def _make_auth(self):
        import bcrypt
        from cnsl.auth import AuthManager
        pw_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()
        cfg = {"auth": {"enabled": True,
                        "secret_key": "testsecret_padded_to_32bytes_ok!",
                        "users": {"testuser": {"password_hash": pw_hash, "role": "admin"}}}}
        return AuthManager(cfg)

    def test_login_no_2fa_returns_three_tuple(self):
        auth = self._make_auth()
        token, err, needs_2fa = auth.login("testuser", "testpass")
        assert token is not None
        assert err is None
        assert needs_2fa is False

    def test_setup_confirm_full_flow(self):
        import pyotp
        auth = self._make_auth()
        # Setup
        uri, err = auth.setup_2fa("testuser")
        assert err is None
        assert "otpauth" in uri
        # Extract secret from URI and generate valid code
        secret = uri.split("secret=")[1].split("&")[0]
        code   = pyotp.TOTP(secret).now()
        # Confirm
        backup_codes, err = auth.confirm_2fa("testuser", code)
        assert err is None
        assert len(backup_codes) == 8

    def test_login_with_2fa_enabled_returns_partial(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        # Login should now require 2FA
        token, err, needs_2fa = auth.login("testuser", "testpass")
        assert needs_2fa is True
        assert err is None

    def test_verify_2fa_with_valid_otp(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        code  = pyotp.TOTP(secret).now()
        full_token, err = auth.verify_2fa(partial, code)
        assert err is None
        assert full_token is not None

    def test_verify_2fa_wrong_code_fails(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        _, err = auth.verify_2fa(partial, "000000")
        assert err is not None

    def test_verify_2fa_with_backup_code(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        backup_codes, _ = auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        full_token, err = auth.verify_2fa(partial, backup_codes[0])
        assert err is None
        assert full_token is not None

    def test_partial_token_rejected_by_verify_token(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        payload, err = auth.verify_token(partial)
        assert payload is None
        assert "2FA" in err or "partial" in err.lower()

    def test_disable_2fa_requires_correct_password(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        err = auth.disable_2fa("testuser", "wrongpass")
        assert err is not None

    def test_disable_2fa_success(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        err = auth.disable_2fa("testuser", "testpass")
        assert err is None
        status = auth.get_2fa_status("testuser")
        assert status["enabled"] is False

    def test_get_2fa_status(self):
        auth = self._make_auth()
        status = auth.get_2fa_status("testuser")
        assert status["enabled"] is False
        assert status["backup_codes_left"] == 0
        assert status["pyotp_available"] is True



# v1.4.0 — Case Management


import asyncio as _asyncio
import tempfile as _tempfile


async def _make_cm():
    """CaseManager backed by a fresh temp SQLite DB."""
    import aiosqlite
    from cnsl.cases import CaseManager

    class _Store:
        available = True
        _db = None

    store = _Store()
    tmp = _tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store._db = await aiosqlite.connect(tmp.name)
    store._db.row_factory = aiosqlite.Row
    cm = CaseManager(store)
    await cm.init()
    return cm


def _det(ip="1.2.3.4", sev="HIGH", reasons=None):
    from cnsl.models import Detection
    return Detection(src_ip=ip, severity=sev,
                     reasons=reasons or ["brute_force: test"],
                     fail_count=5, uniq_users=2, window_sec=60)


class TestCaseManagerCreate:
    def test_auto_title_brute_force(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(reasons=["brute_force: 9 fails"]))
        assert "Brute" in title and "1.2.3.4" in title

    def test_auto_title_country_block(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(ip="5.6.7.8", reasons=["country_block: China (CN)"]))
        assert "Country" in title

    def test_auto_title_fallback(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(ip="9.9.9.9", reasons=["unknown_xyz"]))
        assert "9.9.9.9" in title

    def test_create_from_incident(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(
                _det(), geo={"country": "US", "isp": "Linode"})
            assert case_id is not None
            case = await cm.get(case_id)
            assert case["src_ip"] == "1.2.3.4"
            assert case["status"] == "open"
            assert case["severity"] == "HIGH"
            assert case["country"] == "US"
        _asyncio.run(_run())

    def test_create_manual(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_manual(
                title="Test case", severity="MEDIUM",
                src_ip="2.2.2.2", created_by="admin")
            case = await cm.get(case_id)
            assert case["title"] == "Test case"
            assert case["created_by"] == "admin"
        _asyncio.run(_run())


class TestCaseManagerStatus:
    def test_valid_status_update(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.update_status(case_id, "investigating", actor="alice")
            assert err is None
            assert (await cm.get(case_id))["status"] == "investigating"
        _asyncio.run(_run())

    def test_invalid_status_returns_error(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.update_status(case_id, "invalid_status")
            assert err is not None
        _asyncio.run(_run())

    def test_status_change_creates_system_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            await cm.update_status(case_id, "closed", actor="bob")
            notes = (await cm.get(case_id))["notes"]
            assert any("closed" in n["body"] for n in notes)
        _asyncio.run(_run())

    def test_all_valid_statuses_accepted(self):
        from cnsl.cases import VALID_STATUSES
        assert {"open", "investigating", "closed", "false_positive"} == VALID_STATUSES


class TestCaseManagerNotes:
    def test_add_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="3.3.3.3"))
            err = await cm.add_note(case_id, author="alice", body="Confirmed attacker")
            assert err is None
            notes = (await cm.get(case_id))["notes"]
            analyst = [n for n in notes if n["author"] == "alice"]
            assert len(analyst) == 1
            assert analyst[0]["body"] == "Confirmed attacker"
        _asyncio.run(_run())

    def test_empty_note_returns_error(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.add_note(case_id, author="alice", body="   ")
            assert err is not None
        _asyncio.run(_run())

    def test_note_nonexistent_case(self):
        async def _run():
            cm = await _make_cm()
            err = await cm.add_note(99999, author="alice", body="test")
            assert err is not None
        _asyncio.run(_run())


class TestCaseManagerAssign:
    def test_assign_creates_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="4.4.4.4"))
            err = await cm.assign(case_id, "alice", actor="admin")
            assert err is None
            case = await cm.get(case_id)
            assert case["assigned_to"] == "alice"
            assert any("alice" in n["body"] for n in case["notes"])
        _asyncio.run(_run())

    def test_unassign(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="4.4.4.4"))
            await cm.assign(case_id, "alice")
            err = await cm.assign(case_id, None, actor="admin")
            assert err is None
            assert (await cm.get(case_id))["assigned_to"] is None
        _asyncio.run(_run())


class TestCaseManagerList:
    def test_list_all_cases(self):
        async def _run():
            cm = await _make_cm()
            for i in range(3):
                await cm.create_from_incident(_det(ip=f"1.2.3.{i}"))
            assert len(await cm.list_cases()) == 3
        _asyncio.run(_run())

    def test_filter_by_status(self):
        async def _run():
            cm = await _make_cm()
            for i in range(3):
                case_id = await cm.create_from_incident(_det(ip=f"5.5.5.{i}"))
                if i == 0:
                    await cm.update_status(case_id, "closed")
            assert len(await cm.list_cases(status="open")) == 2
        _asyncio.run(_run())

    def test_stats(self):
        async def _run():
            cm = await _make_cm()
            await cm.create_from_incident(_det(ip="6.6.6.6"))
            s = await cm.stats()
            assert s["total"] == 1
            assert s["open"] == 1
            assert s["high"] == 1
        _asyncio.run(_run())


class TestCaseManagerDelete:
    def test_delete_removes_case_and_notes(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="7.7.7.7"))
            await cm.add_note(case_id, "admin", "some note")
            err = await cm.delete(case_id)
            assert err is None
            assert await cm.get(case_id) is None
        _asyncio.run(_run())


class TestCaseRBAC:
    def test_viewer_has_cases_read(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("viewer", Perm.CASES_READ)

    def test_viewer_cannot_write_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert not RBAC().can("viewer", Perm.CASES_WRITE)

    def test_analyst_can_write_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("analyst", Perm.CASES_WRITE)

    def test_analyst_cannot_delete_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert not RBAC().can("analyst", Perm.CASES_DELETE)

    def test_admin_can_delete_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("admin", Perm.CASES_DELETE)


# v1.5.0 — Alert Rule Engine


class TestRuleEngineDefaults:
    """Built-in rules load correctly with defaults."""

    def test_all_builtin_rules_present(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        ids = {r["id"] for r in re.all_rules()}
        expected = {
            "ssh.brute_force", "ssh.credential_stuffing", "ssh.credential_breach",
            "web.scan_flood", "web.auth_flood", "web.exploit",
            "db.brute_force", "fw.honeypot_port", "net.repeat_offender",
        }
        assert expected <= ids

    def test_builtin_rules_enabled_by_default(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        for r in re.all_rules():
            assert r["enabled"] is True, f"Rule {r['id']} should be enabled by default"

    def test_effective_equals_default_without_config(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        r = re.get("ssh.brute_force")
        assert r.effective_threshold == r.threshold
        assert r.effective_severity  == r.severity

    def test_ssh_brute_force_default_threshold(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        assert re.threshold("ssh.brute_force") == 8

    def test_unknown_rule_returns_none(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        assert re.get("not.a.rule") is None


class TestRuleEngineConfig:
    """Config overrides are applied correctly."""

    def test_config_overrides_threshold(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"rules": {"ssh.brute_force": {"threshold": 3}}})
        assert re.threshold("ssh.brute_force") == 3

    def test_config_overrides_severity(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"rules": {"ssh.brute_force": {"severity": "HIGH"}}})
        assert re.severity("ssh.brute_force") == "HIGH"

    def test_config_disables_rule(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"rules": {"web.scan_flood": {"enabled": False}}})
        assert not re.is_enabled("web.scan_flood")

    def test_unknown_config_key_ignored(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"rules": {"not.a.rule": {"enabled": False}}})
        # Should not raise
        assert re.get("not.a.rule") is None

    def test_default_unchanged_without_override(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"rules": {"ssh.brute_force": {"threshold": 3}}})
        # credential_breach not overridden
        assert re.threshold("ssh.credential_breach") == 5


class TestRuleEngineRuntime:
    """Runtime enable/disable/update operations."""

    def test_enable_disable(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.disable("ssh.brute_force")
        assert err is None
        assert not re.is_enabled("ssh.brute_force")
        err = re.enable("ssh.brute_force")
        assert err is None
        assert re.is_enabled("ssh.brute_force")

    def test_disable_unknown_rule_returns_error(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.disable("not.a.rule")
        assert err is not None

    def test_update_threshold(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.update("ssh.brute_force", threshold=3)
        assert err is None
        assert re.threshold("ssh.brute_force") == 3

    def test_update_severity_uppercase(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.update("ssh.brute_force", severity="high")
        assert err is None
        assert re.severity("ssh.brute_force") == "HIGH"

    def test_update_invalid_severity_returns_error(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.update("ssh.brute_force", severity="CRITICAL")
        assert err is not None

    def test_update_threshold_zero_returns_error(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        err = re.update("ssh.brute_force", threshold=0)
        assert err is not None

    def test_reset_removes_overrides(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine()
        re.update("ssh.brute_force", threshold=2, severity="HIGH")
        err = re.reset("ssh.brute_force")
        assert err is None
        assert re.threshold("ssh.brute_force") == 8    # back to default
        assert re.severity("ssh.brute_force")  == "MEDIUM"

    def test_builtin_defaults_not_mutated(self):
        """Changing RuleEngine state must never affect the module-level defaults."""
        from cnsl.rules import RuleEngine, _BUILTIN_BY_ID
        re = RuleEngine()
        re.update("ssh.brute_force", threshold=1)
        re2 = RuleEngine()
        assert re2.threshold("ssh.brute_force") == 8   # fresh engine is still 8
        assert _BUILTIN_BY_ID["ssh.brute_force"].threshold == 8  # module unchanged


class TestDetectorUsesRuleEngine:
    """Detector reads thresholds from RuleEngine, not hardcoded values."""

    def _make_detector(self, cfg=None):
        from unittest.mock import MagicMock
        from cnsl.detector import Detector
        from cnsl.blocker import Blocker
        logger  = MagicMock()
        blocker = MagicMock(spec=Blocker)
        blocker.dry_run    = True
        blocker.is_blocked = MagicMock(return_value=False)
        return Detector(cfg or {}, logger, blocker)

    def test_detector_has_rules_attribute(self):
        from cnsl.rules import RuleEngine
        d = self._make_detector()
        assert isinstance(d.rules, RuleEngine)

    def test_config_threshold_applied_in_detector(self):
        d = self._make_detector({"rules": {"ssh.brute_force": {"threshold": 3}}})
        assert d.rules.threshold("ssh.brute_force") == 3

    def test_disabled_rule_reflected_in_detector(self):
        d = self._make_detector({"rules": {"web.scan_flood": {"enabled": False}}})
        assert not d.rules.is_enabled("web.scan_flood")

    def test_runtime_disable_propagates(self):
        d = self._make_detector()
        d.rules.disable("db.brute_force")
        assert not d.rules.is_enabled("db.brute_force")


# v1.6.0 — Community Threat Feed


class TestThreatFeedParsing:
    """Feed text parsing logic."""

    def test_parse_plain_ips(self):
        from cnsl.threat_feed import _parse_feed_text, FeedSource, FEED_BY_KEY
        src  = FEED_BY_KEY["emerging_threats"]
        text = "# comment\n1.2.3.4\n5.6.7.8\n\n"
        ips, cidrs = _parse_feed_text(text, src)
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips
        assert len(cidrs) == 0

    def test_parse_cidr_blocks(self):
        from cnsl.threat_feed import _parse_feed_text, FeedSource, FEED_BY_KEY
        src  = FEED_BY_KEY["spamhaus_drop"]
        text = "# Spamhaus DROP\n10.0.0.0/8 ; SBL123\n192.168.0.0/16\n"
        ips, cidrs = _parse_feed_text(text, src)
        assert len(cidrs) == 2

    def test_comments_ignored(self):
        from cnsl.threat_feed import _parse_feed_text, FeedSource, FEED_BY_KEY
        src  = FEED_BY_KEY["feodo_tracker"]
        text = "# this is a comment\n; also ignored\n1.1.1.1\n"
        ips, cidrs = _parse_feed_text(text, src)
        assert "1.1.1.1" in ips
        assert len(ips) == 1

    def test_invalid_lines_skipped(self):
        from cnsl.threat_feed import _parse_feed_text, FeedSource, FEED_BY_KEY
        src  = FEED_BY_KEY["cins_army"]
        text = "not-an-ip\n999.999.999.999\n2.3.4.5\n"
        ips, _ = _parse_feed_text(text, src)
        assert "2.3.4.5" in ips
        assert len(ips) == 1

    def test_single_ip_cidr_treated_as_plain(self):
        from cnsl.threat_feed import _parse_feed_text, FeedSource, FEED_BY_KEY
        src  = FEED_BY_KEY["spamhaus_drop"]
        text = "203.0.113.5/32\n"
        ips, cidrs = _parse_feed_text(text, src)
        assert "203.0.113.5" in ips
        assert len(cidrs) == 0


class TestThreatFeedCheck:
    """ThreatFeed.check() IP lookup logic."""

    def _make_feed(self, ips=None, cidrs=None):
        from cnsl.threat_feed import ThreatFeed
        import ipaddress
        tf = ThreatFeed({"threat_feed": {"enabled": True, "auto_block": False}})
        tf._ips   = set(ips or [])
        tf._cidrs = [ipaddress.ip_network(c) for c in (cidrs or [])]
        return tf

    def test_exact_match(self):
        tf = self._make_feed(ips=["1.2.3.4", "5.6.7.8"])
        hit = tf.check("1.2.3.4")
        assert hit is not None
        assert hit["match_type"] == "exact"

    def test_no_match_returns_none(self):
        tf = self._make_feed(ips=["1.2.3.4"])
        assert tf.check("9.9.9.9") is None

    def test_cidr_match(self):
        tf = self._make_feed(cidrs=["10.0.0.0/8"])
        hit = tf.check("10.1.2.3")
        assert hit is not None
        assert hit["match_type"] == "cidr"
        assert "10.0.0.0/8" in hit["cidr"]

    def test_cidr_no_match(self):
        tf = self._make_feed(cidrs=["10.0.0.0/8"])
        assert tf.check("192.168.1.1") is None

    def test_disabled_feed_always_none(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": False}})
        tf._ips = {"1.2.3.4"}
        assert tf.check("1.2.3.4") is None

    def test_empty_ip_returns_none(self):
        tf = self._make_feed(ips=["1.2.3.4"])
        assert tf.check("") is None


class TestThreatFeedStats:
    """ThreatFeed.get_stats() returns correct structure."""

    def test_stats_structure(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True}})
        stats = tf.get_stats()
        assert "enabled" in stats
        assert "total_ips" in stats
        assert "total_cidrs" in stats
        assert "feeds" in stats
        assert isinstance(stats["feeds"], list)

    def test_ip_count_reflects_loaded_ips(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True}})
        tf._ips = {"1.2.3.4", "5.6.7.8"}
        assert tf.ip_count == 2
        assert tf.get_stats()["total_ips"] == 2

    def test_default_feeds_enabled(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True}})
        feeds = {f["key"]: f for f in tf.get_stats()["feeds"]}
        assert feeds["emerging_threats"]["enabled"] is True
        assert feeds["feodo_tracker"]["enabled"]    is True
        assert feeds["spamhaus_drop"]["enabled"]    is False

    def test_config_disables_feed(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {
            "enabled": True,
            "feeds": {"emerging_threats": False}
        }})
        feeds = {f["key"]: f for f in tf.get_stats()["feeds"]}
        assert feeds["emerging_threats"]["enabled"] is False


class TestThreatFeedConfig:
    """ThreatFeed config loading."""

    def test_disabled_by_default(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({})
        assert tf.enabled is False

    def test_auto_block_default_false(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True}})
        assert tf.auto_block is False

    def test_severity_default_high(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True}})
        assert tf.severity == "HIGH"

    def test_custom_severity(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True, "severity": "MEDIUM"}})
        assert tf.severity == "MEDIUM"

    def test_refresh_interval(self):
        from cnsl.threat_feed import ThreatFeed
        tf = ThreatFeed({"threat_feed": {"enabled": True, "refresh_interval_sec": 7200}})
        assert tf.refresh_interval == 7200


# v1.7.0 — Zeek Log Ingestion


class TestZeekTSVState:
    """TSV header parsing and row splitting."""

    def test_fields_header_parsed(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("ssh")
        line  = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tauth_success"
        assert state.update_from_header(line) is True
        assert state.fields == ["ts", "uid", "id.orig_h", "id.orig_p", "auth_success"]

    def test_comment_lines_skipped(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        assert state.update_from_header("#open\t2026-01-01") is True
        assert state.update_from_header("1.2.3.4\t22") is False

    def test_row_to_dict(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("ssh")
        state.fields = ["ts", "uid", "id.orig_h", "id.orig_p", "auth_success"]
        row = state.row_to_dict("1620000000.0\tabc\t1.2.3.4\t54321\tF")
        assert row["id.orig_h"] == "1.2.3.4"
        assert row["auth_success"] == "F"

    def test_empty_fields_excluded(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        state.fields = ["ts", "uid", "id.orig_h", "service"]
        row = state.row_to_dict("1620000000.0\tabc\t1.2.3.4\t-")
        assert "service" not in row   # "-" is treated as empty

    def test_hash_line_returns_none(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        assert state.row_to_dict("#comment") is None


class TestZeekConnParser:
    """conn.log parsing."""

    def test_valid_conn_row(self):
        from cnsl.zeek_parser import parse_zeek_conn
        row = {"id.orig_h": "1.2.3.4", "id.resp_h": "5.6.7.8",
               "id.resp_p": "22", "proto": "tcp", "conn_state": "SF"}
        ev = parse_zeek_conn(row)
        assert ev is not None
        assert ev.kind == "NET_CONN"
        assert ev.src_ip == "1.2.3.4"
        assert ev.meta["dst_port"] == "22"

    def test_missing_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_conn
        assert parse_zeek_conn({"id.resp_h": "5.6.7.8"}) is None

    def test_empty_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_conn
        assert parse_zeek_conn({"id.orig_h": "-", "id.resp_h": "5.6.7.8"}) is None


class TestZeekSSHParser:
    """ssh.log parsing."""

    def test_ssh_fail(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        row = {"id.orig_h": "1.2.3.4", "id.resp_h": "10.0.0.1",
               "auth_success": "F", "auth_attempts": "3"}
        ev = parse_zeek_ssh(row)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"
        assert ev.src_ip == "1.2.3.4"

    def test_ssh_success(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        row = {"id.orig_h": "2.3.4.5", "id.resp_h": "10.0.0.1",
               "auth_success": "T", "auth_attempts": "1"}
        ev = parse_zeek_ssh(row)
        assert ev is not None
        assert ev.kind == "SSH_SUCCESS"

    def test_ssh_success_variants(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        for val in ("t", "true", "1", "T", "True"):
            row = {"id.orig_h": "1.1.1.1", "auth_success": val}
            assert parse_zeek_ssh(row).kind == "SSH_SUCCESS"

    def test_missing_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        assert parse_zeek_ssh({"auth_success": "F"}) is None


class TestZeekHTTPParser:
    """http.log parsing."""

    def test_exploit_path_detected(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "3.3.3.3", "uri": "/wp-login.php",
               "method": "POST", "status_code": "200", "user_agent": "Mozilla"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_EXPLOIT_ATTEMPT"

    def test_404_is_web_scan(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "4.4.4.4", "uri": "/random-path",
               "method": "GET", "status_code": "404", "user_agent": "Mozilla"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_SCAN"

    def test_401_is_web_auth_fail(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "5.5.5.5", "uri": "/admin",
               "method": "GET", "status_code": "401", "user_agent": "curl/7.0"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_AUTH_FAIL"

    def test_scanner_ua_detected(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "6.6.6.6", "uri": "/index.html",
               "method": "GET", "status_code": "200", "user_agent": "sqlmap/1.0"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_SCAN"

    def test_normal_traffic_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "7.7.7.7", "uri": "/index.html",
               "method": "GET", "status_code": "200", "user_agent": "Mozilla/5.0"}
        assert parse_zeek_http(row) is None


class TestZeekDNSParser:
    """dns.log entropy-based tunneling detection."""

    def test_high_entropy_query_flagged(self):
        from cnsl.zeek_parser import parse_zeek_dns, _shannon_entropy
        # Use a label with confirmed high entropy (>3.5)
        label = "x7Kq2mN9pR4wB6vZ"   # random alphanumeric — high entropy
        entropy = _shannon_entropy(label)
        assert entropy > 3.5, f"Test label entropy too low: {entropy:.2f}"
        row = {"id.orig_h": "8.8.8.8",
               "query": f"{label}.tunnel.example.com",
               "qtype_name": "TXT"}
        ev = parse_zeek_dns(row, entropy_threshold=3.5)
        assert ev is not None
        assert ev.kind == "DNS_QUERY"
        assert ev.meta["entropy"] > 3.5

    def test_normal_domain_not_flagged(self):
        from cnsl.zeek_parser import parse_zeek_dns
        row = {"id.orig_h": "8.8.8.8",
               "query": "www.google.com",
               "qtype_name": "A"}
        ev = parse_zeek_dns(row, entropy_threshold=3.5)
        assert ev is None

    def test_missing_query_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_dns
        assert parse_zeek_dns({"id.orig_h": "1.1.1.1"}) is None


class TestZeekNoticeWierd:
    """notice.log and weird.log parsing."""

    def test_notice_parsed(self):
        from cnsl.zeek_parser import parse_zeek_notice
        row = {"src": "1.2.3.4", "note": "Scan::Port_Scan",
               "msg": "1.2.3.4 scanned at least 15 unique ports"}
        ev = parse_zeek_notice(row)
        assert ev is not None
        assert ev.kind == "ZEEK_NOTICE"
        assert ev.meta["note"] == "Scan::Port_Scan"

    def test_notice_uses_id_orig_h_fallback(self):
        from cnsl.zeek_parser import parse_zeek_notice
        row = {"id.orig_h": "2.3.4.5", "note": "Test::Notice", "msg": "test"}
        ev = parse_zeek_notice(row)
        assert ev is not None
        assert ev.src_ip == "2.3.4.5"

    def test_weird_parsed(self):
        from cnsl.zeek_parser import parse_zeek_weird
        row = {"id.orig_h": "3.4.5.6", "name": "bad_TCP_checksum",
               "addl": "extra info"}
        ev = parse_zeek_weird(row)
        assert ev is not None
        assert ev.kind == "ZEEK_WEIRD"
        assert ev.meta["name"] == "bad_TCP_checksum"

    def test_weird_no_name_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_weird
        assert parse_zeek_weird({"id.orig_h": "1.1.1.1"}) is None


class TestZeekLogParser:
    """ZeekLogParser stateful line-by-line parsing."""

    def test_tsv_full_flow_ssh(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="tsv")
        lines = [
            "#separator \\x09",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tauth_attempts\tdirection\tclient\tserver\tcipher_alg\tmac_alg\tcompression_alg\tkex_alg\thost_key_alg\thost_key",
            "1620000000.0\tabc\t9.9.9.9\t54321\t10.0.0.1\t22\t2\tF\t3\tINBOUND\t-\t-\t-\t-\t-\t-\t-\t-",
        ]
        events = [parser.parse(l) for l in lines]
        events = [e for e in events if e]
        assert len(events) == 1
        assert events[0].kind == "SSH_FAIL"
        assert events[0].src_ip == "9.9.9.9"

    def test_json_ssh_fail(self):
        import json
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="json")
        line = json.dumps({
            "ts": 1620000000.0, "uid": "abc",
            "id.orig_h": "1.2.3.4", "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1", "id.resp_p": 22,
            "auth_success": False, "auth_attempts": 5,
        })
        ev = parser.parse(line)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"

    def test_header_lines_return_none(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("conn")
        assert parser.parse("#separator \\x09") is None
        assert parser.parse("#fields\tts\tuid") is None
        assert parser.parse("") is None

    def test_invalid_json_returns_none(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="json")
        assert parser.parse("not-json-at-all") is None


class TestShannonEntropy:
    """Entropy helper for DNS tunneling detection."""

    def test_high_entropy_string(self):
        from cnsl.zeek_parser import _shannon_entropy
        # Random-looking base64 — high entropy
        assert _shannon_entropy("aGVsbG93b3JsZA") > 3.0

    def test_low_entropy_string(self):
        from cnsl.zeek_parser import _shannon_entropy
        # Simple word — low entropy
        assert _shannon_entropy("www") < 2.0

    def test_empty_string(self):
        from cnsl.zeek_parser import _shannon_entropy
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        from cnsl.zeek_parser import _shannon_entropy
        assert _shannon_entropy("aaaa") == 0.0


# v1.8.0 — Full UEBA


class TestUEBAProfile:
    """UserProfile building and anomaly detection."""

    def _make_ueba(self, cfg=None):
        from cnsl.ueba import UEBAEngine
        return UEBAEngine(cfg or {"ueba": {"enabled": True, "min_observations": 3}})

    def test_no_anomaly_below_min_observations(self):
        ueba = self._make_ueba()
        for _ in range(2):
            a = ueba.observe("alice", "1.2.3.4")
            assert a is None, "should not fire before min_observations"

    def test_profile_created_on_first_observe(self):
        ueba = self._make_ueba()
        ueba.observe("bob", "5.6.7.8")
        assert ueba.get_profile("bob") is not None

    def test_known_ip_not_flagged(self):
        ueba = self._make_ueba()
        ip   = "1.2.3.4"
        # Build up profile past min_observations with same IP
        for _ in range(5):
            ueba.observe("alice", ip)
        # Same IP should not trigger new_source_ip
        a = ueba.observe("alice", ip)
        if a:
            assert "new_source_ip" not in a.anomaly_types

    def test_new_source_ip_flagged(self):
        ueba = self._make_ueba()
        for _ in range(5):
            ueba.observe("alice", "1.1.1.1")
        a = ueba.observe("alice", "9.9.9.9")
        assert a is not None
        assert "new_source_ip" in a.anomaly_types

    def test_login_after_absence_flagged(self):
        ueba = self._make_ueba()
        old_ts = 1000000.0
        for _ in range(5):
            ueba.observe("bob", "2.2.2.2", ts=old_ts)
        # 10 days later
        new_ts = old_ts + (10 * 86400)
        a = ueba.observe("bob", "2.2.2.2", ts=new_ts)
        assert a is not None
        assert "login_after_absence" in a.anomaly_types

    def test_frequency_spike_flagged(self):
        ueba = self._make_ueba({"ueba": {
            "enabled": True, "min_observations": 3,
            "frequency_spike_factor": 2.0,
        }})
        base = 1_700_000_000.0
        day  = 86400
        # Days 0-5: 2 logins each
        for d in range(6):
            for _ in range(2):
                ueba.observe("carol", "3.3.3.3", ts=base + d * day)
        # Day 6: 20 logins (spike)
        anomaly = None
        for _ in range(20):
            anomaly = ueba.observe("carol", "3.3.3.3", ts=base + 6 * day + 1)
        assert anomaly is not None
        assert "frequency_spike" in anomaly.anomaly_types


class TestUEBALateralMovement:
    """Lateral movement detection."""

    def test_lateral_movement_flagged(self):
        from cnsl.ueba import UEBAEngine
        ueba = UEBAEngine({"ueba": {
            "enabled":              True,
            "min_observations":     3,
            "lateral_window_sec":   600,
            "lateral_ip_threshold": 3,
        }})
        base = 1_700_000_000.0
        # Build profile
        for _ in range(5):
            ueba.observe("dave", "1.1.1.1", ts=base)
        # Now hit 3 different IPs within the window
        ueba.observe("dave", "2.2.2.2", ts=base + 100)
        ueba.observe("dave", "3.3.3.3", ts=base + 200)
        a = ueba.observe("dave", "4.4.4.4", ts=base + 300)
        assert a is not None
        assert "lateral_movement" in a.anomaly_types

    def test_lateral_movement_outside_window_not_flagged(self):
        from cnsl.ueba import UEBAEngine
        ueba = UEBAEngine({"ueba": {
            "enabled":              True,
            "min_observations":     3,
            "lateral_window_sec":   60,
            "lateral_ip_threshold": 3,
        }})
        base = 1_700_000_000.0
        for _ in range(5):
            ueba.observe("eve", "1.1.1.1", ts=base)
        # IPs spread > window apart — should NOT trigger lateral movement
        ueba.observe("eve", "2.2.2.2", ts=base + 1000)
        ueba.observe("eve", "3.3.3.3", ts=base + 2000)
        a = ueba.observe("eve", "4.4.4.4", ts=base + 3000)
        if a:
            assert "lateral_movement" not in a.anomaly_types


class TestUEBAAnomaly:
    """UEBAAnomaly dataclass."""

    def test_to_dict_fields(self):
        from cnsl.ueba import UEBAAnomaly
        a = UEBAAnomaly(
            username="alice", src_ip="1.2.3.4",
            reason="test reason", anomaly_types=["new_source_ip"],
            ts=1_700_000_000.0,
        )
        d = a.to_dict()
        assert d["username"] == "alice"
        assert d["src_ip"]   == "1.2.3.4"
        assert d["reason"]   == "test reason"
        assert "new_source_ip" in d["anomaly_types"]
        assert "time" in d

    def test_multiple_anomaly_types(self):
        from cnsl.ueba import UEBAAnomaly
        a = UEBAAnomaly(
            username="bob", src_ip="2.3.4.5",
            reason="a; b",
            anomaly_types=["new_source_ip", "unusual_hour"],
            ts=1_700_000_000.0,
        )
        d = a.to_dict()
        assert len(d["anomaly_types"]) == 2


class TestUEBAEngine:
    """UEBAEngine API methods."""

    def _make_ueba(self):
        from cnsl.ueba import UEBAEngine
        return UEBAEngine({"ueba": {"enabled": True, "min_observations": 3}})

    def test_stats_empty(self):
        ueba = self._make_ueba()
        s = ueba.stats()
        assert s["total_profiles"] == 0
        assert s["anomalous_users"] == 0

    def test_stats_after_observe(self):
        ueba = self._make_ueba()
        ueba.observe("alice", "1.1.1.1")
        ueba.observe("bob", "2.2.2.2")
        assert ueba.stats()["total_profiles"] == 2

    def test_list_profiles(self):
        ueba = self._make_ueba()
        for u in ("alice", "bob", "carol"):
            ueba.observe(u, "1.1.1.1")
        profiles = ueba.list_profiles(limit=10)
        assert len(profiles) == 3

    def test_get_profile_unknown_user(self):
        ueba = self._make_ueba()
        assert ueba.get_profile("nobody") is None

    def test_get_profile_known_user(self):
        ueba = self._make_ueba()
        ueba.observe("alice", "1.1.1.1")
        p = ueba.get_profile("alice")
        assert p is not None
        assert p["username"] == "alice"
        assert p["total_logins"] == 1

    def test_disabled_ueba_returns_none(self):
        from cnsl.ueba import UEBAEngine
        ueba = UEBAEngine({"ueba": {"enabled": False}})
        assert ueba.observe("alice", "1.1.1.1") is None

    def test_profile_count_property(self):
        ueba = self._make_ueba()
        ueba.observe("alice", "1.1.1.1")
        assert ueba.profile_count == 1


class TestUEBAConfig:
    """UEBA config loading."""

    def test_disabled_by_default(self):
        from cnsl.ueba import UEBAEngine
        ueba = UEBAEngine({})
        assert ueba.enabled is False

    def test_custom_thresholds(self):
        from cnsl.ueba import UEBAEngine
        ueba = UEBAEngine({"ueba": {
            "enabled":              True,
            "lateral_window_sec":   300,
            "lateral_ip_threshold": 5,
            "absence_days":         14,
        }})
        assert ueba.lateral_window_sec   == 300
        assert ueba.lateral_ip_threshold == 5
        assert ueba.absence_days         == 14


# v1.9.0 — Agent System + WebSocket


class TestAgentQueue:
    """AgentQueue bounded queue with drop-oldest overflow."""

    def test_put_and_get(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=10)
        q.put_nowait({"event": "test"})
        assert q.qsize == 1

    def test_overflow_drops_oldest(self):
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=3)
        q.put_nowait({"id": 1})
        q.put_nowait({"id": 2})
        q.put_nowait({"id": 3})
        # This should drop {"id": 1}
        q.put_nowait({"id": 4})
        assert q.dropped == 1
        assert q.qsize == 3

    def test_get_batch_respects_max_items(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=100)
        for i in range(10):
            q.put_nowait({"id": i})
        batch = asyncio.run(q.get_batch(5, 0.1))
        assert len(batch) == 5

    def test_get_batch_returns_all_if_fewer_than_max(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=100)
        for i in range(3):
            q.put_nowait({"id": i})
        batch = asyncio.run(q.get_batch(10, 0.1))
        assert len(batch) == 3

    def test_get_batch_timeout_returns_empty(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=10)
        batch = asyncio.run(q.get_batch(5, 0.05))
        assert batch == []


class TestAgentConfig:
    """Agent config loading."""

    def test_default_config_has_required_keys(self):
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        assert "server" in DEFAULT_AGENT_CONFIG
        assert "token"  in DEFAULT_AGENT_CONFIG
        assert "sources" in DEFAULT_AGENT_CONFIG

    def test_load_config_returns_defaults_with_no_file(self):
        from cnsl.agent import load_agent_config
        cfg = load_agent_config("/nonexistent/path/config.json")
        assert cfg["queue_size"] == 1000
        assert "auth" in cfg["sources"]

    def test_load_config_merges_file(self):
        import json, tempfile
        from cnsl.agent import load_agent_config
        data = {"token": "test-token", "hostname": "myhost"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            fname = f.name
        cfg = load_agent_config(fname)
        assert cfg["token"]    == "test-token"
        assert cfg["hostname"] == "myhost"
        assert cfg["queue_size"] == 1000   # default preserved

    def test_hostname_default_is_machine_name(self):
        import socket
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        assert DEFAULT_AGENT_CONFIG["hostname"] == socket.gethostname()


class TestDashboardSignatureWithWS:
    """Dashboard start_dashboard accepts new ws/agent parameters."""

    def test_start_dashboard_accepts_ueba(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "ueba"        in sig.parameters
        assert "threat_feed" in sig.parameters
        assert "case_manager" in sig.parameters

    def test_start_dashboard_all_new_params_optional(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        for name in ("ueba", "threat_feed", "case_manager"):
            p = sig.parameters[name]
            assert p.default is not inspect.Parameter.empty, \
                f"{name} should have a default value"


class TestAgentModule:
    """Agent module structure tests."""

    def test_agent_module_importable(self):
        from cnsl import agent
        assert hasattr(agent, "AgentQueue")
        assert hasattr(agent, "run_agent")
        assert hasattr(agent, "load_agent_config")
        assert hasattr(agent, "main")

    def test_supported_sources(self):
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        sources = DEFAULT_AGENT_CONFIG["sources"]
        assert "auth"   in sources
        assert "nginx"  in sources
        assert "apache" in sources
        assert "mysql"  in sources
        assert "ufw"    in sources
        assert "syslog" in sources

    def test_queue_dropped_counter_starts_zero(self):
        from cnsl.agent import AgentQueue
        q = AgentQueue()
        assert q.dropped == 0


# v2.0.0 — Kafka + Multi-tenant + Rate Limiting + Reports


class TestRateLimiter:
    """RateLimiter sliding window and DDoS detection."""

    def _make_rl(self, rpm=10, burst=5, ddos=20, ddos_window=5):
        from cnsl.rate_limiter import RateLimiter
        return RateLimiter({"rate_limiting": {
            "enabled": True, "requests_per_min": rpm, "burst": burst,
            "window_sec": 60, "ddos_threshold": ddos,
            "ddos_window_sec": ddos_window, "auto_block": False,
            "whitelist": ["127.0.0.1"],
        }})

    def test_allows_within_limit(self):
        rl = self._make_rl(rpm=10, burst=5)
        allowed, retry = rl.check("1.2.3.4")
        assert allowed is True
        assert retry == 0.0

    def test_blocks_above_limit(self):
        rl = self._make_rl(rpm=3, burst=0)
        ip = "1.2.3.4"
        for _ in range(3):
            rl.check(ip)
        allowed, retry = rl.check(ip)
        assert allowed is False
        assert retry > 0

    def test_whitelist_always_allowed(self):
        rl = self._make_rl(rpm=1, burst=0)
        for _ in range(100):
            allowed, _ = rl.check("127.0.0.1")
            assert allowed is True

    def test_disabled_always_allows(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": False}})
        allowed, _ = rl.check("1.2.3.4")
        assert allowed is True

    def test_ddos_detection(self):
        rl = self._make_rl(ddos=5, ddos_window=60)
        ip = "2.3.4.5"
        for _ in range(5):
            rl.check_ddos(ip)
        assert rl.check_ddos(ip) is True

    def test_ddos_whitelist_exempt(self):
        rl = self._make_rl(ddos=5, ddos_window=60)
        for _ in range(100):
            assert rl.check_ddos("127.0.0.1") is False

    def test_reset_clears_state(self):
        rl = self._make_rl(rpm=2, burst=0)
        ip = "3.3.3.3"
        for _ in range(3):
            rl.check(ip)
        rl.reset_ip(ip)
        allowed, _ = rl.check(ip)
        assert allowed is True

    def test_stats_structure(self):
        rl = self._make_rl()
        s  = rl.get_stats()
        assert "enabled" in s
        assert "requests_per_min" in s
        assert "total_requests" in s

    def test_top_requesters(self):
        rl = self._make_rl(rpm=100, burst=50)
        for _ in range(5):
            rl.check("1.1.1.1")
            rl.record("1.1.1.1")
        for _ in range(3):
            rl.check("2.2.2.2")
            rl.record("2.2.2.2")
        top = rl.top_requesters(2)
        assert len(top) <= 2

    def test_per_endpoint_config(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {
            "enabled": True, "requests_per_min": 100, "burst": 0,
            "window_sec": 60, "ddos_threshold": 500, "ddos_window_sec": 10,
            "auto_block": False, "whitelist": [],
            "endpoints": {"/api/login": {"requests_per_min": 2, "window_sec": 60}}
        }})
        ip = "4.4.4.4"
        for _ in range(2):
            rl.check(ip, "/api/login")
        allowed, _ = rl.check(ip, "/api/login")
        assert allowed is False


class TestTenantManager:
    """TenantManager single and multi-tenant modes."""

    def _make_single(self):
        from cnsl.tenants import TenantManager
        return TenantManager({
            "auth": {"users": {"admin": {"password_hash": "x", "role": "admin"}}},
            "tenants": {"enabled": False},
        })

    def _make_multi(self):
        from cnsl.tenants import TenantManager
        return TenantManager({"tenants": {
            "enabled": True,
            "default_tenant": "acme",
            "list": {
                "acme":   {"display_name": "Acme Corp", "users": {"alice": {"role": "admin"}}},
                "globex": {"display_name": "Globex Inc", "users": {"bob": {"role": "analyst"}}},
            },
        }})

    def test_single_tenant_default(self):
        tm = self._make_single()
        assert tm.enabled is False
        assert tm.count == 1

    def test_single_tenant_get_default(self):
        tm = self._make_single()
        t  = tm.get_default()
        assert t is not None
        assert t.id == "default"

    def test_multi_tenant_count(self):
        tm = self._make_multi()
        assert tm.count == 2

    def test_resolve_by_id(self):
        tm = self._make_multi()
        t  = tm.resolve("acme")
        assert t.display_name == "Acme Corp"

    def test_resolve_unknown_falls_back_to_default(self):
        tm = self._make_multi()
        t  = tm.resolve("unknown_tenant")
        assert t.id == "acme"

    def test_list_tenants(self):
        tm = self._make_multi()
        lst = tm.list_tenants()
        ids = [t["id"] for t in lst]
        assert "acme" in ids and "globex" in ids

    def test_add_tenant(self):
        tm  = self._make_multi()
        err = tm.add_tenant("newco", {"display_name": "NewCo"})
        assert err is None
        assert tm.count == 3

    def test_add_duplicate_tenant_returns_error(self):
        tm  = self._make_multi()
        err = tm.add_tenant("acme", {})
        assert err is not None

    def test_remove_tenant(self):
        tm  = self._make_multi()
        err = tm.remove_tenant("globex")
        assert err is None
        assert tm.count == 1

    def test_cannot_remove_default_tenant(self):
        tm  = self._make_multi()
        err = tm.remove_tenant("acme")  # acme is default
        assert err is not None

    def test_per_tenant_rules(self):
        from cnsl.tenants import TenantManager
        tm = TenantManager({"tenants": {
            "enabled": True,
            "default_tenant": "t1",
            "list": {
                "t1": {"rules": {"ssh.brute_force": {"threshold": 3}}},
            },
        }})
        t = tm.resolve("t1")
        re = t.get_rules({})
        assert re.threshold("ssh.brute_force") == 3

    def test_update_tenant_rules(self):
        tm  = self._make_multi()
        err = tm.update_tenant_rules("acme", {"ssh.brute_force": {"threshold": 2}})
        assert err is None
        t   = tm.resolve("acme")
        re  = t.get_rules({})
        assert re.threshold("ssh.brute_force") == 2


class TestKafkaConsumer:
    """KafkaConsumer config and parser registry."""

    def test_disabled_by_default(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({}, None, None)
        assert kc.enabled is False

    def test_config_loaded(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({"kafka": {
            "enabled": True,
            "bootstrap_servers": "kafka:9092",
            "group_id": "test-group",
            "topics": {"auth_logs": {"parser": "auth", "enabled": True}},
        }}, None, None)
        assert kc.enabled is True
        assert kc.bootstrap_servers == "kafka:9092"
        assert "auth_logs" in kc.topics_cfg

    def test_parser_registry_has_standard_parsers(self):
        from cnsl.kafka_consumer import _build_parser_registry
        registry = _build_parser_registry()
        assert "auth"   in registry
        assert "nginx"  in registry
        assert "syslog" in registry
        assert "json"   in registry

    def test_json_parser_valid_event(self):
        from cnsl.kafka_consumer import _parse_json_event
        import json
        line = json.dumps({
            "kind": "SSH_FAIL", "src_ip": "1.2.3.4",
            "source": "kafka", "ts": 1700000000.0
        })
        ev = _parse_json_event(line)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"
        assert ev.src_ip == "1.2.3.4"

    def test_json_parser_invalid_returns_none(self):
        from cnsl.kafka_consumer import _parse_json_event
        assert _parse_json_event("not json") is None
        assert _parse_json_event("{}") is None

    def test_stats_structure(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({"kafka": {"enabled": True}}, None, None)
        s  = kc.get_stats()
        assert "enabled" in s
        assert "messages_received" in s
        assert "events_parsed" in s


class TestReporterEnhanced:
    """Enhanced reporter accepts new optional modules."""

    def test_reporter_accepts_new_params(self):
        import inspect
        from cnsl.reporter import Reporter
        sig = inspect.signature(Reporter.__init__)
        assert "ueba"         in sig.parameters
        assert "case_manager" in sig.parameters
        assert "rule_engine"  in sig.parameters
        assert "rate_limiter" in sig.parameters

    def test_reporter_none_modules_safe(self):
        from cnsl.reporter import Reporter
        r = Reporter(store=None, fim=None, cfg={},
                     ueba=None, case_manager=None,
                     rule_engine=None, rate_limiter=None)
        assert r.ueba         is None
        assert r.rate_limiter is None


# HuddleCluster Integration


class TestHuddleTemperature:
    """Temperature calculator."""

    def test_idle_temp_zero(self):
        from cnsl.huddle_integration import compute_temperature
        t = compute_temperature(0, 0, 10000, 0)
        assert t == 0.0

    def test_full_load_max_temp(self):
        from cnsl.huddle_integration import compute_temperature
        t = compute_temperature(100, 10000, 10000, 50)
        assert t == 1.0

    def test_moderate_load(self):
        from cnsl.huddle_integration import compute_temperature
        t = compute_temperature(
            events_per_sec=20, queue_size=2000,
            queue_max=10000, active_incidents=10)
        assert 0.1 < t < 0.6

    def test_clamped_above_one(self):
        from cnsl.huddle_integration import compute_temperature
        t = compute_temperature(999, 99999, 100, 999)
        assert t == 1.0

    def test_clamped_below_zero(self):
        from cnsl.huddle_integration import compute_temperature
        t = compute_temperature(-10, -100, 10000, -5)
        assert t == 0.0


class TestHuddleManager:
    """HuddleManager config and disabled state."""

    def test_disabled_by_default(self):
        from cnsl.huddle_integration import HuddleManager
        hm = HuddleManager({})
        assert hm.enabled is False

    def test_config_loaded(self):
        from cnsl.huddle_integration import HuddleManager
        hm = HuddleManager({"huddle": {
            "enabled": True,
            "nodes": [{"id": "n1", "host": "10.0.0.1", "port": 8765}],
            "max_inner_size": 1,
        }})
        assert hm.enabled is True
        assert len(hm._nodes_cfg) == 1
        assert hm._max_inner == 1

    def test_disabled_proxy_returns_none(self):
        from cnsl.huddle_integration import HuddleManager
        hm = HuddleManager({})
        assert hm.proxy("1.2.3.4") is None

    def test_disabled_stats_enabled_false(self):
        from cnsl.huddle_integration import HuddleManager
        hm = HuddleManager({})
        assert hm.get_stats()["enabled"] is False

    def test_heat_cool_thresholds(self):
        from cnsl.huddle_integration import HuddleManager
        hm = HuddleManager({"huddle": {
            "enabled": True,
            "heat_threshold": 0.8,
            "cool_threshold": 0.3,
        }})
        assert hm._heat_thresh == 0.8
        assert hm._cool_thresh == 0.3


# v2.2.0 -- kill chain tracker


class TestKillChainStages:
    """Event kind to kill chain stage mapping."""

    def _make_tracker(self, cfg=None):
        from cnsl.kill_chain import KillChainTracker
        return KillChainTracker(cfg or {"kill_chain": {"enabled": True}})

    def test_ssh_fail_maps_to_delivery(self):
        from cnsl.kill_chain import KCStage
        kc = self._make_tracker()
        chain = kc.update("1.2.3.4", "SSH_FAIL")
        assert chain is not None
        assert chain.max_stage == KCStage.DELIVERY

    def test_ssh_success_maps_to_exploitation(self):
        from cnsl.kill_chain import KCStage
        kc = self._make_tracker()
        kc.update("1.2.3.4", "SSH_FAIL")
        chain = kc.update("1.2.3.4", "SSH_SUCCESS")
        assert chain.max_stage == KCStage.EXPLOITATION

    def test_web_scan_maps_to_reconnaissance(self):
        from cnsl.kill_chain import KCStage
        kc = self._make_tracker()
        chain = kc.update("1.2.3.4", "WEB_SCAN")
        assert chain.max_stage == KCStage.RECONNAISSANCE

    def test_sudo_fail_maps_to_installation(self):
        from cnsl.kill_chain import KCStage
        kc = self._make_tracker()
        chain = kc.update("1.2.3.4", "SUDO_FAIL")
        assert chain.max_stage == KCStage.INSTALLATION

    def test_unmapped_kind_returns_none(self):
        kc = self._make_tracker()
        chain = kc.update("1.2.3.4", "SOME_UNKNOWN_KIND")
        assert chain is None

    def test_disabled_tracker_returns_none(self):
        kc = self._make_tracker({"kill_chain": {"enabled": False}})
        chain = kc.update("1.2.3.4", "SSH_FAIL")
        assert chain is None


class TestKillChainScore:
    """Score calculation and complete-chain detection."""

    def _make_tracker(self):
        from cnsl.kill_chain import KillChainTracker
        return KillChainTracker({"kill_chain": {"enabled": True}})

    def test_score_increases_with_stage(self):
        kc = self._make_tracker()
        kc.update("1.1.1.1", "WEB_SCAN")          # stage 0
        chain_low = kc.get_chain("1.1.1.1")

        kc.update("2.2.2.2", "WEB_SCAN")          # stage 0
        kc.update("2.2.2.2", "SSH_FAIL")          # stage 2
        kc.update("2.2.2.2", "SSH_SUCCESS")       # stage 3
        chain_high = kc.get_chain("2.2.2.2")

        assert chain_high.score > chain_low.score

    def test_complete_requires_recon_delivery_exploitation(self):
        kc = self._make_tracker()
        kc.update("1.2.3.4", "WEB_SCAN")     # recon
        kc.update("1.2.3.4", "SSH_FAIL")     # delivery
        chain = kc.get_chain("1.2.3.4")
        assert chain.complete is False

        kc.update("1.2.3.4", "SSH_SUCCESS")  # exploitation
        chain = kc.get_chain("1.2.3.4")
        assert chain.complete is True

    def test_partial_chain_not_complete(self):
        kc = self._make_tracker()
        kc.update("1.2.3.4", "WEB_SCAN")
        chain = kc.get_chain("1.2.3.4")
        assert chain.complete is False

    def test_correlation_rule_maps_to_c2_stage(self):
        from cnsl.kill_chain import KCStage
        kc = self._make_tracker()
        chain = kc.update_from_correlation("1.2.3.4", "persistent_recon")
        assert chain is not None
        assert chain.max_stage == KCStage.C2


class TestKillChainQueries:
    """get_all, stats, and eviction behavior."""

    def _make_tracker(self, max_chains=None):
        from cnsl.kill_chain import KillChainTracker
        cfg = {"kill_chain": {"enabled": True}}
        if max_chains is not None:
            cfg["kill_chain"]["max_chains"] = max_chains
        return KillChainTracker(cfg)

    def test_get_all_sorted_by_score_descending(self):
        kc = self._make_tracker()
        kc.update("1.1.1.1", "WEB_SCAN")
        kc.update("2.2.2.2", "WEB_SCAN")
        kc.update("2.2.2.2", "SSH_FAIL")
        kc.update("2.2.2.2", "SSH_SUCCESS")
        chains = kc.get_all(limit=10)
        assert chains[0].ip == "2.2.2.2"

    def test_complete_only_filter(self):
        kc = self._make_tracker()
        kc.update("1.1.1.1", "WEB_SCAN")
        kc.update("2.2.2.2", "WEB_SCAN")
        kc.update("2.2.2.2", "SSH_FAIL")
        kc.update("2.2.2.2", "SSH_SUCCESS")
        chains = kc.get_all(complete_only=True)
        assert all(c.complete for c in chains)
        assert len(chains) == 1

    def test_stats_returns_totals(self):
        kc = self._make_tracker()
        kc.update("1.1.1.1", "WEB_SCAN")
        stats = kc.stats()
        assert stats["total_chains"] == 1

    def test_max_chains_evicts_oldest(self):
        kc = self._make_tracker(max_chains=2)
        kc.update("1.1.1.1", "WEB_SCAN")
        kc.update("2.2.2.2", "WEB_SCAN")
        kc.update("3.3.3.3", "WEB_SCAN")
        assert len(kc._chains) == 2
        assert "1.1.1.1" not in kc._chains


# v2.3.0 -- automated pattern learning


class TestPatternFingerprint:
    """Pattern fingerprinting and ID generation."""

    def test_fingerprint_sorted_and_deduped(self):
        from cnsl.pattern_learner import _fingerprint
        key, kinds = _fingerprint([("SSH_FAIL", "auth"), ("WEB_SCAN", "nginx"),
                                    ("SSH_FAIL", "auth")])
        assert kinds == ["SSH_FAIL", "WEB_SCAN"]
        assert key == "SSH_FAIL+WEB_SCAN"

    def test_empty_pairs_returns_empty(self):
        from cnsl.pattern_learner import _fingerprint
        key, kinds = _fingerprint([])
        assert key == ""
        assert kinds == []

    def test_same_kinds_different_order_same_fingerprint(self):
        from cnsl.pattern_learner import _fingerprint
        key1, _ = _fingerprint([("A", "x"), ("B", "y")])
        key2, _ = _fingerprint([("B", "y"), ("A", "x")])
        assert key1 == key2

    def test_make_id_deterministic(self):
        from cnsl.pattern_learner import _make_id
        assert _make_id("SSH_FAIL+WEB_SCAN") == _make_id("SSH_FAIL+WEB_SCAN")

    def test_make_id_differs_for_different_patterns(self):
        from cnsl.pattern_learner import _make_id
        assert _make_id("A+B") != _make_id("C+D")


class TestPatternLearnerObservation:
    """Event observation and buffer management."""

    def _make_learner(self, cfg=None):
        from cnsl.pattern_learner import PatternLearner
        return PatternLearner(cfg or {"pattern_learning": {
            "enabled": True, "lookback_sec": 300, "min_occurrences": 3,
        }})

    def _make_event(self, ip, kind, source="auth"):
        from cnsl.models import Event, now
        return Event(ts=now(), source=source, kind=kind, src_ip=ip, user=None,
                     raw=f"test event {kind} from {ip}")

    def test_observe_event_populates_buffer(self):
        pl = self._make_learner()
        pl.observe_event(self._make_event("1.2.3.4", "SSH_FAIL"))
        buf = pl._buffers.get("1.2.3.4")
        assert buf is not None
        assert len(buf.snapshot()) == 1

    def test_disabled_learner_ignores_events(self):
        pl = self._make_learner({"pattern_learning": {"enabled": False}})
        pl.observe_event(self._make_event("1.2.3.4", "SSH_FAIL"))
        assert "1.2.3.4" not in pl._buffers

    def test_event_without_ip_ignored(self):
        from cnsl.models import Event, now
        pl = self._make_learner()
        ev = Event(ts=now(), source="auth", kind="SSH_FAIL", src_ip=None,
                   user=None, raw="no ip")
        pl.observe_event(ev)
        assert len(pl._buffers) == 0


class TestPatternLearnerSuggestions:
    """Suggestion generation, promote, and dismiss."""

    def _make_learner(self, min_occurrences=3):
        from cnsl.pattern_learner import PatternLearner
        return PatternLearner({"pattern_learning": {
            "enabled": True, "lookback_sec": 300,
            "min_occurrences": min_occurrences,
        }})

    def _observe_and_alert(self, pl, ip, kinds):
        from cnsl.models import Event, now
        for kind in kinds:
            pl.observe_event(Event(ts=now(), source="test", kind=kind,
                                    src_ip=ip, user=None, raw=f"{kind} from {ip}"))
        return pl.on_alert(ip, "test_rule")

    def test_no_suggestion_below_min_occurrences(self):
        pl = self._make_learner(min_occurrences=5)
        for i in range(3):
            self._observe_and_alert(pl, f"1.2.3.{i}", ["SSH_FAIL", "WEB_SCAN"])
        assert len(pl.get_suggestions()) == 0

    def test_suggestion_created_at_min_occurrences(self):
        pl = self._make_learner(min_occurrences=3)
        result = None
        for i in range(3):
            result = self._observe_and_alert(pl, f"1.2.3.{i}", ["SSH_FAIL", "WEB_SCAN"])
        assert len(pl.get_suggestions()) == 1
        assert result is not None
        assert "SSH_FAIL" in result.event_kinds

    def test_suggestion_tracks_example_ips(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        # Suggestion is born on the 2nd occurrence, so only the IP that
        # triggered creation is recorded at this point.
        suggestions = pl.get_suggestions()
        assert len(suggestions) == 1
        assert "2.2.2.2" in suggestions[0].example_ips
        # A subsequent occurrence of the same pattern adds its IP too.
        self._observe_and_alert(pl, "3.3.3.3", ["SSH_FAIL", "WEB_SCAN"])
        updated = pl.get_suggestion(suggestions[0].id)
        assert "3.3.3.3" in updated.example_ips

    def test_dismiss_suppresses_future_suggestions(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        sugg = pl.get_suggestions()[0]
        assert pl.dismiss(sugg.id) is True
        assert sugg.pattern_key in pl._dismissed
        # New occurrences of the same pattern should not resurrect it
        self._observe_and_alert(pl, "3.3.3.3", ["SSH_FAIL", "WEB_SCAN"])
        active = pl.get_suggestions()
        assert len(active) == 0

    def test_mark_promoted_sets_flag(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        sugg = pl.get_suggestions()[0]
        assert pl.mark_promoted(sugg.id) is True
        assert sugg.promoted is True
        # Promoted suggestions excluded from default get_suggestions()
        assert len(pl.get_suggestions()) == 0

    def test_dismiss_unknown_id_returns_false(self):
        pl = self._make_learner()
        assert pl.dismiss("nonexistent") is False

    def test_stats_reports_counts(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        stats = pl.stats()
        assert stats["active_suggestions"] == 1
        assert stats["patterns_tracked"] >= 1


# v2.4.0 -- SIEM/SOAR connectors


class TestSIEMSeverityFiltering:
    """min_severity filtering logic shared by all connectors."""

    def test_sev_passes_equal_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("MEDIUM", "MEDIUM") is True

    def test_sev_passes_higher_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("HIGH", "MEDIUM") is True

    def test_sev_fails_lower_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("LOW", "MEDIUM") is False

    def test_sev_unknown_defaults_to_low_rank(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("UNKNOWN", "LOW") is True
        assert _sev_passes("UNKNOWN", "MEDIUM") is False


class TestSIEMConnectorConfig:
    """Connector construction reads config correctly."""

    def test_splunk_disabled_by_default(self):
        from cnsl.siem_connectors import SplunkHECConnector
        c = SplunkHECConnector({})
        assert c.enabled is False

    def test_splunk_reads_config(self):
        from cnsl.siem_connectors import SplunkHECConnector
        c = SplunkHECConnector({"siem": {"splunk": {
            "enabled": True, "hec_url": "https://splunk.example.com:8088",
            "token": "abc123", "index": "myindex",
        }}})
        assert c.enabled is True
        assert c.hec_url == "https://splunk.example.com:8088"
        assert c.index == "myindex"

    def test_sentinel_disabled_by_default(self):
        from cnsl.siem_connectors import SentinelConnector
        c = SentinelConnector({})
        assert c.enabled is False

    def test_webhook_disabled_by_default(self):
        from cnsl.siem_connectors import WebhookConnector
        c = WebhookConnector({})
        assert c.enabled is False

    def test_webhook_reads_bearer_token(self):
        from cnsl.siem_connectors import WebhookConnector
        c = WebhookConnector({"siem": {"webhook": {
            "enabled": True, "url": "https://example.com/ingest",
            "bearer_token": "secret-token",
        }}})
        assert c.bearer_token == "secret-token"


class TestSIEMRouter:
    """SIEMRouter orchestration, push, and disabled-connector behavior."""

    def test_router_disabled_when_no_connector_enabled(self):
        from cnsl.siem_connectors import SIEMRouter
        router = SIEMRouter({})
        assert router.enabled is False

    def test_router_enabled_when_any_connector_enabled(self):
        from cnsl.siem_connectors import SIEMRouter
        router = SIEMRouter({"siem": {"splunk": {"enabled": True,
                             "hec_url": "https://x.com", "token": "t"}}})
        assert router.enabled is True

    def test_push_noop_when_disabled(self):
        from cnsl.siem_connectors import SIEMRouter
        from cnsl.models import Detection

        async def _go():
            router = SIEMRouter({})
            d = Detection(src_ip="1.2.3.4", severity="HIGH", reasons=["test"],
                          fail_count=1, uniq_users=1, window_sec=60)
            # Should not raise even though no connector is enabled
            await router.push(d)

        _run(_go())

    def test_status_returns_all_connector_names(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            return await router.status()

        status = _run(_go())
        assert set(status["connectors"].keys()) == {"splunk", "sentinel", "webhook"}

    def test_flush_queue_empty_returns_empty_dict(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            return await router.flush_queue()

        result = _run(_go())
        assert result == {}

    def test_close_does_not_raise_with_no_sessions(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            await router.close()  # connectors never opened a session

        _run(_go())


class TestDashboardSignatureV2:
    """start_dashboard must accept kill_chain, pattern_learner, siem_router
    -- if it doesn't, engine.py silently passes None and the new dashboard
    tabs/sections always show as unavailable."""

    def test_start_dashboard_accepts_new_v2_params(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        params = list(sig.parameters.keys())
        assert "kill_chain" in params, \
            "start_dashboard missing kill_chain param -- Kill Chain tab will always show disabled"
        assert "pattern_learner" in params, \
            "start_dashboard missing pattern_learner param -- Suggested Rules panel will always be empty"
        assert "siem_router" in params, \
            "start_dashboard missing siem_router param -- SIEM status will always show unavailable"

    def test_start_dashboard_new_v2_params_default_none(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        for name in ("kill_chain", "pattern_learner", "siem_router"):
            assert sig.parameters[name].default is None


class TestDetectorAcceptsV2Modules:
    """Detector.__init__ must accept kill_chain, pattern_learner, siem_router
    as optional kwargs without raising, and store them on self."""

    def _make_cfg(self):
        return {
            "thresholds": {}, "actions": {"dry_run": True},
            "logging": {"console_verbose": False},
        }

    def test_detector_accepts_new_v2_kwargs(self):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        from cnsl.kill_chain import KillChainTracker
        from cnsl.pattern_learner import PatternLearner
        from cnsl.siem_connectors import SIEMRouter

        cfg     = self._make_cfg()
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)

        kc = KillChainTracker(cfg)
        pl = PatternLearner(cfg)
        sr = SIEMRouter(cfg)

        det = Detector(cfg, logger, blocker, kill_chain=kc,
                       pattern_learner=pl, siem_router=sr)
        assert det.kill_chain is kc
        assert det.pattern_learner is pl
        assert det.siem_router is sr

    def test_detector_v2_modules_default_none(self):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker

        cfg     = self._make_cfg()
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)

        det = Detector(cfg, logger, blocker)
        assert det.kill_chain is None
        assert det.pattern_learner is None
        assert det.siem_router is None


# v2.5.0 -- multi-node federation


class TestFederatedSignal:
    """FederatedSignal serialization round-trip and malformed-input handling."""

    def test_to_dict_round_trip(self):
        from cnsl.federation import FederatedSignal
        sig = FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL",
                              severity="MEDIUM")
        d = sig.to_dict()
        restored = FederatedSignal.from_dict(d)
        assert restored.node_id == "node-a"
        assert restored.ip == "1.2.3.4"
        assert restored.kind == "SSH_FAIL"
        assert restored.severity == "MEDIUM"

    def test_from_dict_missing_required_field_returns_none(self):
        from cnsl.federation import FederatedSignal
        assert FederatedSignal.from_dict({"node_id": "a", "ip": "1.2.3.4"}) is None

    def test_from_dict_severity_defaults_to_low(self):
        from cnsl.federation import FederatedSignal
        sig = FederatedSignal.from_dict({"node_id": "a", "ip": "1.2.3.4", "kind": "X"})
        assert sig.severity == "LOW"


class TestFederatedIPRecord:
    """Cross-node detection: is_cross_node only True with 2+ distinct nodes."""

    def test_single_node_not_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert record.is_cross_node is False
        assert record.node_count == 1

    def test_two_nodes_is_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-b", ip="1.2.3.4", kind="WEB_SCAN"))
        assert record.is_cross_node is True
        assert record.node_count == 2

    def test_same_node_multiple_signals_not_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert record.is_cross_node is False

    def test_to_dict_includes_kinds_per_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="WEB_SCAN"))
        d = record.to_dict()
        assert set(d["nodes"]["node-a"]["kinds"]) == {"SSH_FAIL", "WEB_SCAN"}

    def test_signal_history_bounded_per_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        for _ in range(60):
            record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert len(record.node_signals["node-a"]) <= 50


class TestFederationBusConfig:
    """FederationBus construction and config defaults."""

    def _make_redis_sync_stub(self, connected=False, node_id="test-node"):
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = node_id
        stub.prefix    = "cnsl"
        stub.connected = connected
        stub._redis    = None
        return stub

    def test_enabled_by_default(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(), logger=None)
        assert bus.enabled is True

    def test_disabled_via_config(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"enabled": False}},
                            self._make_redis_sync_stub(), logger=None)
        assert bus.enabled is False

    def test_channel_uses_redis_sync_prefix(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(), logger=None)
        assert bus._channel == "cnsl:federation"

    def test_node_id_taken_from_redis_sync(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(node_id="web-01-abc"), logger=None)
        assert bus.node_id == "web-01-abc"

    def test_not_connected_when_redis_sync_not_connected(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=False), logger=None)
        assert bus.is_connected is False

    def test_connected_when_redis_sync_connected_and_enabled(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=True), logger=None)
        assert bus.is_connected is True

    def test_dedupe_window_reads_config(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"dedupe_window_sec": 30}},
                            self._make_redis_sync_stub(), logger=None)
        assert bus.dedupe_window_sec == 30


class TestFederationBusPublish:
    """publish() behavior: disabled is a no-op success, disconnected fails cleanly."""

    def _make_redis_sync_stub(self, connected=False):
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = "test-node"
        stub.prefix    = "cnsl"
        stub.connected = connected
        stub._redis    = None
        return stub

    def test_publish_disabled_returns_true(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"enabled": False}},
                            self._make_redis_sync_stub(), logger=None)
        result = _run(bus.publish("1.2.3.4", "SSH_FAIL"))
        assert result is True  # disabled federation must never look like a failure

    def test_publish_without_ip_returns_true(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=True), logger=None)
        result = _run(bus.publish("", "SSH_FAIL"))
        assert result is True

    def test_publish_when_not_connected_returns_false(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=False), logger=None)
        result = _run(bus.publish("1.2.3.4", "SSH_FAIL"))
        assert result is False

    def test_publish_dedupes_within_window(self):
        from cnsl.federation import FederationBus

        class _StubWithRedis:
            def __init__(self):
                self.node_id   = "test-node"
                self.prefix    = "cnsl"
                self.connected = True
                self.calls     = []

                async def _publish(channel, data):
                    self.calls.append((channel, data))
                self._redis = type("R", (), {"publish": staticmethod(_publish)})()

        stub = _StubWithRedis()
        bus  = FederationBus({"federation": {"dedupe_window_sec": 60}}, stub, logger=None)

        async def _go():
            await bus.publish("1.2.3.4", "SSH_FAIL")
            await bus.publish("1.2.3.4", "SSH_FAIL")  # should be deduped
            await bus.publish("1.2.3.4", "WEB_SCAN")  # different kind, not deduped

        _run(_go())
        assert len(stub.calls) == 2  # SSH_FAIL once, WEB_SCAN once


class TestFederationBusReceive:
    """Remote signal handling: IP record updates and callback invocation."""

    def _make_bus(self):
        from cnsl.federation import FederationBus
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = "local-node"
        stub.prefix    = "cnsl"
        stub.connected = False
        stub._redis    = None
        return FederationBus({}, stub, logger=None)

    def test_handle_remote_signal_creates_ip_record(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        record = bus.get_ip_record("1.2.3.4")
        assert record is not None
        assert "remote-node" in record.node_signals

    def test_handle_remote_signal_invokes_callback(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        received = []

        async def _cb(signal):
            received.append(signal)

        bus.on_remote_signal = _cb
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        assert len(received) == 1
        assert received[0].ip == "1.2.3.4"

    def test_callback_exception_does_not_propagate(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()

        async def _bad_cb(signal):
            raise RuntimeError("boom")

        bus.on_remote_signal = _bad_cb
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))  # must not raise

    def test_node_last_seen_tracked(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        assert "remote-node" in bus._node_last_seen

    def test_signals_received_counter_increments(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        _run(bus._handle_remote_signal(sig))
        assert bus._signals_received == 2

    def test_max_remote_ips_evicts_oldest(self):
        from cnsl.federation import FederatedSignal, FederationBus
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id, stub.prefix, stub.connected, stub._redis = "local", "cnsl", False, None
        bus = FederationBus({"federation": {"max_remote_ips": 2}}, stub, logger=None)

        async def _go():
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="1.1.1.1", kind="SSH_FAIL"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="2.2.2.2", kind="SSH_FAIL"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="3.3.3.3", kind="SSH_FAIL"))

        _run(_go())
        assert len(bus._ip_records) == 2
        assert "1.1.1.1" not in bus._ip_records


class TestFederationBusQueries:
    """get_cross_node_ips, known_nodes, and status reporting."""

    def _make_bus_with_signals(self):
        from cnsl.federation import FederationBus, FederatedSignal
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id, stub.prefix, stub.connected, stub._redis = "local", "cnsl", False, None
        bus = FederationBus({}, stub, logger=None)

        async def _go():
            # 1.1.1.1 seen by two nodes -- cross-node
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-a", ip="1.1.1.1", kind="WEB_SCAN"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-b", ip="1.1.1.1", kind="SSH_FAIL"))
            # 2.2.2.2 seen by only one node -- not cross-node
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-a", ip="2.2.2.2", kind="WEB_SCAN"))

        _run(_go())
        return bus

    def test_get_cross_node_ips_filters_correctly(self):
        bus     = self._make_bus_with_signals()
        crossed = bus.get_cross_node_ips()
        ips     = [r.ip for r in crossed]
        assert "1.1.1.1" in ips
        assert "2.2.2.2" not in ips

    def test_known_nodes_lists_all_seen_nodes(self):
        bus   = self._make_bus_with_signals()
        nodes = bus.known_nodes()
        node_ids = [n["node_id"] for n in nodes]
        assert "node-a" in node_ids
        assert "node-b" in node_ids

    def test_status_reports_cross_node_count(self):
        bus    = self._make_bus_with_signals()
        status = bus.status()
        assert status["cross_node_ips"] == 1
        assert status["ips_tracked"] == 2
        assert status["known_peer_count"] == 2


class TestDetectorKillChainHelper:
    """Detector._kc_update wraps kill_chain.update and federation.publish
    consistently -- this is the single hook point all 7 call sites use."""

    def _make_detector(self, kill_chain=None, federation=None):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        cfg     = {"thresholds": {}, "actions": {"dry_run": True},
                  "logging": {"console_verbose": False}}
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)
        return Detector(cfg, logger, blocker, kill_chain=kill_chain,
                        federation=federation)

    def test_kc_update_calls_kill_chain_when_present(self):
        from cnsl.kill_chain import KillChainTracker
        kc  = KillChainTracker({"kill_chain": {"enabled": True}})
        det = self._make_detector(kill_chain=kc)
        det._kc_update("1.2.3.4", "SSH_FAIL")
        assert kc.get_chain("1.2.3.4") is not None

    def test_kc_update_noop_when_kill_chain_none(self):
        det = self._make_detector(kill_chain=None)
        det._kc_update("1.2.3.4", "SSH_FAIL")  # must not raise

    def test_kc_update_publishes_to_federation_when_present(self):
        from cnsl.federation import FederationBus

        class _Stub:
            pass
        stub = _Stub()
        stub.node_id, stub.prefix, stub.connected, stub._redis = "local", "cnsl", False, None
        fed  = FederationBus({}, stub, logger=None)
        det  = self._make_detector(federation=fed)

        det._kc_update("1.2.3.4", "SSH_FAIL")
        # publish() is scheduled via asyncio.ensure_future inside a sync
        # method -- give the event loop one tick to run it.
        _run(asyncio.sleep(0.01))
        # Not connected, so publish() returns False quickly without raising
        # -- the important contract here is that calling _kc_update with a
        # federation object present never raises synchronously.

    def test_kc_update_federation_exception_does_not_raise(self):
        class _BadFederation:
            async def publish(self, ip, kind, severity):
                raise RuntimeError("boom")
        det = self._make_detector(federation=_BadFederation())
        det._kc_update("1.2.3.4", "SSH_FAIL")  # must not raise synchronously


class TestDashboardSignatureV3:
    """start_dashboard must accept federation -- if it doesn't, engine.py
    silently passes None and the Federation panel always shows unavailable."""

    def test_start_dashboard_accepts_federation_param(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "federation" in sig.parameters.keys(), \
            "start_dashboard missing federation param -- Federation panel will always show unavailable"
        assert sig.parameters["federation"].default is None


# v2.6.0 -- cloud identity connectors


class TestCloudEventKinds:
    """Cloud event kind constants are correct strings."""

    def test_signin_fail_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.SIGNIN_FAIL == "CLOUD_SIGNIN_FAIL"

    def test_signin_success_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.SIGNIN_SUCCESS == "CLOUD_SIGNIN_SUCCESS"

    def test_mfa_fail_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.MFA_FAIL == "CLOUD_MFA_FAIL"

    def test_risky_signin_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.RISKY_SIGNIN == "CLOUD_RISKY_SIGNIN"

    def test_impossible_travel_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.IMPOSSIBLE_TRAVEL == "CLOUD_IMPOSSIBLE_TRAVEL"


class TestCloudConnectorConfig:
    """Connector construction reads config and defaults correctly."""

    def test_aws_disabled_by_default(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        c = AWSCloudTrailConnector({})
        assert c.enabled is False

    def test_aws_reads_config(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        c = AWSCloudTrailConnector({"cloud_identity": {"aws": {
            "enabled": True, "access_key_id": "AK123",
            "secret_access_key": "secret", "region": "eu-west-1",
        }}})
        assert c.enabled is True
        assert c.region == "eu-west-1"
        assert c.access_key == "AK123"

    def test_azure_disabled_by_default(self):
        from cnsl.cloud_identity import AzureADConnector
        c = AzureADConnector({})
        assert c.enabled is False

    def test_azure_reads_config(self):
        from cnsl.cloud_identity import AzureADConnector
        c = AzureADConnector({"cloud_identity": {"azure_ad": {
            "enabled": True, "tenant_id": "tenant-xyz",
            "client_id": "client-abc", "client_secret": "s3cr3t",
        }}})
        assert c.enabled is True
        assert c.tenant_id == "tenant-xyz"

    def test_poller_disabled_when_no_connector_enabled(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({})
        assert poller.any_enabled is False

    def test_poller_enabled_when_aws_enabled(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({"cloud_identity": {
            "aws": {"enabled": True, "access_key_id": "AK", "secret_access_key": "SK"}
        }})
        assert poller.any_enabled is True

    def test_poller_status_reports_events_fed(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({})
        status = poller.status()
        assert "events_fed" in status
        assert "connectors" in status
        assert "aws_cloudtrail" in status["connectors"]
        assert "azure_ad" in status["connectors"]


class TestAWSCloudTrailParser:
    """_parse_events correctly maps CloudTrail events to Event objects."""

    def _make_connector(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        return AWSCloudTrailConnector({})

    def _make_raw_event(self, login_status="Failure", mfa_used="No",
                        event_id="EVT001", src_ip="1.2.3.4", user="alice"):
        import json
        ct = json.dumps({
            "sourceIPAddress":   src_ip,
            "userIdentity":      {"userName": user},
            "responseElements":  {"ConsoleLogin": login_status},
            "additionalEventData": {"MFAUsed": mfa_used},
        })
        return {"EventId": event_id, "EventName": "ConsoleLogin",
                "CloudTrailEvent": ct}

    def test_failure_maps_to_signin_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Failure")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.SIGNIN_FAIL

    def test_success_without_mfa_maps_to_mfa_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Success", mfa_used="No")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.MFA_FAIL

    def test_success_with_mfa_maps_to_signin_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Success", mfa_used="Yes")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_event_has_correct_source_and_ip(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(src_ip="5.6.7.8", user="bob")])
        assert evs[0].source == "aws_cloudtrail"
        assert evs[0].src_ip == "5.6.7.8"
        assert evs[0].user == "bob"

    def test_cursor_deduplication(self):
        c = self._make_connector()
        raw = self._make_raw_event(event_id="EVT001")
        evs1 = c._parse_events([raw])
        assert len(evs1) == 1
        # Same event_id now matches _last_event_id
        evs2 = c._parse_events([raw])
        assert len(evs2) == 0

    def test_unknown_login_status_skipped(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Pending")])
        assert len(evs) == 0

    def test_malformed_ct_json_skipped(self):
        c = self._make_connector()
        raw = {"EventId": "X", "EventName": "ConsoleLogin",
               "CloudTrailEvent": "not-json"}
        evs = c._parse_events([raw])
        assert len(evs) == 0


class TestAzureADParser:
    """_parse_events correctly maps Azure AD sign-in events to Event objects."""

    def _make_connector(self):
        from cnsl.cloud_identity import AzureADConnector
        return AzureADConnector({})

    def _make_raw(self, error_code=0, risk_state="none",
                  ip="1.2.3.4", user="alice@contoso.com"):
        return {
            "id":                 "SIGN001",
            "status":             {"errorCode": error_code},
            "riskState":          risk_state,
            "ipAddress":          ip,
            "userPrincipalName":  user,
            "authenticationRequirement": "singleFactorAuthentication",
        }

    def test_success_maps_to_signin_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=0, risk_state="none")])
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_nonzero_error_maps_to_signin_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=50053)])
        assert evs[0].kind == CloudEventKind.SIGNIN_FAIL

    def test_mfa_error_codes_map_to_mfa_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        for code in (50074, 50079, 50076):
            evs = c._parse_events([self._make_raw(error_code=code)])
            assert evs[0].kind == CloudEventKind.MFA_FAIL, f"code {code} should map to MFA_FAIL"

    def test_risky_state_maps_to_risky_signin(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(risk_state="atRisk")])
        assert evs[0].kind == CloudEventKind.RISKY_SIGNIN

    def test_dismissed_risk_treated_as_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=0, risk_state="dismissed")])
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_event_has_correct_source_and_ip(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(ip="9.8.7.6", user="bob@corp.com")])
        assert evs[0].source == "azure_ad"
        assert evs[0].src_ip == "9.8.7.6"
        assert evs[0].user == "bob@corp.com"


class TestSigV4Signing:
    """AWS Signature Version 4 helper produces correct output shape."""

    def test_build_sigv4_headers_returns_required_keys(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            payload='{"test": 1}', target="CloudTrail.LookupEvents",
        )
        assert "Authorization" in hdrs
        assert "X-Amz-Date" in hdrs
        assert "X-Amz-Target" in hdrs
        assert "Content-Type" in hdrs

    def test_authorization_header_starts_with_aws4_hmac_sha256(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload="{}", target="CT.Lookup",
        )
        assert hdrs["Authorization"].startswith("AWS4-HMAC-SHA256 ")

    def test_different_payloads_produce_different_signatures(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs1 = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload='{"a": 1}', target="CT.Lookup",
        )
        hdrs2 = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload='{"b": 2}', target="CT.Lookup",
        )
        assert hdrs1["Authorization"] != hdrs2["Authorization"]


class TestCloudRulesRegistered:
    """The five new cloud detection rules are in the RuleEngine."""

    def test_cloud_rules_present(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        for rule_id in (
            "cloud.signin_brute_force",
            "cloud.mfa_failure",
            "cloud.risky_signin",
            "cloud.signin_breach",
            "cloud.impossible_travel",
        ):
            assert re.get(rule_id) is not None, f"Rule {rule_id!r} not found"

    def test_cloud_mfa_failure_default_threshold_is_one(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        assert re.get("cloud.mfa_failure").effective_threshold == 1

    def test_cloud_signin_brute_force_default_threshold_is_five(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        assert re.get("cloud.signin_brute_force").effective_threshold == 5


class TestCloudKindsRouting:
    """_CLOUD_KINDS is defined and _ALL_HANDLED includes cloud kinds."""

    def test_cloud_kinds_set_exists(self):
        from cnsl.detector import _CLOUD_KINDS
        assert "CLOUD_SIGNIN_FAIL" in _CLOUD_KINDS
        assert "CLOUD_MFA_FAIL" in _CLOUD_KINDS
        assert "CLOUD_RISKY_SIGNIN" in _CLOUD_KINDS

    def test_all_handled_includes_cloud_kinds(self):
        from cnsl.detector import _ALL_HANDLED
        assert "CLOUD_SIGNIN_FAIL" in _ALL_HANDLED
        assert "CLOUD_RISKY_SIGNIN" in _ALL_HANDLED


class TestCloudEventDetection:
    """End-to-end: cloud events routed through Detector trigger correct alerts."""

    def _make_detector(self):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        cfg = {"thresholds": {}, "actions": {"dry_run": True},
               "logging": {"console_verbose": False}}
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)
        return Detector(cfg, logger, blocker)

    def _make_cloud_event(self, kind, ip="1.2.3.4",
                          user="alice@corp.com", provider="aws"):
        from cnsl.models import Event, now
        return Event(ts=now(), source=provider, kind=kind,
                     src_ip=ip, user=user, raw=f"cloud {kind}",
                     meta={"provider": provider})

    def test_cloud_signin_fail_increments_fails(self):
        det = self._make_detector()
        ip  = "5.5.5.5"
        _run(det.handle(self._make_cloud_event("CLOUD_SIGNIN_FAIL", ip=ip)))
        st = det._state[ip]
        assert st.total_fails == 1

    def test_cloud_risky_signin_fires_high_alert(self):
        det      = self._make_detector()
        ip       = "6.6.6.6"
        incidents_before = det._state[ip].total_incidents
        _run(det.handle(self._make_cloud_event("CLOUD_RISKY_SIGNIN", ip=ip)))
        assert det._state[ip].total_incidents > incidents_before

    def test_cloud_mfa_fail_fires_high_alert(self):
        det = self._make_detector()
        ip  = "7.7.7.7"
        _run(det.handle(self._make_cloud_event("CLOUD_MFA_FAIL", ip=ip)))
        assert det._state[ip].total_incidents > 0

    def test_cloud_signin_fail_brute_force_fires_after_threshold(self):
        det = self._make_detector()
        ip  = "8.8.8.8"
        # Default threshold is 5
        for _ in range(5):
            _run(det.handle(self._make_cloud_event("CLOUD_SIGNIN_FAIL", ip=ip)))
        assert det._state[ip].total_incidents > 0

    def test_cloud_signin_fail_below_threshold_no_alert(self):
        det = self._make_detector()
        ip  = "9.9.9.9"
        for _ in range(4):
            _run(det.handle(self._make_cloud_event("CLOUD_SIGNIN_FAIL", ip=ip)))
        assert det._state[ip].total_incidents == 0

# v2.7.0 -- zero-trust engine


class TestTrustSignals:
    """TrustSignal constants have correct (name, delta) shape."""

    def test_positive_signal_has_positive_delta(self):
        from cnsl.zero_trust import TrustSignal
        name, delta = TrustSignal.KNOWN_IP_LOGIN
        assert delta > 0
        assert isinstance(name, str)

    def test_negative_signal_has_negative_delta(self):
        from cnsl.zero_trust import TrustSignal
        name, delta = TrustSignal.UEBA_ANOMALY
        assert delta < 0

    def test_mfa_failure_signal_value(self):
        from cnsl.zero_trust import TrustSignal
        _, delta = TrustSignal.MFA_FAILURE
        assert delta == -0.25


class TestEntityTrust:
    """EntityTrust dataclass methods."""

    def test_initial_score_label_is_trusted(self):
        from cnsl.zero_trust import EntityTrust
        e = EntityTrust(entity_id="1.2.3.4", entity_type="ip")
        assert e.trust_label() == "trusted"

    def test_low_score_label_is_untrusted(self):
        from cnsl.zero_trust import EntityTrust
        e = EntityTrust(entity_id="1.2.3.4", entity_type="ip", score=0.1)
        assert e.trust_label() == "untrusted"

    def test_to_dict_includes_label_and_score(self):
        from cnsl.zero_trust import EntityTrust
        e = EntityTrust(entity_id="1.2.3.4", entity_type="ip", score=0.45)
        d = e.to_dict()
        assert d["label"] == "suspicious"
        assert d["score"] == 0.45

    def test_from_db_row_round_trip(self):
        from cnsl.zero_trust import EntityTrust
        row = {"entity_id": "a", "entity_type": "user",
               "score": 0.6, "last_updated": 0.0, "signal_count": 3, "last_signal": "x"}
        e = EntityTrust.from_db_row(row)
        assert e.entity_id == "a"
        assert e.score == 0.6


class TestZeroTrustEngineBasic:
    """ZeroTrustEngine apply_signal, get_score, and initial state."""

    def _make_zt(self, **kwargs):
        from cnsl.zero_trust import ZeroTrustEngine
        cfg = {"zero_trust": {"enabled": True, "initial_score": 0.8,
                              "min_score": 0.05, "recovery_per_day": 0.05,
                              "apply_to_threshold": True}}
        cfg["zero_trust"].update(kwargs)
        return ZeroTrustEngine(cfg)

    def test_unknown_entity_returns_initial_score(self):
        zt = self._make_zt()
        assert zt.get_score("brand-new", "ip") == 0.8

    def test_apply_negative_signal_decreases_score(self):
        from cnsl.zero_trust import TrustSignal
        zt = self._make_zt()
        _, delta = TrustSignal.UEBA_ANOMALY
        new = zt.apply_signal("1.2.3.4", "ip", TrustSignal.UEBA_ANOMALY)
        assert new == pytest.approx(0.8 + delta, abs=1e-9)

    def test_apply_positive_signal_increases_score(self):
        from cnsl.zero_trust import TrustSignal
        zt = self._make_zt()
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.UEBA_ANOMALY)
        before = zt.get_score("1.2.3.4", "ip")
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.KNOWN_IP_LOGIN)
        after = zt.get_score("1.2.3.4", "ip")
        assert after > before

    def test_score_never_below_min_score(self):
        from cnsl.zero_trust import TrustSignal
        zt = self._make_zt(min_score=0.1)
        for _ in range(50):
            zt.apply_signal("1.2.3.4", "ip", TrustSignal.BLOCK_APPLIED)
        assert zt.get_score("1.2.3.4", "ip") >= 0.1

    def test_score_never_above_one(self):
        from cnsl.zero_trust import TrustSignal
        zt = self._make_zt()
        for _ in range(50):
            zt.apply_signal("1.2.3.4", "ip", TrustSignal.KNOWN_IP_LOGIN)
        assert zt.get_score("1.2.3.4", "ip") <= 1.0

    def test_disabled_engine_returns_initial_score(self):
        from cnsl.zero_trust import TrustSignal, ZeroTrustEngine
        zt = ZeroTrustEngine({"zero_trust": {"enabled": False}})
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.BLOCK_APPLIED)
        assert zt.get_score("1.2.3.4", "ip") == zt.initial_score

    def test_ip_and_user_have_independent_scores(self):
        from cnsl.zero_trust import TrustSignal
        zt = self._make_zt()
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.BLOCK_APPLIED)
        ip_score   = zt.get_score("1.2.3.4", "ip")
        user_score = zt.get_score("1.2.3.4", "user")
        assert ip_score < user_score  # user not penalized, ip is


class TestZeroTrustThreshold:
    """effective_threshold scales correctly with trust score."""

    def _make_zt(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True,
                              "apply_to_threshold": True}})
        # Set ip to score ~0.5 by applying UEBA_ANOMALY x3
        zt.apply_signal("bad-ip", "ip", TrustSignal.UEBA_ANOMALY)
        zt.apply_signal("bad-ip", "ip", TrustSignal.UEBA_ANOMALY)
        zt.apply_signal("bad-ip", "ip", TrustSignal.UEBA_ANOMALY)
        return zt

    def test_trusted_ip_returns_normal_threshold(self):
        from cnsl.zero_trust import ZeroTrustEngine
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True,
                              "apply_to_threshold": True, "initial_score": 1.0}})
        assert zt.effective_threshold("new-ip", "ip", 8) == 8

    def test_low_trust_ip_returns_lower_threshold(self):
        zt = self._make_zt()
        eff = zt.effective_threshold("bad-ip", "ip", 8)
        assert eff < 8

    def test_threshold_never_zero(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True,
                              "min_score": 0.05, "apply_to_threshold": True}})
        for _ in range(100):
            zt.apply_signal("bad-ip", "ip", TrustSignal.BLOCK_APPLIED)
        assert zt.effective_threshold("bad-ip", "ip", 1) >= 1

    def test_apply_to_threshold_false_returns_normal(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True,
                              "apply_to_threshold": False}})
        zt.apply_signal("bad-ip", "ip", TrustSignal.BLOCK_APPLIED)
        assert zt.effective_threshold("bad-ip", "ip", 8) == 8


class TestZeroTrustReset:
    """reset() restores entity to initial_score."""

    def test_reset_restores_initial_score(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True}})
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.BLOCK_APPLIED)
        assert zt.get_score("1.2.3.4", "ip") < 0.8
        zt.reset("1.2.3.4", "ip")
        assert zt.get_score("1.2.3.4", "ip") == zt.initial_score

    def test_reset_unknown_entity_returns_false(self):
        from cnsl.zero_trust import ZeroTrustEngine
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True}})
        assert zt.reset("unknown", "ip") is False


class TestZeroTrustStats:
    """stats() reports correct counts per label."""

    def test_stats_reports_trusted_count(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True}})
        # Three IPs: two trusted, one degraded (brute_force_fail x3 = 0.8 - 0.15 = 0.65 = moderate)
        zt.apply_signal("1.1.1.1", "ip", TrustSignal.KNOWN_IP_LOGIN)
        zt.apply_signal("2.2.2.2", "ip", TrustSignal.KNOWN_IP_LOGIN)
        for _ in range(3):
            zt.apply_signal("3.3.3.3", "ip", TrustSignal.BRUTE_FORCE_FAIL)
        stats = zt.stats()
        assert stats["total_entities"] == 3
        # 1.1.1.1 and 2.2.2.2 each had KNOWN_IP_LOGIN (+0.05) so score=0.85 -> trusted
        assert stats["trusted"] >= 2
        # 3.3.3.3 had 3x brute_force_fail (-0.05 each) -> 0.65 -> moderate
        assert stats["moderate"] >= 1

    def test_stats_empty_engine(self):
        from cnsl.zero_trust import ZeroTrustEngine
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True}})
        stats = zt.stats()
        assert stats["total_entities"] == 0


class TestZeroTrustMaxEntities:
    """max_entities cap evicts oldest on overflow."""

    def test_max_entities_evicts_oldest(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True, "max_entities": 2}})
        zt.apply_signal("1.1.1.1", "ip", TrustSignal.BRUTE_FORCE_FAIL)
        zt.apply_signal("2.2.2.2", "ip", TrustSignal.BRUTE_FORCE_FAIL)
        zt.apply_signal("3.3.3.3", "ip", TrustSignal.BRUTE_FORCE_FAIL)
        assert len(zt._scores) == 2
        assert ("1.1.1.1", "ip") not in zt._scores


class TestDetectorZeroTrustWiring:
    """Detector stores zero_trust and calls _zt_threshold correctly."""

    def _make_detector(self, zero_trust=None):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        cfg     = {"thresholds": {}, "actions": {"dry_run": True},
                  "logging": {"console_verbose": False}}
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)
        return Detector(cfg, logger, blocker, zero_trust=zero_trust)

    def test_detector_stores_zero_trust(self):
        from cnsl.zero_trust import ZeroTrustEngine
        zt  = ZeroTrustEngine({"zero_trust": {"enabled": True}})
        det = self._make_detector(zero_trust=zt)
        assert det.zero_trust is zt

    def test_zt_threshold_without_zero_trust_returns_normal(self):
        det = self._make_detector(zero_trust=None)
        assert det._zt_threshold("1.2.3.4", "ip", 8) == 8

    def test_zt_threshold_with_low_trust_returns_lower(self):
        from cnsl.zero_trust import ZeroTrustEngine, TrustSignal
        zt = ZeroTrustEngine({"zero_trust": {"enabled": True,
                              "apply_to_threshold": True}})
        for _ in range(5):
            zt.apply_signal("1.2.3.4", "ip", TrustSignal.UEBA_ANOMALY)
        det = self._make_detector(zero_trust=zt)
        assert det._zt_threshold("1.2.3.4", "ip", 8) < 8

    def test_zt_threshold_exception_returns_normal(self):
        class _Bad:
            def effective_threshold(self, *a, **k):
                raise RuntimeError("boom")
        det = self._make_detector(zero_trust=_Bad())
        assert det._zt_threshold("1.2.3.4", "ip", 8) == 8

# v2.8.0 -- attack behavior graph


class TestGraphTabPresence:
    """Graph tab button and page exist in the dashboard HTML."""

    def _get_html(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        # HTML is now in dashboard_html.py; routes remain in dashboard.py
        return (
            (root / "dashboard.py").read_text(encoding="utf-8") +
            (root / "dashboard_html.py").read_text(encoding="utf-8")
        )

    def test_graph_tab_button_present(self):
        html = self._get_html()
        assert "showTab('graph')" in html, "Graph tab button missing from nav"

    def test_graph_page_div_present(self):
        html = self._get_html()
        assert 'id="page-graph"' in html, "Graph page div missing"

    def test_graph_canvas_present(self):
        html = self._get_html()
        assert 'id="graph-canvas"' in html, "Graph canvas element missing"

    def test_load_graph_js_function_present(self):
        html = self._get_html()
        assert "async function loadGraph()" in html, "loadGraph() JS function missing"

    def test_render_graph_js_function_present(self):
        html = self._get_html()
        assert "function renderGraph()" in html, "renderGraph() JS function missing"

    def test_graph_tooltip_present(self):
        html = self._get_html()
        assert 'id="graph-tooltip"' in html, "Graph tooltip element missing"

    def test_graph_detail_panel_present(self):
        html = self._get_html()
        assert 'id="graph-detail"' in html, "Graph node detail panel missing"


class TestGraphAPIRoute:
    """GET /api/graph route registered in start_dashboard."""

    def test_graph_api_route_registered(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py").read_text(encoding="utf-8")
        assert '"/api/graph"' in src, "/api/graph route missing from dashboard.py"


class TestDashboardSignatureV4:
    """start_dashboard must still accept all module params including zero_trust."""

    def test_start_dashboard_has_zero_trust(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "zero_trust" in sig.parameters
        assert sig.parameters["zero_trust"].default is None

    def test_start_dashboard_has_cloud_identity(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "cloud_identity" in sig.parameters

# v2.9.0 -- ML tuning UI


class TestMLDetectorRecentAlerts:
    """_recent_alerts deque is populated and bounded."""

    def _make_detector(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": 1,
                      "contamination": 0.5, "anomaly_score_threshold": 0.0}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_recent_alerts_starts_empty(self):
        det = self._make_detector()
        assert len(det._recent_alerts) == 0

    def test_recent_alerts_list_returns_empty(self):
        det = self._make_detector()
        assert det.recent_alerts_list() == []

    def test_feature_stats_empty_when_no_alerts(self):
        det = self._make_detector()
        assert det.feature_stats() == {}


class TestMLDetectorUpdateParams:
    """update_params() applies valid changes and clamps values."""

    def _make_detector(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": 100,
                      "contamination": 0.05, "anomaly_score_threshold": -0.1,
                      "retrain_interval_sec": 3600}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_update_contamination(self):
        det = self._make_detector()
        result = det.update_params(contamination=0.1)
        assert det.contamination == 0.1
        assert result["updated"]["contamination"] == 0.1

    def test_update_threshold(self):
        det = self._make_detector()
        det.update_params(threshold=-0.2)
        assert det.threshold == -0.2

    def test_update_min_samples(self):
        det = self._make_detector()
        det.update_params(min_samples=200)
        assert det.min_samples == 200

    def test_update_retrain_interval(self):
        det = self._make_detector()
        det.update_params(retrain_interval_sec=7200)
        assert det.retrain_sec == 7200

    def test_contamination_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(contamination=-5.0)
        assert det.contamination == 0.001

    def test_contamination_clamped_to_max(self):
        det = self._make_detector()
        det.update_params(contamination=0.99)
        assert det.contamination == 0.5

    def test_min_samples_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(min_samples=0)
        assert det.min_samples == 10

    def test_retrain_sec_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(retrain_interval_sec=0)
        assert det.retrain_sec == 60

    def test_none_values_not_applied(self):
        det = self._make_detector()
        original = det.contamination
        det.update_params(contamination=None)
        assert det.contamination == original

    def test_status_reflects_updated_params(self):
        det = self._make_detector()
        det.update_params(contamination=0.15, threshold=-0.2)
        status = det.status()
        assert status["contamination"] == 0.15
        assert status["threshold"] == -0.2


class TestMLDetectorTriggerRetrain:
    """trigger_retrain() returns correct ok/fail status."""

    def _make_detector(self, min_samples=100):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": min_samples,
                      "contamination": 0.05, "anomaly_score_threshold": -0.1}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_trigger_retrain_disabled_returns_false(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        det = MLDetector({"ml": {"enabled": False}}, JsonLogger("/dev/null", verbose=False))
        result = _run(det.trigger_retrain())
        assert result["ok"] is False
        assert "enabled" in result["reason"]

    def test_trigger_retrain_insufficient_samples_returns_false(self):
        det = self._make_detector(min_samples=100)
        # No training data accumulated
        result = _run(det.trigger_retrain())
        assert result["ok"] is False
        assert "samples" in result["reason"].lower()


class TestMLStatusIncludesNewFields:
    """status() returns the new fields added for the tuning UI."""

    def test_status_has_contamination(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "contamination": 0.07}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        s   = det.status()
        assert "contamination" in s
        assert s["contamination"] == 0.07

    def test_status_has_threshold(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "anomaly_score_threshold": -0.15}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        assert det.status()["threshold"] == -0.15

    def test_status_has_recent_alert_count(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        det = MLDetector({"ml": {"enabled": True}}, JsonLogger("/dev/null", verbose=False))
        assert "recent_alert_count" in det.status()
        assert det.status()["recent_alert_count"] == 0

    def test_status_has_retrain_interval_sec(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "retrain_interval_sec": 7200}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        assert det.status()["retrain_interval_sec"] == 7200


class TestMLAPIRoutes:
    """New ML API routes present in dashboard source."""

    def _src(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        # Routes are in dashboard.py; JS functions moved with HTML to dashboard_html.py
        return (
            (root / "dashboard.py").read_text(encoding="utf-8") +
            (root / "dashboard_html.py").read_text(encoding="utf-8")
        )

    def test_params_patch_route(self):
        assert '"/api/ml/params"' in self._src()

    def test_retrain_post_route(self):
        assert '"/api/ml/retrain"' in self._src()

    def test_alerts_get_route(self):
        assert '"/api/ml/alerts"' in self._src()

    def test_feature_stats_route(self):
        assert '"/api/ml/feature-stats"' in self._src()

    def test_ml_save_params_js(self):
        assert "async function mlSaveParams()" in self._src()

    def test_ml_trigger_retrain_js(self):
        assert "async function mlTriggerRetrain()" in self._src()

# v3.0.0 -- OT/IoT protocol support


class TestOTParserModbus:
    """parse_modbus() correctly classifies Modbus function codes."""

    def test_fc3_read_from_unknown_ip_is_scan(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 3 holding registers")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_SCAN
        assert ev.src_ip == "1.2.3.4"

    def test_fc3_read_from_trusted_ip_is_none(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 3 holding registers",
                          trusted_ips={"1.2.3.4"})
        assert ev is None

    def test_fc6_write_always_flagged(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 6 single register write",
                          trusted_ips={"1.2.3.4"})
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE

    def test_fc16_write_multiple_registers(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus src: 5.6.7.8 function_code: 16")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE
        assert ev.meta["function_code"] == 16

    def test_fc1_read_coils_from_trusted_is_none(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus from: 10.0.0.1 fc=1 read coils",
                          trusted_ips={"10.0.0.1"})
        assert ev is None

    def test_exception_line_returns_exception_kind(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus exception code 2 from 1.2.3.4 gateway error")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_EXCEPTION

    def test_empty_line_returns_none(self):
        from cnsl.ot_parser import parse_modbus
        assert parse_modbus("") is None
        assert parse_modbus("   ") is None

    def test_unrelated_line_returns_none(self):
        from cnsl.ot_parser import parse_modbus
        assert parse_modbus("nginx 200 GET /index.html") is None

    def test_meta_includes_protocol(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus src: 1.2.3.4 fc: 3 read")
        assert ev is not None
        assert ev.meta["protocol"] == "modbus"

    def test_source_is_modbus(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 6 write")
        assert ev is not None
        assert ev.source == "modbus"


class TestOTParserDNP3:
    """parse_dnp3() correctly classifies DNP3 events."""

    def test_unsolicited_from_unknown_ip(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp3 unsolicited response from 10.0.0.5")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_UNSOLICITED
        assert ev.src_ip == "10.0.0.5"

    def test_unsolicited_from_trusted_ip_is_none(self):
        from cnsl.ot_parser import parse_dnp3
        ev = parse_dnp3("dnp3 unsolicited response from 10.0.0.5",
                        trusted_ips={"10.0.0.5"})
        assert ev is None

    def test_auth_fail_detected(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp3 authentication failed from 10.0.0.9 bad mac")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_AUTH_FAIL

    def test_invalid_hmac_detected(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp security fail invalid hmac from 192.168.1.5")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_AUTH_FAIL

    def test_unrelated_line_returns_none(self):
        from cnsl.ot_parser import parse_dnp3
        assert parse_dnp3("sshd failed password for root") is None

    def test_empty_line_returns_none(self):
        from cnsl.ot_parser import parse_dnp3
        assert parse_dnp3("") is None


class TestOTParserSCADA:
    """parse_scada() correctly classifies SCADA/HMI log events."""

    def test_unauthorized_from_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("unauthorized command from 192.168.50.99")
        assert ev is not None
        assert ev.kind == OTEventKind.UNAUTHORIZED_CMD

    def test_denied_from_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("access denied from ip 10.10.10.50 setpoint change")
        assert ev is not None
        assert ev.kind == OTEventKind.UNAUTHORIZED_CMD

    def test_alarm_with_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("alarm: high pressure trip from operator 192.168.1.10")
        assert ev is not None
        assert ev.kind == OTEventKind.SCADA_ALARM

    def test_alarm_without_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("CRITICAL: emergency shutdown ALARM triggered")
        assert ev is not None
        assert ev.kind == OTEventKind.SCADA_ALARM
        assert ev.src_ip is None

    def test_empty_returns_none(self):
        from cnsl.ot_parser import parse_scada
        assert parse_scada("") is None


class TestMakeOTParser:
    """make_ot_parser() factory returns correct parser per protocol."""

    def _cfg(self, trusted=None):
        return {"ot": {"enabled": True,
                       "trusted_ips": trusted or [],
                       "alert_on_any_write": True}}

    def test_modbus_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("modbus", self._cfg())
        assert p is not None
        assert callable(p)

    def test_dnp3_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("dnp3", self._cfg())
        assert p is not None

    def test_scada_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("scada", self._cfg())
        assert p is not None

    def test_unknown_protocol_returns_none(self):
        from cnsl.ot_parser import make_ot_parser
        assert make_ot_parser("profinet", self._cfg()) is None

    def test_trusted_ips_passed_to_parser(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("modbus", self._cfg(trusted=["1.2.3.4"]))
        # FC3 read from trusted IP should return None
        assert p("modbus client: 1.2.3.4 fc: 3") is None

    def test_write_still_flagged_for_trusted_ip(self):
        from cnsl.ot_parser import make_ot_parser, OTEventKind
        p = make_ot_parser("modbus", self._cfg(trusted=["1.2.3.4"]))
        ev = p("modbus client: 1.2.3.4 fc: 6 write register")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE


class TestOTKindsInDetector:
    """_OT_KINDS is defined and _ALL_HANDLED includes OT kinds."""

    def test_ot_kinds_set_exists(self):
        from cnsl.detector import _OT_KINDS
        assert "OT_MODBUS_SCAN"      in _OT_KINDS
        assert "OT_MODBUS_WRITE"     in _OT_KINDS
        assert "OT_DNP3_UNSOLICITED" in _OT_KINDS
        assert "OT_SCADA_ALARM"      in _OT_KINDS
        assert "OT_UNAUTHORIZED_CMD" in _OT_KINDS

    def test_all_handled_includes_ot(self):
        from cnsl.detector import _ALL_HANDLED
        assert "OT_MODBUS_WRITE" in _ALL_HANDLED
        assert "OT_SCADA_ALARM"  in _ALL_HANDLED


class TestOTRulesRegistered:
    """The 3 OT detection rules are in the RuleEngine."""

    def test_ot_rules_present(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        for rule_id in ("ot.modbus_write", "ot.modbus_scan", "ot.scada_alarm"):
            assert re.get(rule_id) is not None, f"Rule {rule_id!r} missing"

    def test_modbus_write_is_high_threshold_one(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        r = re.get("ot.modbus_write")
        assert r.effective_severity == "HIGH"
        assert r.effective_threshold == 1

    def test_modbus_scan_is_medium_threshold_five(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        r = re.get("ot.modbus_scan")
        assert r.effective_severity == "MEDIUM"
        assert r.effective_threshold == 5

    def test_scada_alarm_is_high_threshold_one(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        r = re.get("ot.scada_alarm")
        assert r.effective_severity == "HIGH"
        assert r.effective_threshold == 1


class TestOTEventDetection:
    """OT events routed through Detector trigger correct alerts."""

    def _make_detector(self):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        cfg = {"thresholds": {}, "actions": {"dry_run": True},
               "logging": {"console_verbose": False}}
        logger  = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                          ipset_name="test", block_duration_sec=10,
                          allowlist=set(), logger=logger)
        return Detector(cfg, logger, blocker)

    def _make_ot_event(self, kind, ip="192.168.100.99",
                       protocol="modbus", fc=None):
        from cnsl.models import Event, now
        meta = {"protocol": protocol}
        if fc is not None:
            meta["function_code"] = fc
        return Event(ts=now(), source=protocol, kind=kind,
                     src_ip=ip, user=None, raw=f"ot {kind}",
                     meta=meta)

    def test_modbus_write_fires_immediately(self):
        from cnsl.ot_parser import OTEventKind
        det = self._make_detector()
        ip  = "192.168.100.99"
        _run(det.handle(self._make_ot_event(
            OTEventKind.MODBUS_WRITE, ip=ip, fc=6)))
        assert det._state[ip].total_incidents > 0

    def test_modbus_scan_below_threshold_no_alert(self):
        from cnsl.ot_parser import OTEventKind
        det = self._make_detector()
        ip  = "192.168.100.88"
        for _ in range(4):  # threshold is 5
            _run(det.handle(self._make_ot_event(
                OTEventKind.MODBUS_SCAN, ip=ip)))
        assert det._state[ip].total_incidents == 0

    def test_modbus_scan_at_threshold_fires(self):
        from cnsl.ot_parser import OTEventKind
        det = self._make_detector()
        ip  = "192.168.100.77"
        for _ in range(5):
            _run(det.handle(self._make_ot_event(
                OTEventKind.MODBUS_SCAN, ip=ip)))
        assert det._state[ip].total_incidents > 0

    def test_scada_alarm_fires_immediately(self):
        from cnsl.ot_parser import OTEventKind
        det = self._make_detector()
        ip  = "192.168.100.66"
        _run(det.handle(self._make_ot_event(
            OTEventKind.SCADA_ALARM, ip=ip, protocol="scada")))
        assert det._state[ip].total_incidents > 0

    def test_unauthorized_cmd_fires_immediately(self):
        from cnsl.ot_parser import OTEventKind
        det = self._make_detector()
        ip  = "192.168.100.55"
        _run(det.handle(self._make_ot_event(
            OTEventKind.UNAUTHORIZED_CMD, ip=ip, protocol="scada")))
        assert det._state[ip].total_incidents > 0
# v3.1.0 -- Batch 1+2+3 fixes


class TestLegacyThresholdsApplied:
    """cfg["thresholds"]["fails_threshold"] now actually affects ssh.brute_force."""

    def test_fails_threshold_sets_ssh_brute_force(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"thresholds": {"fails_threshold": 3}})
        assert re.get("ssh.brute_force").effective_threshold == 3

    def test_fails_threshold_default_when_not_set(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({})
        assert re.get("ssh.brute_force").effective_threshold == 8

    def test_explicit_rule_override_takes_priority_over_legacy(self):
        """cfg["rules"] override beats cfg["thresholds"] fallback."""
        from cnsl.rules import RuleEngine
        re = RuleEngine({
            "thresholds": {"fails_threshold": 3},
            "rules": {"ssh.brute_force": {"threshold": 12}},
        })
        assert re.get("ssh.brute_force").effective_threshold == 12

    def test_web_threshold_maps_to_web_scan_flood(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"thresholds": {"web_threshold": 10}})
        assert re.get("web.scan_flood").effective_threshold == 10

    def test_db_threshold_maps_to_db_brute_force(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"thresholds": {"db_threshold": 4}})
        assert re.get("db.brute_force").effective_threshold == 4

    def test_invalid_threshold_value_ignored(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"thresholds": {"fails_threshold": "not-a-number"}})
        # Should fall back to default 8, not crash
        assert re.get("ssh.brute_force").effective_threshold == 8

    def test_none_threshold_value_ignored(self):
        from cnsl.rules import RuleEngine
        re = RuleEngine({"thresholds": {"fails_threshold": None}})
        assert re.get("ssh.brute_force").effective_threshold == 8


class TestNoDuplicateFunctions:
    """log_sources.py must have exactly one definition of each function."""

    def _src(self):
        from pathlib import Path
        return (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
                ).read_text(encoding="utf-8")

    def test_parse_mysql_defined_once(self):
        assert self._src().count("def parse_mysql(") == 1

    def test_parse_ufw_defined_once(self):
        assert self._src().count("def parse_ufw(") == 1

    def test_parse_syslog_defined_once(self):
        assert self._src().count("def parse_syslog(") == 1

    def test_tail_log_file_defined_once(self):
        assert self._src().count("async def tail_log_file(") == 1

    def test_get_log_tasks_defined_once(self):
        assert self._src().count("def get_log_tasks(") == 1


class TestSQLiteWALMode:
    """store.py schema must include WAL and synchronous=NORMAL pragmas."""

    def _schema(self):
        from cnsl.store import _SCHEMA
        return _SCHEMA

    def test_wal_mode_pragma_present(self):
        assert "journal_mode=WAL" in self._schema()

    def test_synchronous_normal_pragma_present(self):
        assert "synchronous=NORMAL" in self._schema()

    def test_severity_index_present(self):
        assert "idx_incidents_sev" in self._schema()

    def test_ip_index_present(self):
        assert "idx_incidents_ip" in self._schema()

    def test_ts_index_present(self):
        assert "idx_incidents_ts" in self._schema()


class TestRequestSizeLimit:
    """dashboard.py must set client_max_size on the aiohttp Application."""

    def test_client_max_size_set(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py"
               ).read_text(encoding="utf-8")
        assert "client_max_size" in src, \
            "client_max_size missing from web.Application() -- no request size limit"


class TestDistributedRateLimiter:
    """RateLimiter accepts redis_sync param and exposes increment_distributed."""

    def test_accepts_redis_sync_param(self):
        from cnsl.rate_limiter import RateLimiter
        import inspect
        sig = inspect.signature(RateLimiter.__init__)
        assert "redis_sync" in sig.parameters

    def test_redis_sync_defaults_to_none(self):
        from cnsl.rate_limiter import RateLimiter
        import inspect
        sig = inspect.signature(RateLimiter.__init__)
        assert sig.parameters["redis_sync"].default is None

    def test_increment_distributed_method_exists(self):
        from cnsl.rate_limiter import RateLimiter
        assert hasattr(RateLimiter, "increment_distributed")
        assert callable(RateLimiter.increment_distributed)

    def test_increment_distributed_returns_minus_one_without_redis(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": True}}, redis_sync=None)
        result = _run(rl.increment_distributed("1.2.3.4", 60))
        assert result == -1

    def test_no_redis_does_not_crash_check(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": True}}, redis_sync=None)
        allowed, retry = rl.check("1.2.3.4")
        assert isinstance(allowed, bool)


class TestTailLogFileRotation:
    """tail_log_file has inode-tracking fallback when tail binary unavailable."""

    def test_inode_tracking_present_in_source(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
               ).read_text(encoding="utf-8")
        assert "st_ino" in src, \
            "inode tracking missing from tail_log_file fallback"

    def test_shutil_which_check_present(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
               ).read_text(encoding="utf-8")
        assert "shutil.which" in src, \
            "shutil.which check missing -- no fallback detection"


class TestStartupParallelism:
    """engine.py uses asyncio.gather for kill_chain + pattern_learner load."""

    def test_gather_used_for_parallel_load(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "asyncio.gather(" in src, \
            "asyncio.gather missing from engine.py startup -- loads are sequential"
        assert "kill_chain_tracker.load_all" in src
        assert "pattern_learner.load_all" in src


class TestSIGHUPHotReload:
    """engine.py registers SIGHUP handler for config hot-reload."""

    def test_sighup_handler_registered(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "SIGHUP" in src, \
            "SIGHUP handler missing from engine.py -- no config hot-reload"
        assert "_handle_sighup" in src
        assert "_apply_config" in src

# v3.2.0 -- Batch 4: dashboard split + PostgreSQL backend


class TestDashboardSplit:
    """dashboard_html.py must exist and contain _LOGIN_HTML and _HTML."""

    def test_dashboard_html_module_exists(self):
        from pathlib import Path
        assert (Path(__file__).parent.parent / "cnsl" / "dashboard_html.py").exists(), \
            "cnsl/dashboard_html.py missing -- HTML not split from dashboard.py"

    def test_login_html_in_html_module(self):
        from cnsl.dashboard_html import _LOGIN_HTML
        assert "<!DOCTYPE html>" in _LOGIN_HTML
        assert "login" in _LOGIN_HTML.lower()

    def test_main_html_in_html_module(self):
        from cnsl.dashboard_html import _HTML
        assert "<!DOCTYPE html>" in _HTML
        assert len(_HTML) > 10000  # must be the full template

    def test_dashboard_imports_from_html_module(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py"
               ).read_text(encoding="utf-8")
        assert "from .dashboard_html import" in src, \
            "dashboard.py does not import from dashboard_html.py"

    def test_dashboard_py_under_2000_lines(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000, \
            f"dashboard.py has {lines} lines -- split did not reduce size enough"

    def test_html_module_has_no_route_handlers(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard_html.py"
               ).read_text(encoding="utf-8")
        assert "@router." not in src, \
            "dashboard_html.py contains route handlers -- should only have HTML"


class TestStoreBackendConfig:
    """Store accepts full cfg dict and reads backend + db_path from it."""

    def test_store_accepts_cfg_dict(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "sqlite", "db_path": ":memory:"}})
        assert s._backend == "sqlite"
        assert s.db_path == ":memory:"

    def test_store_accepts_plain_path_string(self):
        from cnsl.store import Store
        s = Store(":memory:")
        assert s._backend == "sqlite"
        assert s.db_path == ":memory:"

    def test_store_postgresql_backend_detected(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "postgresql",
                             "dsn": "postgresql://user:pass@localhost/cnsl"}})
        assert s._backend == "postgresql"
        assert "postgresql" in s._pg_dsn

    def test_store_default_backend_is_sqlite(self):
        from cnsl.store import Store
        s = Store({})
        assert s._backend == "sqlite"

    def test_store_sqlite_init_works(self):
        from cnsl.store import Store
        s = Store(":memory:")
        result = _run(s.init())
        assert result is True
        assert s.available is True
        _run(s.close())

    def test_store_postgresql_graceful_fail_without_asyncpg(self):
        from cnsl.store import Store
        import sys
        # Temporarily hide asyncpg if installed
        asyncpg = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = None
        try:
            s = Store({"store": {"backend": "postgresql",
                                 "dsn": "postgresql://user:pass@localhost/cnsl"}})
            result = _run(s.init())
            # Should return False (asyncpg not available) without crashing
            assert result is False
        finally:
            if asyncpg is not None:
                sys.modules["asyncpg"] = asyncpg
            elif "asyncpg" in sys.modules:
                del sys.modules["asyncpg"]

    def test_store_close_both_backends_no_crash(self):
        from cnsl.store import Store
        s = Store(":memory:")
        _run(s.init())
        _run(s.close())  # must not raise

    def test_init_postgresql_requires_dsn(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "postgresql", "dsn": ""}})
        result = _run(s.init())
        assert result is False  # no DSN -> fail gracefully

# v3.3.0 -- comprehensive config validation


class TestValidationErrorClass:
    """ValidationError dataclass has correct fields."""

    def test_has_path_message_level(self):
        from cnsl.validator import ValidationError
        e = ValidationError(path="auth.secret_key", message="required")
        assert e.path == "auth.secret_key"
        assert e.message == "required"
        assert e.level == "error"

    def test_warning_level(self):
        from cnsl.validator import ValidationError
        w = ValidationError(path="redis.host", message="needed", level="warning")
        assert w.level == "warning"

    def test_str_includes_path_and_message(self):
        from cnsl.validator import ValidationError
        e = ValidationError(path="auth.secret_key", message="too short")
        assert "auth.secret_key" in str(e)
        assert "too short" in str(e)


class TestValidateConfigClean:
    """A clean minimal config produces no errors."""

    def test_empty_config_no_errors(self):
        from cnsl.validator import validate_config
        # Empty config should have no errors (everything optional)
        errs = [e for e in validate_config({}) if e.level == "error"]
        assert errs == []

    def test_valid_minimal_config_clean(self):
        from cnsl.validator import validate_config
        cfg = {
            "authlog_path": "/var/log/auth.log",
            "actions": {"dry_run": True, "block_duration_sec": 900},
            "allowlist": ["127.0.0.1"],
        }
        errs = [e for e in validate_config(cfg) if e.level == "error"]
        assert errs == []


class TestValidateConfigAuth:
    """auth.secret_key validation."""

    def test_missing_secret_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_short_secret_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True, "secret_key": "tooshort"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_insecure_default_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True, "secret_key": "cnsl-secret"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_valid_secret_key_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True,
                         "secret_key": "a" * 32}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" not in paths

    def test_auth_disabled_no_secret_required(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": False}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" not in paths


class TestValidateConfigAllowlist:
    """allowlist IP/CIDR validation."""

    def test_valid_ip_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": ["1.2.3.4", "10.0.0.0/8"]}
        errs = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("allowlist" in e.path for e in errs)

    def test_invalid_ip_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": ["not-an-ip"]}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("allowlist" in p for p in paths)

    def test_allowlist_not_list_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": "1.2.3.4"}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "allowlist" in paths


class TestValidateConfigNotifications:
    """notifications block validation."""

    def test_telegram_missing_token_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"telegram": {"enabled": True, "chat_id": "123"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "notifications.telegram.bot_token" in paths

    def test_telegram_missing_chat_id_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"telegram": {"enabled": True,
                                               "bot_token": "abc"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "notifications.telegram.chat_id" in paths

    def test_invalid_severity_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"min_severity": "CRITICAL"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("min_severity" in p for p in paths)

    def test_invalid_digest_hour_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {
            "daily_digest": {"enabled": True, "hour": 25}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("hour" in p for p in paths)


class TestValidateConfigStore:
    """store.backend validation."""

    def test_invalid_backend_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "mongodb"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("backend" in p for p in paths)

    def test_postgresql_without_dsn_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "postgresql", "dsn": ""}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "store.dsn" in paths

    def test_postgresql_with_valid_dsn_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "postgresql",
                          "dsn": "postgresql://user:pass@localhost/cnsl"}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("store.dsn" in e.path for e in errors)

    def test_sqlite_backend_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "sqlite", "db_path": "/tmp/test.db"}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("store" in e.path for e in errors)


class TestValidateConfigML:
    """ml block validation."""

    def test_invalid_contamination_too_high(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.9}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "ml.contamination" in paths

    def test_invalid_contamination_zero(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.0}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "ml.contamination" in paths

    def test_valid_contamination_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.05}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("contamination" in e.path for e in errors)


class TestValidateConfigSIEM:
    """siem connectors block validation."""

    def test_splunk_missing_url_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"splunk": {"enabled": True, "token": "abc"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.splunk.hec_url" in paths

    def test_splunk_missing_token_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"splunk": {"enabled": True,
                                    "hec_url": "https://splunk.example.com"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.splunk.token" in paths

    def test_webhook_missing_url_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"webhook": {"enabled": True}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.webhook.url" in paths


class TestValidateConfigCloudIdentity:
    """cloud_identity block validation."""

    def test_aws_missing_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"cloud_identity": {"enabled": True,
                                   "aws": {"enabled": True,
                                           "secret_access_key": "secret"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "cloud_identity.aws.access_key_id" in paths

    def test_azure_missing_tenant_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"cloud_identity": {"enabled": True,
                                   "azure_ad": {"enabled": True,
                                                "client_id": "abc",
                                                "client_secret": "xyz"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "cloud_identity.azure_ad.tenant_id" in paths


class TestValidateConfigOT:
    """OT/IoT config block validation."""

    def test_invalid_protocol_is_warning(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "log_sources": {"profinet": "/var/log/profinet.log"}}}
        warns = [e for e in validate_config(cfg) if e.level == "warning"]
        assert any("profinet" in e.path for e in warns)

    def test_invalid_trusted_ip_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "trusted_ips": ["not-an-ip"]}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("trusted_ips" in p for p in paths)

    def test_valid_ot_config_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "log_sources": {"modbus": "/var/log/modbus.log"},
                       "trusted_ips": ["192.168.100.10"]}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("ot" in e.path for e in errors)


class TestValidateConfigRules:
    """rules block override validation."""

    def test_invalid_severity_in_rule_override(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"severity": "CRITICAL"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("severity" in p for p in paths)

    def test_invalid_threshold_in_rule_override(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"threshold": -1}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("threshold" in p for p in paths)

    def test_valid_rule_override_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"threshold": 5, "severity": "HIGH"}}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("ssh.brute_force" in e.path for e in errors)


class TestValidateConfigDashboard:
    """dashboard host/port validation."""

    def test_invalid_port_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"port": 80}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "dashboard.port" in paths

    def test_open_host_is_warning(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"host": "0.0.0.0", "port": 8765}}
        warns = [e for e in validate_config(cfg) if e.level == "warning"]
        assert any("dashboard.host" in e.path for e in warns)

    def test_valid_port_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"port": 8765}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("dashboard.port" in e.path for e in errors)


class TestValidateAndPrint:
    """validate_and_print returns True on valid config, False on invalid."""

    def test_returns_true_on_clean_config(self):
        from cnsl.validator import validate_and_print
        result = validate_and_print({})
        assert result is True

    def test_returns_false_on_invalid_config(self):
        from cnsl.validator import validate_and_print
        result = validate_and_print({"auth": {"enabled": True,
                                               "secret_key": "short"}})
        assert result is False


class TestCLIValidateConfigFlag:
    """--validate-config flag is registered in engine.py."""

    def test_flag_present_in_engine(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "--validate-config" in src
        assert "validate_and_print" in src