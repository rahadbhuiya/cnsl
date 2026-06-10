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