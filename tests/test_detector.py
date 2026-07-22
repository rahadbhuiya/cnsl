"""
tests/test_detector.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_detector.py -v
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

from helpers import make_cfg, make_detector, _run, _det, _make_cm, _SKLEARN_AVAILABLE


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
