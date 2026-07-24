"""
tests/test_correlation.py -- tests for correlation rule tuning
(cnsl/correlator.py's Correlator management API) and its dashboard
wiring (cnsl/dashboard_correlation.py).
"""

from __future__ import annotations

import pytest

from cnsl.correlator import Correlator, CorrelationRule, IPEventBuffer
from cnsl.models import Event, EventKind, now


ALL_RULE_NAMES = {
    "multi_service_brute_force", "web_recon_then_ssh", "honeypot_then_ssh",
    "web_auth_flood", "privilege_escalation", "persistent_recon",
}


class TestCorrelatorRuleListing:
    def test_all_rules_returns_all_six_builtin_rules(self):
        c = Correlator()
        names = {r["name"] for r in c.all_rules()}
        assert names == ALL_RULE_NAMES

    def test_all_rules_sorted_by_name(self):
        c = Correlator()
        names = [r["name"] for r in c.all_rules()]
        assert names == sorted(names)

    def test_get_rule_returns_none_for_unknown(self):
        c = Correlator()
        assert c.get_rule("does_not_exist") is None

    def test_get_rule_returns_rule_object(self):
        c = Correlator()
        rule = c.get_rule("web_auth_flood")
        assert isinstance(rule, CorrelationRule)
        assert rule.name == "web_auth_flood"

    def test_rule_to_dict_reports_effective_and_default_fields(self):
        c = Correlator()
        d = c.get_rule("honeypot_then_ssh").to_dict()
        assert d["default_window_sec"] == d["effective_window_sec"] == 180
        assert d["default_confidence"] == d["effective_confidence"] == 0.9
        assert d["enabled"] is True
        assert d["overridden"] is False


class TestCorrelatorEnableDisable:
    def test_disable_then_enable_round_trip(self):
        c = Correlator()
        assert c.disable("web_auth_flood") is None
        assert c.get_rule("web_auth_flood").enabled is False
        assert c.enable("web_auth_flood") is None
        assert c.get_rule("web_auth_flood").enabled is True

    def test_disable_unknown_rule_returns_error(self):
        c = Correlator()
        err = c.disable("nonexistent")
        assert err is not None
        assert "nonexistent" in err

    def test_enable_unknown_rule_returns_error(self):
        c = Correlator()
        err = c.enable("nonexistent")
        assert err is not None

    def test_disabled_rule_is_skipped_during_ingest(self):
        c = Correlator()
        c.disable("honeypot_then_ssh")
        ev1 = Event(ts=now(), source="fw", kind="FW_HONEYPOT_PORT", src_ip="1.2.3.4", raw="x")
        ev2 = Event(ts=now(), source="auth", kind="SSH_FAIL", src_ip="1.2.3.4", raw="x")
        assert c.ingest(ev1) is None
        assert c.ingest(ev2) is None  # would normally fire honeypot_then_ssh

    def test_enabled_rule_still_fires(self):
        c = Correlator()
        ev1 = Event(ts=now(), source="fw", kind="FW_HONEYPOT_PORT", src_ip="5.6.7.8", raw="x")
        ev2 = Event(ts=now(), source="auth", kind="SSH_FAIL", src_ip="5.6.7.8", raw="x")
        c.ingest(ev1)
        alert = c.ingest(ev2)
        assert alert is not None
        assert alert.rule_name == "honeypot_then_ssh"


class TestCorrelatorUpdate:
    def test_update_window_sec(self):
        c = Correlator()
        err = c.update("persistent_recon", window_sec=900)
        assert err is None
        rule = c.get_rule("persistent_recon")
        assert rule.effective_window_sec == 900
        assert rule.window_sec == 1800  # default unchanged
        assert rule.to_dict()["overridden"] is True

    def test_update_cooldown_sec(self):
        c = Correlator()
        err = c.update("web_auth_flood", cooldown_sec=30)
        assert err is None
        assert c.get_rule("web_auth_flood").effective_cooldown_sec == 30

    def test_update_confidence(self):
        c = Correlator()
        err = c.update("web_auth_flood", confidence=0.99)
        assert err is None
        assert c.get_rule("web_auth_flood").effective_confidence == 0.99

    def test_update_enabled_flag(self):
        c = Correlator()
        err = c.update("web_auth_flood", enabled=False)
        assert err is None
        assert c.get_rule("web_auth_flood").enabled is False

    def test_update_multiple_fields_at_once(self):
        c = Correlator()
        err = c.update("web_auth_flood", enabled=False, window_sec=60, confidence=0.5)
        assert err is None
        rule = c.get_rule("web_auth_flood")
        assert rule.enabled is False
        assert rule.effective_window_sec == 60
        assert rule.effective_confidence == 0.5

    def test_update_unknown_rule_returns_error(self):
        c = Correlator()
        err = c.update("nonexistent", enabled=True)
        assert err is not None

    def test_update_rejects_negative_window_sec(self):
        c = Correlator()
        err = c.update("web_auth_flood", window_sec=-5)
        assert err is not None
        assert c.get_rule("web_auth_flood").effective_window_sec != -5

    def test_update_rejects_zero_window_sec(self):
        c = Correlator()
        err = c.update("web_auth_flood", window_sec=0)
        assert err is not None

    def test_update_rejects_negative_cooldown_sec(self):
        c = Correlator()
        err = c.update("web_auth_flood", cooldown_sec=-1)
        assert err is not None

    def test_update_rejects_confidence_above_one(self):
        c = Correlator()
        err = c.update("web_auth_flood", confidence=1.5)
        assert err is not None

    def test_update_rejects_confidence_below_zero(self):
        c = Correlator()
        err = c.update("web_auth_flood", confidence=-0.1)
        assert err is not None

    def test_update_accepts_confidence_boundaries(self):
        c = Correlator()
        assert c.update("web_auth_flood", confidence=0.0) is None
        assert c.update("web_auth_flood", confidence=1.0) is None

    def test_update_with_no_args_is_a_noop_success(self):
        c = Correlator()
        err = c.update("web_auth_flood")
        assert err is None
        assert c.get_rule("web_auth_flood").to_dict()["overridden"] is False


class TestCorrelatorReset:
    def test_reset_clears_overrides(self):
        c = Correlator()
        c.update("web_auth_flood", enabled=False, window_sec=999, confidence=0.99)
        err = c.reset("web_auth_flood")
        assert err is None
        rule = c.get_rule("web_auth_flood")
        assert rule.enabled is True
        assert rule.effective_window_sec == rule.window_sec == 120
        assert rule.effective_confidence == rule.confidence == 0.75
        assert rule.to_dict()["overridden"] is False

    def test_reset_unknown_rule_returns_error(self):
        c = Correlator()
        err = c.reset("nonexistent")
        assert err is not None


class TestCorrelatorConfigDriven:
    def test_config_disables_rule_at_init(self):
        cfg = {"correlation_rules": {"web_auth_flood": {"enabled": False}}}
        c = Correlator(cfg=cfg)
        assert c.get_rule("web_auth_flood").enabled is False

    def test_config_tunes_window_and_confidence_at_init(self):
        cfg = {"correlation_rules": {
            "persistent_recon": {"window_sec": 900, "confidence": 0.6}
        }}
        c = Correlator(cfg=cfg)
        rule = c.get_rule("persistent_recon")
        assert rule.effective_window_sec == 900
        assert rule.effective_confidence == 0.6

    def test_config_unknown_rule_name_ignored_without_crash(self):
        cfg = {"correlation_rules": {"not_a_real_rule": {"enabled": False}}}
        c = Correlator(cfg=cfg)  # must not raise
        assert c.get_rule("not_a_real_rule") is None

    def test_empty_config_leaves_defaults(self):
        c = Correlator(cfg={})
        assert c.get_rule("web_auth_flood").enabled is True

    def test_no_config_leaves_defaults(self):
        c = Correlator()
        assert c.get_rule("web_auth_flood").enabled is True


class TestCorrelatorInstanceIsolation:
    """Overrides on one Correlator instance must never leak into another --
    this was a real bug risk since rule *classes* are shared across
    instances unless each Correlator gets fresh rule objects."""

    def test_two_correlators_have_independent_overrides(self):
        c1 = Correlator()
        c2 = Correlator()
        c1.update("web_auth_flood", window_sec=999)
        assert c2.get_rule("web_auth_flood").effective_window_sec == 120  # untouched

    def test_two_correlators_have_independent_enabled_state(self):
        c1 = Correlator()
        c2 = Correlator()
        c1.disable("web_auth_flood")
        assert c2.get_rule("web_auth_flood").enabled is True


class TestDashboardCorrelationWiring:
    """start_dashboard() signature + route registration wiring."""

    def test_start_dashboard_accepts_correlator_param(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "correlator" in sig.parameters
        assert sig.parameters["correlator"].default is None

    def test_register_correlation_routes_importable(self):
        from cnsl.dashboard_correlation import register_correlation_routes
        assert callable(register_correlation_routes)

    def test_dashboard_py_stays_under_line_budget(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000