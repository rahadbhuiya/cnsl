"""
tests/test_ueba_zerotrust.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_ueba_zerotrust.py -v
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
