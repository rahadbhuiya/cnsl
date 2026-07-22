"""
tests/test_reporting.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_reporting.py -v
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
