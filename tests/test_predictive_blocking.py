"""
tests/test_predictive_blocking.py -- tests for kill-chain-trajectory-
based blocking (cnsl/predictive_blocking.py) and its wiring into
cnsl/detector.py's _kc_update.
"""

from __future__ import annotations

import asyncio

import pytest

from cnsl.predictive_blocking import should_predictively_block
from cnsl.kill_chain import KillChain, KCStage


def _run(coro):
    return asyncio.run(coro)


def _make_chain(stages: dict, score: float) -> KillChain:
    """Build a KillChain with specific stages/score for testing the
    pure decision function without going through the full tracker."""
    chain = KillChain(ip="1.2.3.4")
    chain.stages = stages
    chain.score = score
    return chain


class TestShouldPredictivelyBlock:
    def test_disabled_by_default_returns_none(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.9)
        assert should_predictively_block(chain, {}) is None

    def test_disabled_explicitly_returns_none(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.9)
        cfg = {"predictive_blocking": {"enabled": False}}
        assert should_predictively_block(chain, cfg) is None

    def test_none_chain_returns_none(self):
        cfg = {"predictive_blocking": {"enabled": True}}
        assert should_predictively_block(None, cfg) is None

    def test_enabled_score_above_threshold_and_enough_stages_fires(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.7)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.6, "min_stages": 2}}
        reason = should_predictively_block(chain, cfg)
        assert reason is not None
        assert "predictive:" in reason

    def test_score_below_threshold_does_not_fire(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.5)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.6, "min_stages": 2}}
        assert should_predictively_block(chain, cfg) is None

    def test_score_exactly_at_threshold_fires(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.6)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.6, "min_stages": 2}}
        assert should_predictively_block(chain, cfg) is not None

    def test_too_few_stages_does_not_fire_even_with_high_score(self):
        """A single very-late-stage event can spike score without a real
        multi-step pattern -- min_stages guards against that."""
        chain = _make_chain({5: object()}, score=0.9)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.5, "min_stages": 2}}
        assert should_predictively_block(chain, cfg) is None

    def test_min_stages_one_allows_single_stage(self):
        chain = _make_chain({5: object()}, score=0.9)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.5, "min_stages": 1}}
        assert should_predictively_block(chain, cfg) is not None

    def test_reason_includes_score_and_stage_names(self):
        chain = _make_chain({KCStage.RECONNAISSANCE: object(), KCStage.DELIVERY: object()}, score=0.65)
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.6, "min_stages": 2}}
        reason = should_predictively_block(chain, cfg)
        assert "0.65" in reason
        assert "2 stages" in reason

    def test_defaults_used_when_predictive_blocking_key_absent(self):
        chain = _make_chain({1: object(), 2: object()}, score=0.9)
        assert should_predictively_block(chain, {}) is None  # default is disabled

    def test_partial_config_overrides_merge_with_defaults(self):
        """Only overriding score_threshold should still respect the
        default min_stages=2."""
        chain = _make_chain({1: object()}, score=0.9)  # only 1 stage
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.1}}
        assert should_predictively_block(chain, cfg) is None  # min_stages default=2 not met


class TestDetectorPredictiveBlockingWiring:
    def _make_detector(self, pb_cfg=None):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        from cnsl.kill_chain import KillChainTracker
        from cnsl.detector import Detector

        cfg = {"kill_chain": {"enabled": True}}
        if pb_cfg is not None:
            cfg["predictive_blocking"] = pb_cfg
        logger = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                           ipset_name="test", block_duration_sec=900,
                           allowlist=set(), logger=logger)
        kc = KillChainTracker(cfg)
        det = Detector(cfg, logger, blocker, kill_chain=kc)
        return det, blocker, kc

    def test_predictive_block_fires_across_two_distinct_event_kinds(self):
        """The core scenario this feature exists for: an attacker spread
        across two different attack types, neither of which alone hits
        its own rule's threshold."""
        det, blocker, kc = self._make_detector(
            pb_cfg={"enabled": True, "score_threshold": 0.3, "min_stages": 2})

        _run(det._kc_update("45.33.32.1", "WEB_SCAN", severity="LOW"))
        assert blocker.is_blocked("45.33.32.1") is False  # only 1 stage so far

        _run(det._kc_update("45.33.32.1", "SSH_FAIL", severity="MEDIUM"))
        assert blocker.is_blocked("45.33.32.1") is True  # 2nd stage crosses threshold

    def test_disabled_by_default_never_blocks(self):
        det, blocker, kc = self._make_detector(pb_cfg=None)  # no predictive_blocking key at all
        _run(det._kc_update("45.33.32.1", "WEB_SCAN", severity="LOW"))
        _run(det._kc_update("45.33.32.1", "SSH_FAIL", severity="MEDIUM"))
        _run(det._kc_update("45.33.32.1", "SSH_SUCCESS", severity="HIGH"))
        assert blocker.is_blocked("45.33.32.1") is False

    def test_explicitly_disabled_never_blocks(self):
        det, blocker, kc = self._make_detector(pb_cfg={"enabled": False})
        _run(det._kc_update("45.33.32.1", "WEB_SCAN", severity="LOW"))
        _run(det._kc_update("45.33.32.1", "SSH_FAIL", severity="MEDIUM"))
        assert blocker.is_blocked("45.33.32.1") is False

    def test_kill_chain_absent_does_not_crash(self):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        from cnsl.detector import Detector
        cfg = {"predictive_blocking": {"enabled": True}}
        logger = JsonLogger("/dev/null", verbose=False)
        blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                           ipset_name="test", block_duration_sec=900,
                           allowlist=set(), logger=logger)
        det = Detector(cfg, logger, blocker, kill_chain=None)
        _run(det._kc_update("1.2.3.4", "SSH_FAIL"))  # must not raise

    def test_does_not_double_block_already_blocked_ip(self):
        """Blocker.block_ip() is already idempotent -- calling it again
        for an IP that's already blocked must not raise or re-schedule."""
        det, blocker, kc = self._make_detector(
            pb_cfg={"enabled": True, "score_threshold": 0.3, "min_stages": 2})
        _run(det._kc_update("45.33.32.1", "WEB_SCAN", severity="LOW"))
        _run(det._kc_update("45.33.32.1", "SSH_FAIL", severity="MEDIUM"))
        assert blocker.is_blocked("45.33.32.1") is True
        # Further events for the same IP must not raise even though
        # it's already blocked.
        _run(det._kc_update("45.33.32.1", "SSH_SUCCESS", severity="HIGH"))
        assert blocker.is_blocked("45.33.32.1") is True

    def test_unrelated_ip_not_affected(self):
        det, blocker, kc = self._make_detector(
            pb_cfg={"enabled": True, "score_threshold": 0.3, "min_stages": 2})
        _run(det._kc_update("45.33.32.1", "WEB_SCAN", severity="LOW"))
        _run(det._kc_update("45.33.32.1", "SSH_FAIL", severity="MEDIUM"))
        assert blocker.is_blocked("9.9.9.9") is False


class TestPredictiveBlockingConfigValidation:
    def test_valid_config_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"enabled": True, "score_threshold": 0.6, "min_stages": 2}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("predictive_blocking" in e.path for e in errors)

    def test_non_bool_enabled_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"enabled": "yes"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("predictive_blocking.enabled" in p for p in paths)

    def test_threshold_out_of_range_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"score_threshold": 1.5}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("predictive_blocking.score_threshold" in p for p in paths)

    def test_negative_threshold_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"score_threshold": -0.1}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("predictive_blocking.score_threshold" in p for p in paths)

    def test_zero_min_stages_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"min_stages": 0}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("predictive_blocking.min_stages" in p for p in paths)

    def test_min_stages_one_while_enabled_is_warning(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"enabled": True, "min_stages": 1}}
        issues = validate_config(cfg)
        errors = [e for e in issues if e.level == "error"]
        warnings = [e for e in issues if e.level == "warning"]
        assert not any("predictive_blocking.min_stages" in e.path for e in errors)
        assert any("predictive_blocking.min_stages" in e.path for e in warnings)

    def test_min_stages_one_while_disabled_no_warning(self):
        from cnsl.validator import validate_config
        cfg = {"predictive_blocking": {"enabled": False, "min_stages": 1}}
        warnings = [e.path for e in validate_config(cfg) if e.level == "warning"]
        assert not any("predictive_blocking.min_stages" in p for p in warnings)

    def test_empty_block_no_error(self):
        from cnsl.validator import validate_config
        errors = [e for e in validate_config({"predictive_blocking": {}}) if e.level == "error"]
        assert not any("predictive_blocking" in e.path for e in errors)


class TestDefaultConfigPredictiveBlocking:
    def test_default_config_has_predictive_blocking_disabled(self):
        from cnsl.config import DEFAULT_CONFIG
        assert "predictive_blocking" in DEFAULT_CONFIG
        assert DEFAULT_CONFIG["predictive_blocking"]["enabled"] is False