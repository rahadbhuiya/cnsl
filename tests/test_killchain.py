"""
tests/test_killchain.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_killchain.py -v
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
