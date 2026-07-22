"""
tests/test_threat_feed.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_threat_feed.py -v
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
