"""
cnsl/threat_feed.py — Community Threat Feed.

Downloads and maintains a local blocklist of known-bad IPs from multiple
public threat intelligence feeds. IPs matching the feed are flagged or
blocked immediately — before detection thresholds are reached.

Built-in public feeds (all free, no API key required):

  Feed                  URL (fetched by ThreatFeed)          Format
  ────────────────────  ───────────────────────────────────  ──────
  Emerging Threats      rules.emergingthreats.net            plain
  Feodo Tracker         feodotracker.abuse.ch                plain
  CINS Army             cinsscore.com                        plain
  abuse.ch SSLBL        sslbl.abuse.ch                       plain
  Spamhaus DROP         spamhaus.org/drop                    CIDR
  Spamhaus EDROP        spamhaus.org/drop                    CIDR

Custom local feed:
  Set "threat_feed.local_file" to a path containing one IP or CIDR per line.

Config (config.json):
  "threat_feed": {
    "enabled":          true,
    "auto_block":       true,         -- block immediately on hit (default: flag only)
    "severity":         "HIGH",
    "refresh_interval_sec": 3600,     -- how often to re-download feeds
    "feeds": {
      "emerging_threats": true,
      "feodo_tracker":    true,
      "cins_army":        true,
      "abuse_ch_sslbl":   true,
      "spamhaus_drop":    false,
      "spamhaus_edrop":   false
    },
    "local_file":       null          -- path to a custom IP list
  }
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import iso_time, now


#  Feed source definitions 


@dataclass
class FeedSource:
    key:         str
    name:        str
    url:         str
    is_cidr:     bool = False   # True if feed contains CIDR blocks, not plain IPs
    comment_char: str = "#"


FEED_SOURCES: List[FeedSource] = [
    FeedSource(
        key  = "emerging_threats",
        name = "Emerging Threats Compromised IPs",
        url  = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    ),
    FeedSource(
        key  = "feodo_tracker",
        name = "Feodo Tracker Botnet C2",
        url  = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    ),
    FeedSource(
        key  = "cins_army",
        name = "CINS Army Score",
        url  = "https://cinsscore.com/list/ci-badguys.txt",
    ),
    FeedSource(
        key  = "abuse_ch_sslbl",
        name = "abuse.ch SSL Blacklist",
        url  = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    ),
    FeedSource(
        key     = "spamhaus_drop",
        name    = "Spamhaus DROP",
        url     = "https://www.spamhaus.org/drop/drop.txt",
        is_cidr = True,
    ),
    FeedSource(
        key     = "spamhaus_edrop",
        name    = "Spamhaus EDROP",
        url     = "https://www.spamhaus.org/drop/edrop.txt",
        is_cidr = True,
    ),
]

FEED_BY_KEY: Dict[str, FeedSource] = {f.key: f for f in FEED_SOURCES}


#  ThreatFeed 


@dataclass
class FeedStats:
    key:          str
    name:         str
    enabled:      bool
    ip_count:     int    = 0
    cidr_count:   int    = 0
    last_updated: Optional[str] = None
    last_error:   Optional[str] = None
    ok:           bool   = False


class ThreatFeed:
    """
    Downloads and caches known-bad IP lists from multiple public feeds.

    Usage:
        feed = ThreatFeed(cfg)
        await feed.start()           # background refresh loop
        hit = feed.check("1.2.3.4") # returns FeedHit or None
    """

    def __init__(self, cfg: Dict[str, Any]):
        tf = cfg.get("threat_feed", {})

        self.enabled              = bool(tf.get("enabled", False))
        self.auto_block           = bool(tf.get("auto_block", False))
        self.severity             = tf.get("severity", "HIGH").upper()
        self.refresh_interval     = int(tf.get("refresh_interval_sec", 3600))
        self.local_file           = tf.get("local_file")
        self.feeds_cfg: Dict[str, bool] = tf.get("feeds", {})

        # In-memory sets
        self._ips:   Set[str]                    = set()
        self._cidrs: List[ipaddress.IPv4Network] = []

        # Per-feed metadata
        self._stats: Dict[str, FeedStats] = {}
        for src in FEED_SOURCES:
            enabled = self.feeds_cfg.get(src.key, src.key in {
                "emerging_threats", "feodo_tracker", "cins_army", "abuse_ch_sslbl"
            })
            self._stats[src.key] = FeedStats(
                key=src.key, name=src.name, enabled=enabled
            )

        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None

    #  Public API 

    def check(self, ip: str) -> Optional[Dict[str, str]]:
        """
        Check if an IP is in any threat feed.
        Returns a dict with feed info, or None if clean.

        Fast path: O(1) set lookup for plain IPs.
        CIDR path: O(n) but only if plain lookup misses.
        """
        if not self.enabled or not ip:
            return None

        # Plain IP match
        if ip in self._ips:
            return {"ip": ip, "match_type": "exact", "source": "threat_feed"}

        # CIDR match (Spamhaus etc.)
        try:
            addr = ipaddress.ip_address(ip)
            for net in self._cidrs:
                if addr in net:
                    return {
                        "ip":         ip,
                        "match_type": "cidr",
                        "cidr":       str(net),
                        "source":     "threat_feed",
                    }
        except ValueError:
            pass

        return None

    @property
    def ip_count(self) -> int:
        return len(self._ips)

    @property
    def cidr_count(self) -> int:
        return len(self._cidrs)

    @property
    def last_refresh_time(self) -> Optional[str]:
        if not self._last_refresh:
            return None
        return iso_time(self._last_refresh)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled":        self.enabled,
            "auto_block":     self.auto_block,
            "severity":       self.severity,
            "total_ips":      self.ip_count,
            "total_cidrs":    self.cidr_count,
            "last_refresh":   self.last_refresh_time,
            "refresh_interval_sec": self.refresh_interval,
            "feeds": [
                {
                    "key":          s.key,
                    "name":         s.name,
                    "enabled":      s.enabled,
                    "ip_count":     s.ip_count,
                    "cidr_count":   s.cidr_count,
                    "last_updated": s.last_updated,
                    "last_error":   s.last_error,
                    "ok":           s.ok,
                }
                for s in self._stats.values()
            ],
        }

    #  Lifecycle 

    async def start(self) -> None:
        """Start the background refresh loop."""
        if not self.enabled:
            return
        # Initial load
        await self.refresh()
        # Background loop
        self._task = asyncio.create_task(self._refresh_loop(), name="threat_feed")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def refresh(self) -> Dict[str, Any]:
        """Download and merge all enabled feeds. Returns stats."""
        async with self._lock:
            return await self._do_refresh()

    #  Internal 

    async def _refresh_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.refresh_interval)
                await self._do_refresh()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _do_refresh(self) -> Dict[str, Any]:
        new_ips:   Set[str]                    = set()
        new_cidrs: List[ipaddress.IPv4Network] = []

        for src in FEED_SOURCES:
            stat = self._stats[src.key]
            if not stat.enabled:
                continue
            try:
                ips, cidrs = await _fetch_feed(src)
                new_ips.update(ips)
                new_cidrs.extend(cidrs)
                stat.ip_count   = len(ips)
                stat.cidr_count = len(cidrs)
                stat.last_updated = iso_time()
                stat.last_error   = None
                stat.ok           = True
            except Exception as exc:
                stat.last_error = str(exc)[:200]
                stat.ok         = False

        # Local file
        if self.local_file:
            try:
                local_ips, local_cidrs = _load_local_file(self.local_file)
                new_ips.update(local_ips)
                new_cidrs.extend(local_cidrs)
            except Exception:
                pass

        # Atomic swap
        self._ips   = new_ips
        self._cidrs = new_cidrs
        self._last_refresh = time.time()

        return self.get_stats()


#  Feed fetch helpers 


async def _fetch_feed(src: FeedSource) -> Tuple[Set[str], List[ipaddress.IPv4Network]]:
    """Download a feed and return (plain_ips, cidr_networks)."""
    try:
        import aiohttp
    except ImportError:
        raise RuntimeError("aiohttp not installed — run: pip install aiohttp")

    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(src.url, headers={"User-Agent": "CNSL/1.5 threat-feed"}) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            text = await resp.text(errors="replace")

    return _parse_feed_text(text, src)


def _parse_feed_text(
    text: str, src: FeedSource
) -> Tuple[Set[str], List[ipaddress.IPv4Network]]:
    """Parse raw feed text into (plain_ips, cidr_networks)."""
    ips:   Set[str]                    = set()
    cidrs: List[ipaddress.IPv4Network] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(src.comment_char):
            continue
        # Some feeds put extra fields after a semicolon or space
        token = line.split()[0].split(";")[0].strip()
        if not token:
            continue

        if src.is_cidr or "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
                if net.num_addresses == 1:
                    ips.add(str(net.network_address))
                else:
                    cidrs.append(net)
            except ValueError:
                pass
        else:
            try:
                ipaddress.ip_address(token)
                ips.add(token)
            except ValueError:
                pass

    return ips, cidrs


def _load_local_file(path: str) -> Tuple[Set[str], List[ipaddress.IPv4Network]]:
    """Load a local file with one IP or CIDR per line."""
    src = FeedSource(key="local", name="Local File", url="", comment_char="#")
    text = Path(path).read_text(errors="replace")
    src.is_cidr = True   # accept both IPs and CIDRs
    return _parse_feed_text(text, src)