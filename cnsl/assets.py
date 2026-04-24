"""
cnsl/assets.py — Asset inventory via passive network discovery.

Builds a map of all devices on the network without active scanning.
Uses existing tcpdump and auth.log data — no extra traffic generated.

Tracks:
  - IP addresses seen on the network
  - First/last seen timestamps
  - Hostnames (from DNS/mDNS)
  - MAC addresses (from ARP — same subnet only)
  - Open services (inferred from connections)
  - Trust level (allowlisted, known, unknown, suspicious)
  - Activity patterns

Why passive:
  Active scanning (nmap) is noisy, may violate policy, and is
  already handled by dedicated tools. Passive discovery is silent
  and gives us a security-relevant view (what IPs are attacking us,
  what IPs are legitimate clients, etc.)
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from .models import iso_time, now


# Asset model


@dataclass
class Asset:
    ip:          str
    first_seen:  float          = field(default_factory=now)
    last_seen:   float          = field(default_factory=now)
    hostnames:   Set[str]       = field(default_factory=set)
    mac:         Optional[str]  = None
    services:    Set[str]       = field(default_factory=set)  # "ssh", "http", "smb"
    trust:       str            = "unknown"  # allowlisted|known|unknown|suspicious|attacker
    event_count: int            = 0
    fail_count:  int            = 0
    country:     Optional[str]  = None
    flag:        Optional[str]  = None
    notes:       List[str]      = field(default_factory=list)

    def seen_now(self) -> None:
        self.last_seen = now()
        self.event_count += 1

    def add_hostname(self, name: str) -> None:
        if name and not name.startswith("_"):
            self.hostnames.add(name)

    def add_service(self, svc: str) -> None:
        self.services.add(svc)

    def last_seen_ago(self) -> str:
        secs = now() - self.last_seen
        if secs < 60:
            return f"{int(secs)}s ago"
        if secs < 3600:
            return f"{int(secs/60)}m ago"
        if secs < 86400:
            return f"{int(secs/3600)}h ago"
        return f"{int(secs/86400)}d ago"

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["hostnames"] = sorted(self.hostnames)
        d["services"]  = sorted(self.services)
        d["first_seen_iso"] = iso_time(self.first_seen)
        d["last_seen_iso"]  = iso_time(self.last_seen)
        d["last_seen_ago"]  = self.last_seen_ago()
        return d



# ARP / DNS parsing helpers


# ARP: "arp who-has 192.168.1.1 tell 192.168.1.2"
# ARP reply: "arp reply 192.168.1.1 is-at aa:bb:cc:dd:ee:ff"
_ARP_WHO_RE  = re.compile(r"who-has\s+([\d\.]+)\s+tell\s+([\d\.]+)")
_ARP_RPLY_RE = re.compile(r"([\d\.]+)\s+is-at\s+([0-9a-f:]{17})", re.I)

# DNS: "192.168.1.1 > 8.8.8.8: 12345+ A? hostname.example.com."
_DNS_QUERY_RE = re.compile(r"A\?\s+([\w\.\-]+)\.", re.I)
# PTR: "8.8.8.8.in-addr.arpa. PTR hostname.example.com."
_PTR_RE       = re.compile(r"PTR\?\s+([\w\.\-]+)\.", re.I)

# mDNS service names: "_ssh._tcp.local", "_http._tcp.local"
_MDNS_SVC_RE  = re.compile(r"_([\w\-]+)\._tcp\.local")

# SSH service (port 22 connection)
_SSH_PORT_RE  = re.compile(r"\.22\s+>|>\s+\.22\s")


def _parse_arp(line: str) -> Optional[Dict]:
    lower = line.lower()
    m = _ARP_WHO_RE.search(lower)
    if m:
        return {"type": "arp_request", "target": m.group(1), "sender": m.group(2)}
    m = _ARP_RPLY_RE.search(line)
    if m:
        return {"type": "arp_reply", "ip": m.group(1), "mac": m.group(2).lower()}
    return None


def _parse_dns_hostname(line: str) -> Optional[str]:
    m = _DNS_QUERY_RE.search(line)
    if m:
        return m.group(1)
    m = _PTR_RE.search(line)
    if m:
        return m.group(1)
    return None


def _parse_mdns_service(line: str) -> Optional[str]:
    m = _MDNS_SVC_RE.search(line.lower())
    if m:
        return m.group(1)
    return None



# Asset inventory


class AssetInventory:
    """
    Passively discovers and tracks all network assets.

    Feed it events/lines from tcpdump and auth.log.
    It builds a real-time map of every IP seen on the network.

    Usage:
        inv = AssetInventory(cfg)
        inv.ingest_tcpdump_line("ARP who-has 192.168.1.1 tell 192.168.1.5")
        inv.ingest_auth_event(ip="1.2.3.4", kind="SSH_FAIL")
        inv.mark_allowlisted(["127.0.0.1", "10.0.0.1"])
        inv.mark_attacker("5.5.5.5")
        assets = inv.all_assets()
    """

    def __init__(self, cfg: Dict[str, Any] = None):
        cfg = cfg or {}
        inv_cfg          = cfg.get("asset_inventory", {})
        self.enabled     = bool(inv_cfg.get("enabled", True))
        self._assets:    Dict[str, Asset] = {}
        self._allowlist: Set[str]         = set()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def set_allowlist(self, ips: List[str]) -> None:
        self._allowlist = set(ips)
        for ip in ips:
            a = self._get_or_create(ip)
            a.trust = "allowlisted"

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest_tcpdump_line(self, line: str, src_ip: Optional[str] = None) -> None:
        """Process one tcpdump output line."""
        if not self.enabled:
            return

        lower = line.lower()

        # ARP discovery
        arp = _parse_arp(line)
        if arp:
            if arp["type"] == "arp_request":
                self._touch(arp["sender"])
            elif arp["type"] == "arp_reply":
                a = self._get_or_create(arp["ip"])
                a.mac = arp["mac"]
                a.seen_now()
            return

        # DNS hostname extraction
        hostname = _parse_dns_hostname(line)
        if hostname and src_ip:
            a = self._get_or_create(src_ip)
            a.add_hostname(hostname)
            a.seen_now()

        # mDNS service detection
        svc = _parse_mdns_service(line)
        if svc and src_ip:
            a = self._get_or_create(src_ip)
            a.add_service(svc)
            a.seen_now()

        # SMB/NetBIOS
        if " smb" in lower or " nbns" in lower:
            if src_ip:
                a = self._get_or_create(src_ip)
                a.add_service("smb")
                a.seen_now()

        # SSH connections
        if _SSH_PORT_RE.search(line) and src_ip:
            a = self._get_or_create(src_ip)
            a.add_service("ssh")
            a.seen_now()

    def ingest_auth_event(
        self,
        ip:      str,
        kind:    str,
        user:    Optional[str] = None,
        geo:     Optional[Dict] = None,
    ) -> None:
        """Process an auth event (SSH_FAIL, SSH_SUCCESS, etc.)."""
        if not self.enabled or not ip:
            return

        a = self._get_or_create(ip)
        a.seen_now()
        a.add_service("ssh")

        if kind == "SSH_FAIL":
            a.fail_count += 1
            if a.trust == "unknown" and a.fail_count >= 3:
                a.trust = "suspicious"

        elif kind == "SSH_SUCCESS":
            if a.trust == "unknown":
                a.trust = "known"

        if user:
            # Track users as notes
            note = f"user:{user}"
            if note not in a.notes:
                a.notes.append(note)

        if geo:
            a.country = geo.get("country")
            a.flag    = geo.get("flag")

    def mark_attacker(self, ip: str, reason: str = "") -> None:
        a = self._get_or_create(ip)
        a.trust = "attacker"
        if reason and reason not in a.notes:
            a.notes.append(f"blocked:{reason[:60]}")

    def mark_known(self, ip: str) -> None:
        a = self._get_or_create(ip)
        if a.trust not in ("allowlisted", "attacker"):
            a.trust = "known"

    # ── Queries ───────────────────────────────────────────────────────────────

    def all_assets(self) -> List[Dict]:
        return sorted(
            [a.to_dict() for a in self._assets.values()],
            key=lambda x: x["last_seen"], reverse=True,
        )

    def by_trust(self, trust: str) -> List[Dict]:
        return [a.to_dict() for a in self._assets.values() if a.trust == trust]

    def attackers(self) -> List[Dict]:
        return self.by_trust("attacker")

    def suspicious(self) -> List[Dict]:
        return self.by_trust("suspicious")

    def unknown(self) -> List[Dict]:
        return self.by_trust("unknown")

    def summary(self) -> Dict:
        counts: Dict[str, int] = defaultdict(int)
        for a in self._assets.values():
            counts[a.trust] += 1
        return {
            "total":        len(self._assets),
            "allowlisted":  counts["allowlisted"],
            "known":        counts["known"],
            "unknown":      counts["unknown"],
            "suspicious":   counts["suspicious"],
            "attacker":     counts["attacker"],
        }

    def get(self, ip: str) -> Optional[Dict]:
        a = self._assets.get(ip)
        return a.to_dict() if a else None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> Asset:
        if ip not in self._assets:
            trust = "allowlisted" if ip in self._allowlist else "unknown"
            self._assets[ip] = Asset(ip=ip, trust=trust)
        return self._assets[ip]

    def _touch(self, ip: str) -> Asset:
        a = self._get_or_create(ip)
        a.seen_now()
        return a