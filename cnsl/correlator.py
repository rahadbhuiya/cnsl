"""
cnsl/correlator.py — Cross-source correlation rules engine.

This is the core of "Correlated Network Security Layer" —
it combines signals from multiple sources to detect attacks
that no single log source can see alone.

Example correlations:
  - SSH fail + Web scan from same IP = coordinated attack
  - Web exploit attempt + UFW block = active intrusion attempt
  - DB auth fail + SSH fail = credential spray across services
  - Many 404s + exploit path = automated web scanner

Each rule:
  - Watches a sliding time window
  - Requires events from specific sources/kinds
  - Produces a CorrelationAlert with confidence score
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Event, now



# Alert model


@dataclass
class CorrelationAlert:
    rule_name:   str
    src_ip:      str
    confidence:  float
    severity:    str
    description: str
    evidence:    List[Dict]    # list of contributing events
    ts:          float = field(default_factory=now)

    def to_dict(self) -> Dict:
        return {
            "rule":        self.rule_name,
            "src_ip":      self.src_ip,
            "confidence":  self.confidence,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence,
            "ts":          self.ts,
        }



# Per-IP event buffer


@dataclass
class IPEventBuffer:
    events: deque = field(default_factory=lambda: deque(maxlen=500))

    def add(self, ev: Event) -> None:
        self.events.appendleft((now(), ev))

    def get_window(self, window_sec: int) -> List[Event]:
        cutoff = now() - window_sec
        return [ev for ts, ev in self.events if ts > cutoff]

    def count_kind(self, kind: str, window_sec: int) -> int:
        return sum(1 for ev in self.get_window(window_sec) if ev.kind == kind)

    def count_source(self, source: str, window_sec: int) -> int:
        return sum(1 for ev in self.get_window(window_sec) if ev.source == source)

    def has_kind(self, kind: str, window_sec: int) -> bool:
        return self.count_kind(kind, window_sec) > 0

    def has_source(self, source: str, window_sec: int) -> bool:
        return self.count_source(source, window_sec) > 0


# Correlation rules


class CorrelationRule:
    """Base class for correlation rules."""
    name:        str = "base_rule"
    description: str = ""
    window_sec:  int = 300
    cooldown_sec:int = 120

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        raise NotImplementedError


class MultiServiceBruteForce(CorrelationRule):
    """
    SSH fail + DB auth fail from same IP = credential spray.
    Attacker is trying stolen credentials across multiple services.
    """
    name        = "multi_service_brute_force"
    description = "Credential spray across SSH and database"
    window_sec  = 300
    confidence  = 0.85

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        ssh_fails = buf.count_kind("SSH_FAIL",    self.window_sec)
        db_fails  = buf.count_kind("DB_AUTH_FAIL", self.window_sec)

        if ssh_fails >= 3 and db_fails >= 2:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "HIGH",
                description = f"Credential spray: {ssh_fails} SSH fails + {db_fails} DB fails in {self.window_sec}s",
                evidence    = [
                    {"kind": "SSH_FAIL",    "count": ssh_fails},
                    {"kind": "DB_AUTH_FAIL","count": db_fails},
                ],
            )
        return None


class WebReconThenSSH(CorrelationRule):
    """
    Web scanning + SSH brute-force from same IP = coordinated attack.
    Attacker first maps the server, then tries to break in via SSH.
    """
    name        = "web_recon_then_ssh"
    description = "Web reconnaissance followed by SSH brute-force"
    window_sec  = 600
    confidence  = 0.80

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        web_scans = buf.count_kind("WEB_SCAN",          self.window_sec)
        web_exp   = buf.count_kind("WEB_EXPLOIT_ATTEMPT",self.window_sec)
        ssh_fails = buf.count_kind("SSH_FAIL",           self.window_sec)

        if (web_scans + web_exp) >= 5 and ssh_fails >= 3:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "HIGH",
                description = (
                    f"Coordinated attack: {web_scans} web scans, "
                    f"{web_exp} exploit attempts, {ssh_fails} SSH fails"
                ),
                evidence    = [
                    {"kind": "WEB_SCAN",            "count": web_scans},
                    {"kind": "WEB_EXPLOIT_ATTEMPT", "count": web_exp},
                    {"kind": "SSH_FAIL",             "count": ssh_fails},
                ],
            )
        return None


class HoneypotPortThenSSH(CorrelationRule):
    """
    Firewall block on honeypot port + SSH fail = worm / automated scanner.
    Legitimate users never hit ports like 23, 3389, 6379.
    """
    name        = "honeypot_then_ssh"
    description = "Honeypot port probe followed by SSH attempt"
    window_sec  = 180
    confidence  = 0.90

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        honeypot = buf.count_kind("FW_HONEYPOT_PORT", self.window_sec)
        ssh_fail = buf.count_kind("SSH_FAIL",         self.window_sec)

        if honeypot >= 1 and ssh_fail >= 1:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "HIGH",
                description = f"Automated scanner: hit honeypot port(s) then tried SSH",
                evidence    = [
                    {"kind": "FW_HONEYPOT_PORT", "count": honeypot},
                    {"kind": "SSH_FAIL",          "count": ssh_fail},
                ],
            )
        return None


class WebAuthFlood(CorrelationRule):
    """
    Many 401/403 responses = web credential brute-force.
    """
    name        = "web_auth_flood"
    description = "Web authentication brute-force"
    window_sec  = 120
    confidence  = 0.75
    threshold   = 15

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        auth_fails = buf.count_kind("WEB_AUTH_FAIL", self.window_sec)

        if auth_fails >= self.threshold:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "MEDIUM",
                description = f"Web auth flood: {auth_fails} 401/403 responses in {self.window_sec}s",
                evidence    = [{"kind": "WEB_AUTH_FAIL", "count": auth_fails}],
            )
        return None


class PrivilegeEscalationAttempt(CorrelationRule):
    """
    Sudo/su failures after SSH success = post-compromise privilege escalation.
    """
    name        = "privilege_escalation"
    description = "Privilege escalation attempt after login"
    window_sec  = 300
    confidence  = 0.85

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        ssh_ok    = buf.count_kind("SSH_SUCCESS", self.window_sec)
        sudo_fail = buf.count_kind("SUDO_FAIL",   self.window_sec)
        su_fail   = buf.count_kind("SU_FAIL",     self.window_sec)

        if ssh_ok >= 1 and (sudo_fail + su_fail) >= 2:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "HIGH",
                description = (
                    f"Privilege escalation after login: "
                    f"{sudo_fail} sudo fails, {su_fail} su fails"
                ),
                evidence    = [
                    {"kind": "SSH_SUCCESS", "count": ssh_ok},
                    {"kind": "SUDO_FAIL",   "count": sudo_fail},
                    {"kind": "SU_FAIL",     "count": su_fail},
                ],
            )
        return None


class PersistentReconnaissance(CorrelationRule):
    """
    Many different attack types from same IP over a longer window.
    This IP is methodically probing the server.
    """
    name        = "persistent_recon"
    description = "Persistent multi-vector reconnaissance"
    window_sec  = 1800   # 30 minutes
    confidence  = 0.70

    def evaluate(self, ip: str, buf: IPEventBuffer) -> Optional[CorrelationAlert]:
        events    = buf.get_window(self.window_sec)
        sources   = {ev.source for ev in events}
        kinds     = {ev.kind   for ev in events}
        total     = len(events)

        # Multiple sources AND multiple attack types AND significant volume
        if len(sources) >= 3 and len(kinds) >= 4 and total >= 20:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.confidence,
                severity    = "MEDIUM",
                description = (
                    f"Persistent recon: {total} events across "
                    f"{len(sources)} sources, {len(kinds)} attack types in 30min"
                ),
                evidence    = [
                    {"sources": list(sources), "kinds": list(kinds), "total": total}
                ],
            )
        return None



# Correlator engine


# All active rules
_DEFAULT_RULES = [
    MultiServiceBruteForce(),
    WebReconThenSSH(),
    HoneypotPortThenSSH(),
    WebAuthFlood(),
    PrivilegeEscalationAttempt(),
    PersistentReconnaissance(),
]


class Correlator:
    """
    Maintains per-IP event buffers and evaluates correlation rules.

    Usage:
        correlator = Correlator()
        alert = await correlator.ingest(event)
        if alert:
            # handle alert
    """

    def __init__(self, rules: List[CorrelationRule] = None):
        self._rules:   List[CorrelationRule]     = rules or _DEFAULT_RULES
        self._buffers: Dict[str, IPEventBuffer]  = defaultdict(IPEventBuffer)
        self._last_alert: Dict[Tuple[str,str], float] = {}  # (ip, rule) -> ts

    def ingest(self, ev: Event) -> Optional[CorrelationAlert]:
        """
        Add event to IP buffer and evaluate all rules.
        Returns a CorrelationAlert if a rule fires, else None.
        """
        ip = ev.src_ip
        if not ip:
            return None

        buf = self._buffers[ip]
        buf.add(ev)

        for rule in self._rules:
            # Per-rule cooldown per IP
            key     = (ip, rule.name)
            last_ts = self._last_alert.get(key, 0)
            if now() - last_ts < rule.cooldown_sec:
                continue

            alert = rule.evaluate(ip, buf)
            if alert:
                self._last_alert[key] = now()
                return alert

        return None

    def get_ip_summary(self, ip: str, window_sec: int = 300) -> Dict[str, Any]:
        """Return event counts by kind for an IP."""
        buf    = self._buffers.get(ip)
        if not buf:
            return {}
        events = buf.get_window(window_sec)
        counts: Dict[str, int] = defaultdict(int)
        for ev in events:
            counts[ev.kind] += 1
        return dict(counts)

    def active_ips(self) -> List[str]:
        return list(self._buffers.keys())