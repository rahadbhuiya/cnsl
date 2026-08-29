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
    """Base class for correlation rules.

    Tunable at runtime (via the dashboard's /api/correlation-rules API
    or config.json's "correlation_rules" block) without touching each
    rule's evaluate() logic:
      - enabled       -- skip this rule entirely when False
      - window_sec    -- sliding window the rule looks back over
      - confidence    -- confidence score attached to alerts it raises
      - cooldown_sec  -- minimum time between repeat alerts for the same IP

    Rule-specific trigger counts (e.g. "3 SSH fails") stay in each
    rule's evaluate() -- generalizing those per-rule thresholds would
    require a much larger rework, and the four knobs above already
    cover the common tuning need (turn a noisy rule off, widen/narrow
    its window, adjust how loudly it should alert).
    """
    name:        str = "base_rule"
    description: str = ""
    window_sec:  int = 300
    cooldown_sec:int = 120
    confidence:  float = 0.5
    enabled:     bool = True

    # Runtime override fields (set via update()/config, None = use class defaults)
    _override_window_sec:   Optional[int]   = None
    _override_cooldown_sec: Optional[int]   = None
    _override_confidence:   Optional[float] = None

    def __init__(self) -> None:
        # Instance-level so overrides on one rule instance never leak to
        # another instance of the same class (defaults above are class
        # attributes and would otherwise be shared).
        self._override_window_sec   = None
        self._override_cooldown_sec = None
        self._override_confidence   = None

    @property
    def effective_window_sec(self) -> int:
        return self._override_window_sec if self._override_window_sec is not None else self.window_sec

    @property
    def effective_cooldown_sec(self) -> int:
        return self._override_cooldown_sec if self._override_cooldown_sec is not None else self.cooldown_sec

    @property
    def effective_confidence(self) -> float:
        return self._override_confidence if self._override_confidence is not None else self.confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":                self.name,
            "description":         self.description,
            "enabled":             self.enabled,
            "default_window_sec":  self.window_sec,
            "default_cooldown_sec":self.cooldown_sec,
            "default_confidence":  self.confidence,
            "effective_window_sec":   self.effective_window_sec,
            "effective_cooldown_sec": self.effective_cooldown_sec,
            "effective_confidence":   self.effective_confidence,
            "overridden": any([
                self._override_window_sec is not None,
                self._override_cooldown_sec is not None,
                self._override_confidence is not None,
            ]),
        }

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
        ssh_fails = buf.count_kind("SSH_FAIL",    self.effective_window_sec)
        db_fails  = buf.count_kind("DB_AUTH_FAIL", self.effective_window_sec)

        if ssh_fails >= 3 and db_fails >= 2:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
                severity    = "HIGH",
                description = f"Credential spray: {ssh_fails} SSH fails + {db_fails} DB fails in {self.effective_window_sec}s",
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
        web_scans = buf.count_kind("WEB_SCAN",          self.effective_window_sec)
        web_exp   = buf.count_kind("WEB_EXPLOIT_ATTEMPT",self.effective_window_sec)
        ssh_fails = buf.count_kind("SSH_FAIL",           self.effective_window_sec)

        if (web_scans + web_exp) >= 5 and ssh_fails >= 3:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
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
        honeypot = buf.count_kind("FW_HONEYPOT_PORT", self.effective_window_sec)
        ssh_fail = buf.count_kind("SSH_FAIL",         self.effective_window_sec)

        if honeypot >= 1 and ssh_fail >= 1:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
                severity    = "HIGH",
                description = "Automated scanner: hit honeypot port(s) then tried SSH",
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
        auth_fails = buf.count_kind("WEB_AUTH_FAIL", self.effective_window_sec)

        if auth_fails >= self.threshold:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
                severity    = "MEDIUM",
                description = f"Web auth flood: {auth_fails} 401/403 responses in {self.effective_window_sec}s",
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
        ssh_ok    = buf.count_kind("SSH_SUCCESS", self.effective_window_sec)
        sudo_fail = buf.count_kind("SUDO_FAIL",   self.effective_window_sec)
        su_fail   = buf.count_kind("SU_FAIL",     self.effective_window_sec)

        if ssh_ok >= 1 and (sudo_fail + su_fail) >= 2:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
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
        events    = buf.get_window(self.effective_window_sec)
        sources   = {ev.source for ev in events}
        kinds     = {ev.kind   for ev in events}
        total     = len(events)

        # Multiple sources AND multiple attack types AND significant volume
        if len(sources) >= 3 and len(kinds) >= 4 and total >= 20:
            return CorrelationAlert(
                rule_name   = self.name,
                src_ip      = ip,
                confidence  = self.effective_confidence,
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


# All active rule classes -- Correlator() instantiates fresh copies of
# each so overrides never leak between separate Correlator instances.
_DEFAULT_RULE_CLASSES = [
    MultiServiceBruteForce,
    WebReconThenSSH,
    HoneypotPortThenSSH,
    WebAuthFlood,
    PrivilegeEscalationAttempt,
    PersistentReconnaissance,
]


class Correlator:
    """
    Maintains per-IP event buffers and evaluates correlation rules.

    Usage:
        correlator = Correlator(cfg=cfg)
        alert = await correlator.ingest(event)
        if alert:
            # handle alert

    Tuning (dashboard API or config.json's "correlation_rules" block):
        "correlation_rules": {
          "web_auth_flood": {"enabled": false},
          "persistent_recon": {"window_sec": 900, "confidence": 0.6}
        }
    """

    def __init__(self, rules: List[CorrelationRule] = None, cfg: Optional[Dict[str, Any]] = None):
        # Fresh instances each time (not the module-level _DEFAULT_RULES
        # objects) so overrides on one Correlator never leak into another
        # -- e.g. two Correlator() instances in the same test run.
        self._rules: List[CorrelationRule] = rules if rules is not None else [
            cls() for cls in _DEFAULT_RULE_CLASSES
        ]
        self._rules_by_name: Dict[str, CorrelationRule] = {r.name: r for r in self._rules}
        self._buffers: Dict[str, IPEventBuffer]  = defaultdict(IPEventBuffer)
        self._last_alert: Dict[Tuple[str,str], float] = {}  # (ip, rule) -> ts

        if cfg:
            self._apply_config(cfg)

    def ingest(self, ev: Event) -> Optional[CorrelationAlert]:
        """
        Add event to IP buffer and evaluate all enabled rules.
        Returns a CorrelationAlert if a rule fires, else None.
        """
        ip = ev.src_ip
        if not ip:
            return None

        buf = self._buffers[ip]
        buf.add(ev)

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Per-rule cooldown per IP
            key     = (ip, rule.name)
            last_ts = self._last_alert.get(key, 0)
            if now() - last_ts < rule.effective_cooldown_sec:
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

    #  Rule management (dashboard API / config) 

    def get_rule(self, name: str) -> Optional[CorrelationRule]:
        """Return a rule by name, or None if unknown."""
        return self._rules_by_name.get(name)

    def all_rules(self) -> List[Dict[str, Any]]:
        """Return all rules as dicts, sorted by name."""
        return [r.to_dict() for r in sorted(self._rules, key=lambda r: r.name)]

    def enable(self, name: str) -> Optional[str]:
        """Enable a rule. Returns None on success, error string on failure."""
        r = self._rules_by_name.get(name)
        if not r:
            return f"Unknown correlation rule '{name}'."
        r.enabled = True
        return None

    def disable(self, name: str) -> Optional[str]:
        """Disable a rule. Returns None on success, error string on failure."""
        r = self._rules_by_name.get(name)
        if not r:
            return f"Unknown correlation rule '{name}'."
        r.enabled = False
        return None

    def update(
        self,
        name: str,
        *,
        enabled:      Optional[bool]  = None,
        window_sec:   Optional[int]   = None,
        cooldown_sec: Optional[int]   = None,
        confidence:   Optional[float] = None,
    ) -> Optional[str]:
        """
        Update one or more tunable fields of a correlation rule.
        Returns None on success, error string on validation failure.
        """
        r = self._rules_by_name.get(name)
        if not r:
            return f"Unknown correlation rule '{name}'."

        if window_sec is not None:
            if not isinstance(window_sec, int) or window_sec < 1:
                return "window_sec must be a positive integer."
            r._override_window_sec = window_sec

        if cooldown_sec is not None:
            if not isinstance(cooldown_sec, int) or cooldown_sec < 0:
                return "cooldown_sec must be a non-negative integer."
            r._override_cooldown_sec = cooldown_sec

        if confidence is not None:
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                return "confidence must be a number."
            if not (0.0 <= confidence <= 1.0):
                return "confidence must be between 0.0 and 1.0."
            r._override_confidence = confidence

        if enabled is not None:
            r.enabled = bool(enabled)

        return None

    def reset(self, name: str) -> Optional[str]:
        """Reset a rule to its built-in defaults (remove all overrides)."""
        r = self._rules_by_name.get(name)
        if not r:
            return f"Unknown correlation rule '{name}'."
        r._override_window_sec   = None
        r._override_cooldown_sec = None
        r._override_confidence   = None
        r.enabled = type(r).enabled  # class default, in case __init__ changes it later
        return None

    def _apply_config(self, cfg: Dict[str, Any]) -> None:
        """Apply config.json's "correlation_rules" overrides. Unknown rule
        names are ignored (validator.py flags them separately as warnings)."""
        rules_cfg = cfg.get("correlation_rules", {})
        if not isinstance(rules_cfg, dict):
            return
        for name, overrides in rules_cfg.items():
            if not isinstance(overrides, dict):
                continue
            self.update(
                name,
                enabled      = overrides.get("enabled"),
                window_sec   = overrides.get("window_sec"),
                cooldown_sec = overrides.get("cooldown_sec"),
                confidence   = overrides.get("confidence"),
            )
        return list(self._buffers.keys())