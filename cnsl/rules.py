"""
cnsl/rules.py — Alert Rule Engine.

Defines detection rules as first-class objects that can be:
  - Listed via the dashboard API
  - Enabled or disabled at runtime
  - Threshold-tuned without restarting CNSL
  - Overridden per-rule in config.json

Built-in rules (mirrors the hardcoded thresholds in detector.py):

  Rule ID                  Default sev  Trigger
  ──────────────────────── ───────────  ──────────────────────────────────
  ssh.brute_force          MEDIUM       >= N SSH fails in window
  ssh.credential_stuffing  MEDIUM       >= N distinct usernames in window
  ssh.credential_breach    HIGH         SSH success after >= N fails
  web.scan_flood           MEDIUM       >= N web 404/scan events in window
  web.auth_flood           MEDIUM       >= N 401/403 events in window
  web.exploit              HIGH         any exploit-path hit (threshold=1)
  db.brute_force           MEDIUM       >= N DB auth failures in window
  fw.honeypot_port         HIGH         connection to honeypot port (threshold=1)
  net.repeat_offender      HIGH         IP hits N+ incidents in escalation window

Config override example (config.json):
  "rules": {
    "ssh.brute_force": {
      "enabled":   true,
      "threshold": 5,
      "severity":  "HIGH"
    },
    "web.scan_flood": {
      "enabled": false
    }
  }
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


#  Rule dataclass 


@dataclass
class Rule:
    """A single detection rule."""

    id:          str                    # unique dotted id e.g. "ssh.brute_force"
    name:        str                    # human-readable name
    description: str                    # one-line explanation
    severity:    str                    # DEFAULT severity: LOW / MEDIUM / HIGH
    threshold:   int                    # event count that triggers the rule
    window_sec:  int                    # sliding window in seconds (0 = instantaneous)
    enabled:     bool       = True      # can be toggled at runtime
    tags:        List[str]  = field(default_factory=list)  # e.g. ["ssh", "brute"]
    # Runtime override fields (set from config, None = use defaults above)
    _override_severity:  Optional[str] = field(default=None, repr=False)
    _override_threshold: Optional[int] = field(default=None, repr=False)
    _override_window:    Optional[int] = field(default=None, repr=False)

    @property
    def effective_severity(self) -> str:
        return self._override_severity or self.severity

    @property
    def effective_threshold(self) -> int:
        return self._override_threshold if self._override_threshold is not None else self.threshold

    @property
    def effective_window(self) -> int:
        return self._override_window if self._override_window is not None else self.window_sec

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":                 self.id,
            "name":               self.name,
            "description":        self.description,
            "default_severity":   self.severity,
            "default_threshold":  self.threshold,
            "default_window_sec": self.window_sec,
            "effective_severity":  self.effective_severity,
            "effective_threshold": self.effective_threshold,
            "effective_window":    self.effective_window,
            "enabled":            self.enabled,
            "tags":               self.tags,
            "overridden":         any([
                self._override_severity is not None,
                self._override_threshold is not None,
                self._override_window is not None,
            ]),
        }


#  Built-in rule definitions 


_BUILTIN_RULES: List[Rule] = [
    Rule(
        id          = "ssh.brute_force",
        name        = "SSH Brute Force",
        description = "Fires when an IP exceeds the SSH failure threshold in the sliding window.",
        severity    = "MEDIUM",
        threshold   = 8,
        window_sec  = 60,
        tags        = ["ssh", "brute-force"],
    ),
    Rule(
        id          = "ssh.credential_stuffing",
        name        = "SSH Credential Stuffing",
        description = "Fires when an IP tries too many distinct usernames — indicates a credential list.",
        severity    = "MEDIUM",
        threshold   = 4,
        window_sec  = 60,
        tags        = ["ssh", "credential-stuffing"],
    ),
    Rule(
        id          = "ssh.credential_breach",
        name        = "SSH Credential Breach",
        description = "Fires when an IP succeeds after many failures — stolen credentials.",
        severity    = "HIGH",
        threshold   = 5,
        window_sec  = 60,
        tags        = ["ssh", "breach", "high-priority"],
    ),
    Rule(
        id          = "web.scan_flood",
        name        = "Web Scan Flood",
        description = "Fires when an IP generates many 404/scan responses — active directory enumeration.",
        severity    = "MEDIUM",
        threshold   = 20,
        window_sec  = 60,
        tags        = ["web", "scan"],
    ),
    Rule(
        id          = "web.auth_flood",
        name        = "Web Auth Flood",
        description = "Fires when an IP generates many 401/403 responses — web credential brute-force.",
        severity    = "MEDIUM",
        threshold   = 15,
        window_sec  = 60,
        tags        = ["web", "auth", "brute-force"],
    ),
    Rule(
        id          = "web.exploit",
        name        = "Web Exploit Attempt",
        description = "Fires on the first hit to a known exploit path (SQLi, RCE, traversal, etc.).",
        severity    = "HIGH",
        threshold   = 1,
        window_sec  = 0,
        tags        = ["web", "exploit", "high-priority"],
    ),
    Rule(
        id          = "db.brute_force",
        name        = "Database Brute Force",
        description = "Fires when an IP generates many database authentication failures.",
        severity    = "MEDIUM",
        threshold   = 5,
        window_sec  = 60,
        tags        = ["database", "brute-force"],
    ),
    Rule(
        id          = "fw.honeypot_port",
        name        = "Honeypot Port Hit",
        description = "Fires on any connection to a honeypot port — never a legitimate access.",
        severity    = "HIGH",
        threshold   = 1,
        window_sec  = 0,
        tags        = ["firewall", "honeypot", "high-priority"],
    ),
    Rule(
        id          = "net.repeat_offender",
        name        = "Repeat Offender Escalation",
        description = "Escalates MEDIUM detections to HIGH when an IP hits multiple incidents in the escalation window.",
        severity    = "HIGH",
        threshold   = 3,
        window_sec  = 3600,
        tags        = ["escalation"],
    ),
]

# Quick lookup by id
_BUILTIN_BY_ID: Dict[str, Rule] = {r.id: r for r in _BUILTIN_RULES}


#  Rule Engine 


class RuleEngine:
    """
    Manages the full set of detection rules.

    On startup:
      1. Load built-in rules (copies, so originals are never mutated)
      2. Apply config overrides (enabled flag, threshold, severity, window)

    At runtime:
      - detector.py queries rules via get() to read effective thresholds
      - Dashboard API calls enable()/disable()/update() for live tuning

    Config format (config.json):
      "rules": {
        "ssh.brute_force": { "enabled": true, "threshold": 5, "severity": "HIGH" },
        "web.scan_flood":  { "enabled": false }
      }
    """

    def __init__(self, cfg: Dict[str, Any] = None):
        # Deep-copy built-ins so mutations never affect the module-level defaults
        self._rules: Dict[str, Rule] = {
            r.id: copy.deepcopy(r) for r in _BUILTIN_RULES
        }
        if cfg:
            self._apply_config(cfg)

    #  Query 

    def get(self, rule_id: str) -> Optional[Rule]:
        """Return a rule by id, or None if unknown."""
        return self._rules.get(rule_id)

    def is_enabled(self, rule_id: str) -> bool:
        """True if the rule exists and is enabled."""
        r = self._rules.get(rule_id)
        return r is not None and r.enabled

    def threshold(self, rule_id: str, fallback: int = 0) -> int:
        """Effective threshold for a rule (config override > default)."""
        r = self._rules.get(rule_id)
        return r.effective_threshold if r else fallback

    def severity(self, rule_id: str, fallback: str = "MEDIUM") -> str:
        """Effective severity for a rule."""
        r = self._rules.get(rule_id)
        return r.effective_severity if r else fallback

    def window(self, rule_id: str, fallback: int = 60) -> int:
        """Effective window_sec for a rule."""
        r = self._rules.get(rule_id)
        return r.effective_window if r else fallback

    def all_rules(self) -> List[Dict[str, Any]]:
        """Return all rules as dicts, sorted by id."""
        return [r.to_dict() for r in sorted(self._rules.values(), key=lambda r: r.id)]

    def rules_by_tag(self, tag: str) -> List[Rule]:
        return [r for r in self._rules.values() if tag in r.tags]

    #  Mutations (dashboard API / config) 

    def enable(self, rule_id: str) -> Optional[str]:
        """Enable a rule. Returns None on success, error string on failure."""
        r = self._rules.get(rule_id)
        if not r:
            return f"Unknown rule '{rule_id}'."
        r.enabled = True
        return None

    def disable(self, rule_id: str) -> Optional[str]:
        """Disable a rule. Returns None on success, error string on failure."""
        r = self._rules.get(rule_id)
        if not r:
            return f"Unknown rule '{rule_id}'."
        r.enabled = False
        return None

    def update(
        self,
        rule_id:   str,
        *,
        enabled:   Optional[bool] = None,
        threshold: Optional[int]  = None,
        severity:  Optional[str]  = None,
        window:    Optional[int]  = None,
    ) -> Optional[str]:
        """
        Update one or more fields of a rule.
        Returns None on success, error string on validation failure.
        """
        r = self._rules.get(rule_id)
        if not r:
            return f"Unknown rule '{rule_id}'."

        if severity is not None:
            sev = severity.upper()
            if sev not in {"LOW", "MEDIUM", "HIGH"}:
                return f"Invalid severity '{severity}'. Must be LOW, MEDIUM, or HIGH."
            r._override_severity = sev

        if threshold is not None:
            if threshold < 1:
                return "Threshold must be >= 1."
            r._override_threshold = threshold

        if window is not None:
            if window < 0:
                return "Window must be >= 0."
            r._override_window = window

        if enabled is not None:
            r.enabled = bool(enabled)

        return None

    def reset(self, rule_id: str) -> Optional[str]:
        """Reset a rule to its built-in defaults (remove all overrides)."""
        if rule_id not in self._rules:
            return f"Unknown rule '{rule_id}'."
        original = _BUILTIN_BY_ID.get(rule_id)
        if not original:
            return f"No built-in defaults for '{rule_id}'."
        r = self._rules[rule_id]
        r._override_severity  = None
        r._override_threshold = None
        r._override_window    = None
        r.enabled             = original.enabled
        return None

    #  Internal 

    def _apply_config(self, cfg: Dict[str, Any]) -> None:
        """Apply config.json rule overrides. Unknown rule ids are ignored."""
        rules_cfg = cfg.get("rules", {})
        if not isinstance(rules_cfg, dict):
            return
        for rule_id, overrides in rules_cfg.items():
            if not isinstance(overrides, dict):
                continue
            self.update(
                rule_id,
                enabled   = overrides.get("enabled"),
                threshold = overrides.get("threshold"),
                severity  = overrides.get("severity"),
                window    = overrides.get("window_sec"),
            )