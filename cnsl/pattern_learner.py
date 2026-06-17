"""
cnsl/pattern_learner.py -- Automated Attack Pattern Discovery.

Observes ML anomaly alerts and correlation incidents over time and
discovers recurring event sequences that reliably precede attacks.
When a pattern repeats above a confidence threshold, it generates a
SuggestedRule that operators can promote to a live detection rule with
one click from the dashboard.

This implements the "automated pattern discovery" goal from the original
CNSL research paper:

    "CNSL: A Cognitive Network Security Layer for
     Intent-Based Incident Detection and Response"

    "The system should be capable of automated discovery of new intent
     patterns without requiring manual rule authoring."

How it works:

  1. Every time an incident fires or an ML anomaly is detected, the
     PatternLearner records the sequence of event kinds that preceded it
     within a configurable look-back window (default 5 minutes).

  2. Event sequences are normalized into a pattern fingerprint --
     a sorted tuple of (event_kind, source) pairs that appeared together.

  3. Fingerprints are counted. When a fingerprint has been seen
     at least MIN_OCCURRENCES times, it becomes a SuggestedRule.

  4. Each SuggestedRule includes:
       - The event kinds in the pattern
       - Observed threshold (median count when pattern fired)
       - Suggested window_sec
       - Confidence score (0.0-1.0): how consistently this pattern
         preceded an actual alert
       - Example IPs that triggered it
       - First and last seen timestamps

  5. Operators can:
       - Promote: convert the SuggestedRule into a live Rule in RuleEngine
       - Dismiss: suppress this suggestion permanently

SQLite persistence:
  Table: pl_suggestions
  Auto-migrated via Store when pattern_learner is passed in.

Config (config.json):
  "pattern_learning": {
    "enabled":           true,
    "lookback_sec":      300,
    "min_occurrences":   5,
    "max_suggestions":   50,
    "persist":           true
  }

API endpoints (added in dashboard.py):
  GET  /api/pattern-suggestions          -- all current suggestions
  POST /api/pattern-suggestions/{id}/promote  -- promote to live rule
  POST /api/pattern-suggestions/{id}/dismiss  -- dismiss suggestion
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .models import Event, iso_time, now



# SQLite schema


PL_SCHEMA = """
CREATE TABLE IF NOT EXISTS pl_suggestions (
    id           TEXT PRIMARY KEY,
    pattern_key  TEXT NOT NULL,
    event_kinds  TEXT NOT NULL,
    occurrences  INTEGER DEFAULT 0,
    confidence   REAL DEFAULT 0.0,
    severity     TEXT DEFAULT 'MEDIUM',
    threshold    INTEGER DEFAULT 1,
    window_sec   INTEGER DEFAULT 60,
    example_ips  TEXT DEFAULT '[]',
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    dismissed    INTEGER DEFAULT 0,
    promoted     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pl_confidence ON pl_suggestions(confidence DESC);
CREATE INDEX IF NOT EXISTS idx_pl_last_seen  ON pl_suggestions(last_seen DESC);
"""



# Data models


@dataclass
class SuggestedRule:
    """
    A rule candidate discovered by the pattern learner.

    id           -- stable hash of the pattern_key
    pattern_key  -- canonical string representation of the event sequence
    event_kinds  -- list of event kinds in the pattern
    occurrences  -- how many times this pattern has preceded an alert
    confidence   -- fraction of occurrences that led to a confirmed alert
    severity     -- suggested severity based on observed pattern
    threshold    -- suggested event count threshold
    window_sec   -- suggested detection window
    example_ips  -- up to 5 IPs that triggered this pattern
    first_seen   -- first time this pattern was observed
    last_seen    -- most recent observation
    dismissed    -- operator has dismissed this suggestion
    promoted     -- operator has promoted this to a live rule
    """
    id:          str
    pattern_key: str
    event_kinds: List[str]
    occurrences: int        = 0
    confidence:  float      = 0.0
    severity:    str        = "MEDIUM"
    threshold:   int        = 1
    window_sec:  int        = 60
    example_ips: List[str]  = field(default_factory=list)
    first_seen:  float      = field(default_factory=now)
    last_seen:   float      = field(default_factory=now)
    dismissed:   bool       = False
    promoted:    bool       = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":          self.id,
            "pattern_key": self.pattern_key,
            "event_kinds": self.event_kinds,
            "occurrences": self.occurrences,
            "confidence":  round(self.confidence, 3),
            "severity":    self.severity,
            "threshold":   self.threshold,
            "window_sec":  self.window_sec,
            "example_ips": self.example_ips,
            "first_seen":  iso_time(self.first_seen),
            "last_seen":   iso_time(self.last_seen),
            "dismissed":   self.dismissed,
            "promoted":    self.promoted,
            "suggested_rule_id": self._suggested_id(),
        }

    def _suggested_id(self) -> str:
        """Generate a suggested rule ID from the pattern kinds."""
        kinds = "_".join(k.lower() for k in sorted(set(self.event_kinds)))
        return f"learned.{kinds[:60]}"

    def to_db_row(self) -> Dict[str, Any]:
        return {
            "id":          self.id,
            "pattern_key": self.pattern_key,
            "event_kinds": json.dumps(self.event_kinds),
            "occurrences": self.occurrences,
            "confidence":  self.confidence,
            "severity":    self.severity,
            "threshold":   self.threshold,
            "window_sec":  self.window_sec,
            "example_ips": json.dumps(self.example_ips[:5]),
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
            "dismissed":   1 if self.dismissed else 0,
            "promoted":    1 if self.promoted else 0,
        }

    @staticmethod
    def from_db_row(row: Dict[str, Any]) -> "SuggestedRule":
        return SuggestedRule(
            id          = row["id"],
            pattern_key = row["pattern_key"],
            event_kinds = json.loads(row.get("event_kinds", "[]")),
            occurrences = row.get("occurrences", 0),
            confidence  = row.get("confidence", 0.0),
            severity    = row.get("severity", "MEDIUM"),
            threshold   = row.get("threshold", 1),
            window_sec  = row.get("window_sec", 60),
            example_ips = json.loads(row.get("example_ips", "[]")),
            first_seen  = row.get("first_seen", now()),
            last_seen   = row.get("last_seen", now()),
            dismissed   = bool(row.get("dismissed", 0)),
            promoted    = bool(row.get("promoted", 0)),
        )



# Per-IP event buffer


class _EventBuffer:
    """
    Sliding window of recent events for one IP.
    Used to extract the event sequence that preceded an alert.
    """

    def __init__(self, window_sec: int) -> None:
        self._window_sec = window_sec
        self._events: Deque[Tuple[float, str, str]] = deque()
        # (timestamp, event_kind, source)

    def add(self, ts: float, kind: str, source: str) -> None:
        self._events.append((ts, kind, source))
        self._prune(ts)

    def _prune(self, t: float) -> None:
        cutoff = t - self._window_sec
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def snapshot(self) -> List[Tuple[str, str]]:
        """Return (kind, source) pairs in the current window."""
        t = now()
        self._prune(t)
        return [(kind, src) for _, kind, src in self._events]



# Pattern fingerprinting


def _fingerprint(pairs: List[Tuple[str, str]]) -> Tuple[str, List[str]]:
    """
    Convert a list of (kind, source) pairs into a stable fingerprint.

    Returns:
        pattern_key  -- canonical string (sorted unique kinds joined by '+')
        event_kinds  -- sorted list of unique event kinds
    """
    kinds = sorted(set(k for k, _ in pairs))
    if not kinds:
        return "", []
    pattern_key = "+".join(kinds)
    return pattern_key, kinds


def _make_id(pattern_key: str) -> str:
    """Stable short ID from pattern key."""
    return hashlib.sha1(pattern_key.encode()).hexdigest()[:12]


def _suggest_severity(kinds: List[str]) -> str:
    """Suggest severity based on what event kinds are present."""
    high_kinds = {
        "SSH_SUCCESS", "WEB_EXPLOIT_ATTEMPT", "FW_HONEYPOT_PORT",
        "SUDO_FAIL", "SU_FAIL", "THREAT_FEED_HIT",
    }
    if any(k in high_kinds for k in kinds):
        return "HIGH"
    if len(kinds) >= 3:
        return "HIGH"
    return "MEDIUM"


def _suggest_threshold(occurrences_list: List[int]) -> int:
    """Suggest threshold as the median observed event count."""
    if not occurrences_list:
        return 1
    s = sorted(occurrences_list)
    mid = len(s) // 2
    return max(1, s[mid])



# Pattern Learner (main class)


class PatternLearner:
    """
    Observes incidents and ML anomalies, discovers recurring event
    patterns, and generates suggested detection rules.

    Usage:
        learner = PatternLearner(cfg)
        learner.observe_event(event)          # call for every event
        learner.on_alert(ip, rule_name)       # call when alert fires
        suggestions = learner.get_suggestions()
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        pl_cfg = cfg.get("pattern_learning", {})
        self.enabled         = bool(pl_cfg.get("enabled", True))
        self.lookback_sec    = int(pl_cfg.get("lookback_sec", 300))
        self.min_occurrences = int(pl_cfg.get("min_occurrences", 5))
        self.max_suggestions = int(pl_cfg.get("max_suggestions", 50))
        self.persist         = bool(pl_cfg.get("persist", True))

        # Per-IP event buffers
        self._buffers: Dict[str, _EventBuffer] = {}

        # Pattern occurrence tracking
        # pattern_key -> list of event counts when it fired
        self._pattern_counts: Dict[str, List[int]] = defaultdict(list)

        # Pattern -> first confirmed alert (used for confidence)
        self._pattern_alerts: Dict[str, int] = defaultdict(int)

        # All observations (confirmed + unconfirmed) per pattern
        self._pattern_observations: Dict[str, int] = defaultdict(int)

        # Suggestions keyed by id
        self._suggestions: Dict[str, SuggestedRule] = {}

        # Dismissed ids (never re-suggest)
        self._dismissed: set = set()

    
    # Public observation API

    def observe_event(self, ev: Event) -> None:
        """Record an event for pattern tracking."""
        if not self.enabled or not ev.src_ip:
            return
        ip  = ev.src_ip
        buf = self._get_or_create_buffer(ip)
        buf.add(ev.ts or now(), ev.kind, ev.source or "unknown")

    def on_alert(self, ip: str, rule_name: str) -> Optional[SuggestedRule]:
        """
        Called when a detection or correlation alert fires for an IP.
        Extracts the event sequence that preceded the alert and updates
        pattern statistics. Returns a new/updated SuggestedRule if the
        pattern crosses the min_occurrences threshold.
        """
        if not self.enabled or not ip:
            return None

        buf = self._buffers.get(ip)
        if buf is None:
            return None

        pairs = buf.snapshot()
        if len(pairs) < 2:
            return None

        pattern_key, kinds = _fingerprint(pairs)
        if not pattern_key or pattern_key in self._dismissed:
            return None

        count = len(pairs)
        self._pattern_counts[pattern_key].append(count)
        self._pattern_alerts[pattern_key] += 1
        self._pattern_observations[pattern_key] += 1

        occurrences = self._pattern_alerts[pattern_key]

        # Update or create suggestion
        sid = _make_id(pattern_key)
        if sid in self._suggestions:
            sugg = self._suggestions[sid]
            sugg.occurrences = occurrences
            sugg.last_seen   = now()
            sugg.confidence  = self._compute_confidence(pattern_key)
            sugg.threshold   = _suggest_threshold(self._pattern_counts[pattern_key])
            if ip not in sugg.example_ips:
                sugg.example_ips = (sugg.example_ips + [ip])[:5]
        elif occurrences >= self.min_occurrences:
            # New suggestion born
            if len(self._suggestions) >= self.max_suggestions:
                self._evict_weakest()
            sugg = SuggestedRule(
                id          = sid,
                pattern_key = pattern_key,
                event_kinds = kinds,
                occurrences = occurrences,
                confidence  = self._compute_confidence(pattern_key),
                severity    = _suggest_severity(kinds),
                threshold   = _suggest_threshold(self._pattern_counts[pattern_key]),
                window_sec  = self.lookback_sec,
                example_ips = [ip],
                first_seen  = now(),
                last_seen   = now(),
            )
            self._suggestions[sid] = sugg
            return sugg
        else:
            return None

        return self._suggestions.get(sid)

    def on_ml_anomaly(self, ip: str, reasons: List[str]) -> Optional[SuggestedRule]:
        """
        Called when an ML anomaly is detected. Treats the anomaly reasons
        as synthetic event kinds for pattern discovery.
        """
        if not self.enabled or not ip:
            return None

        buf = self._buffers.get(ip)
        if buf is None:
            return None

        pairs = buf.snapshot()
        if not pairs:
            return None

        # Augment with ML reason kinds
        ml_kinds = [(r.split(":")[0].strip().upper().replace(" ", "_"), "ml")
                    for r in reasons]
        combined = pairs + ml_kinds

        pattern_key, kinds = _fingerprint(combined)
        if not pattern_key or pattern_key in self._dismissed:
            return None

        return self.on_alert(ip, "ml_anomaly")

    def get_suggestions(
        self,
        include_dismissed: bool = False,
        include_promoted:  bool = False,
    ) -> List[SuggestedRule]:
        """Return suggestions sorted by confidence descending."""
        results = [
            s for s in self._suggestions.values()
            if (include_dismissed or not s.dismissed)
            and (include_promoted  or not s.promoted)
        ]
        results.sort(key=lambda s: (s.confidence, s.occurrences), reverse=True)
        return results

    def get_suggestion(self, sid: str) -> Optional[SuggestedRule]:
        return self._suggestions.get(sid)

    def dismiss(self, sid: str) -> bool:
        """Dismiss a suggestion. Returns True if found."""
        sugg = self._suggestions.get(sid)
        if not sugg:
            return False
        sugg.dismissed = True
        self._dismissed.add(sugg.pattern_key)
        return True

    def mark_promoted(self, sid: str) -> bool:
        """Mark a suggestion as promoted. Returns True if found."""
        sugg = self._suggestions.get(sid)
        if not sugg:
            return False
        sugg.promoted = True
        return True

    def stats(self) -> Dict[str, Any]:
        suggestions = list(self._suggestions.values())
        active = [s for s in suggestions if not s.dismissed and not s.promoted]
        return {
            "enabled":              self.enabled,
            "total_suggestions":    len(suggestions),
            "active_suggestions":   len(active),
            "dismissed":            sum(1 for s in suggestions if s.dismissed),
            "promoted":             sum(1 for s in suggestions if s.promoted),
            "patterns_tracked":     len(self._pattern_observations),
            "min_occurrences":      self.min_occurrences,
        }

    
    # SQLite persistence
    

    async def save_all(self, store: Any) -> None:
        if not self.persist or not store:
            return
        for sugg in self._suggestions.values():
            await self._save_suggestion(store, sugg)

    async def load_all(self, store: Any) -> None:
        if not self.persist or not store:
            return
        try:
            rows = await store.db_fetchall(
                "SELECT * FROM pl_suggestions ORDER BY confidence DESC LIMIT ?",
                (self.max_suggestions,),
            )
            for row in rows:
                sugg = SuggestedRule.from_db_row(row)
                self._suggestions[sugg.id] = sugg
                if sugg.dismissed:
                    self._dismissed.add(sugg.pattern_key)
        except Exception:
            pass

    async def save_suggestion(self, store: Any, sugg: SuggestedRule) -> None:
        if not self.persist or not store:
            return
        await self._save_suggestion(store, sugg)

    
    # Internal helpers
    

    def _get_or_create_buffer(self, ip: str) -> _EventBuffer:
        if ip not in self._buffers:
            self._buffers[ip] = _EventBuffer(self.lookback_sec)
        return self._buffers[ip]

    def _compute_confidence(self, pattern_key: str) -> float:
        """
        Confidence = alerts / observations.
        Since we only record observations on alerts right now, this is
        always 1.0 for promoted patterns. Reserved for future where we
        track all patterns, not just alert-triggering ones.
        """
        obs = self._pattern_observations.get(pattern_key, 0)
        alerts = self._pattern_alerts.get(pattern_key, 0)
        if obs == 0:
            return 0.0
        return round(min(1.0, alerts / obs), 3)

    def _evict_weakest(self) -> None:
        """Remove the suggestion with the lowest confidence."""
        if not self._suggestions:
            return
        weakest = min(
            self._suggestions,
            key=lambda sid: (
                self._suggestions[sid].confidence,
                self._suggestions[sid].occurrences,
            ),
        )
        del self._suggestions[weakest]

    async def _save_suggestion(self, store: Any, sugg: SuggestedRule) -> None:
        try:
            row = sugg.to_db_row()
            await store.db_execute(
                """
                INSERT INTO pl_suggestions
                    (id, pattern_key, event_kinds, occurrences, confidence,
                     severity, threshold, window_sec, example_ips,
                     first_seen, last_seen, dismissed, promoted)
                VALUES
                    (:id, :pattern_key, :event_kinds, :occurrences, :confidence,
                     :severity, :threshold, :window_sec, :example_ips,
                     :first_seen, :last_seen, :dismissed, :promoted)
                ON CONFLICT(id) DO UPDATE SET
                    occurrences = excluded.occurrences,
                    confidence  = excluded.confidence,
                    severity    = excluded.severity,
                    threshold   = excluded.threshold,
                    example_ips = excluded.example_ips,
                    last_seen   = excluded.last_seen,
                    dismissed   = excluded.dismissed,
                    promoted    = excluded.promoted
                """,
                row,
            )
        except Exception:
            pass