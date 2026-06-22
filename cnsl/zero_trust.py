"""
cnsl/zero_trust.py -- Zero-Trust Trust Score Engine.

Maintains a per-entity (IP or username) trust score that reflects how
much CNSL trusts that entity based on observed behavior. A low trust
score causes CNSL to treat the entity more aggressively -- lowering the
effective detection threshold so fewer events are needed to trigger an
alert.

This implements the zero-trust architecture support gap from the CNSL
research paper:

    "CNSL: A Cognitive Network Security Layer for
     Intent-Based Incident Detection and Response"

    "Future work includes zero-trust architecture support: identity-based
     trust scoring so the same IP from an admin account and an attacker
     are treated differently."

Zero-trust philosophy applied here:

  Traditional CNSL treats every IP identically -- 8 SSH failures from
  admin@corp.com and 8 failures from an unknown attacker both trigger
  the same alert threshold. Zero-trust says: an entity that has
  demonstrated risky behavior (unknown IP, unusual hour, MFA failure,
  cloud risk flag) should be treated with more suspicion -- fewer
  events should be needed to trigger an alert.

How trust scores work:

  Every entity starts at 0.8 (trusted but not implicitly).
  Score ranges:

    0.8 - 1.0   Trusted      -- known entity, good behavior history
    0.5 - 0.8   Moderate     -- some anomalies or unknown elements
    0.2 - 0.5   Suspicious   -- multiple anomalies or risk signals
    0.0 - 0.2   Untrusted    -- active threat signals, treat aggressively

  Score is updated by signals:
    +increase (toward 1.0): successful login from known IP at known hour
    -decrease (toward 0.0): UEBA anomaly, MFA failure, cloud risk flag,
                             unknown IP, unusual hour

  Effective threshold multiplier:
    When detector evaluates whether to fire for an entity with low
    trust, it multiplies the rule's normal threshold by the trust score:

      effective_threshold = ceil(normal_threshold * trust_score)

    Example: cloud.signin_brute_force default = 5 fails
      trust=1.0 -> need 5 fails to alert  (ceil(5 * 1.0) = 5)
      trust=0.5 -> need 3 fails to alert  (ceil(5 * 0.5) = 3)
      trust=0.1 -> need 1 fail  to alert  (ceil(5 * 0.1) = 1)

  Score decay:
    Scores recover toward the initial_score at a rate of
    recovery_per_day_sec per day, so a low-trust entity that goes
    quiet will eventually return to trusted status.

SQLite persistence:
  Table: zt_scores
  Stored as (entity_id, entity_type, score, last_updated, signal_count,
             last_signal)

Config (config.json):
  "zero_trust": {
    "enabled":           true,
    "initial_score":     0.8,
    "min_score":         0.05,
    "recovery_per_day":  0.05,
    "persist":           true,
    "max_entities":      50000,
    "apply_to_threshold": true
  }

API endpoints (added in dashboard.py):
  GET  /api/zero-trust/scores          -- all scored entities
  GET  /api/zero-trust/scores/{entity} -- score detail for one entity
  POST /api/zero-trust/scores/{entity}/reset -- reset entity to initial
  GET  /api/zero-trust/stats           -- aggregate trust statistics
"""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import iso_time, now



# SQLite schema


ZT_SCHEMA = """
CREATE TABLE IF NOT EXISTS zt_scores (
    entity_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL DEFAULT 'ip',
    score         REAL NOT NULL DEFAULT 0.8,
    last_updated  REAL NOT NULL,
    signal_count  INTEGER DEFAULT 0,
    last_signal   TEXT DEFAULT '',
    PRIMARY KEY (entity_id, entity_type)
);

CREATE INDEX IF NOT EXISTS idx_zt_score       ON zt_scores(score ASC);
CREATE INDEX IF NOT EXISTS idx_zt_last_updated ON zt_scores(last_updated DESC);
"""


# Trust signal constants


class TrustSignal:
    """Named trust signal constants with their score deltas."""

    # Positive signals -- increase trust
    KNOWN_IP_LOGIN      = ("known_ip_login",      +0.05)
    NORMAL_HOUR_LOGIN   = ("normal_hour_login",   +0.02)

    # Negative signals -- decrease trust
    UEBA_ANOMALY        = ("ueba_anomaly",        -0.20)
    UNKNOWN_IP_LOGIN    = ("unknown_ip_login",    -0.10)
    UNUSUAL_HOUR_LOGIN  = ("unusual_hour_login",  -0.08)
    MFA_FAILURE         = ("mfa_failure",         -0.25)
    CLOUD_RISK_FLAG     = ("cloud_risk_flag",     -0.30)
    BRUTE_FORCE_FAIL    = ("brute_force_fail",    -0.05)
    IMPOSSIBLE_TRAVEL   = ("impossible_travel",   -0.35)
    BLOCK_APPLIED       = ("block_applied",       -0.40)
    CORRELATION_ALERT   = ("correlation_alert",   -0.15)


# Entity trust record


@dataclass
class EntityTrust:
    """Trust record for a single entity (IP or username)."""
    entity_id:    str
    entity_type:  str                   # "ip" or "user"
    score:        float  = 0.8
    last_updated: float  = field(default_factory=now)
    signal_count: int    = 0
    signal_log:   List[Tuple[float, str, float]] = field(default_factory=list)
    # signal_log entries: (ts, signal_name, delta)

    def trust_label(self) -> str:
        if self.score >= 0.8:
            return "trusted"
        if self.score >= 0.5:
            return "moderate"
        if self.score >= 0.2:
            return "suspicious"
        return "untrusted"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id":    self.entity_id,
            "entity_type":  self.entity_type,
            "score":        round(self.score, 3),
            "label":        self.trust_label(),
            "signal_count": self.signal_count,
            "last_updated": iso_time(self.last_updated),
            "recent_signals": [
                {"ts": iso_time(ts), "signal": sig, "delta": round(delta, 3)}
                for ts, sig, delta in self.signal_log[-10:]
            ],
        }

    def to_db_row(self) -> Dict[str, Any]:
        last_sig = self.signal_log[-1][1] if self.signal_log else ""
        return {
            "entity_id":    self.entity_id,
            "entity_type":  self.entity_type,
            "score":        self.score,
            "last_updated": self.last_updated,
            "signal_count": self.signal_count,
            "last_signal":  last_sig,
        }

    @staticmethod
    def from_db_row(row: Dict[str, Any]) -> "EntityTrust":
        return EntityTrust(
            entity_id    = row["entity_id"],
            entity_type  = row.get("entity_type", "ip"),
            score        = float(row.get("score", 0.8)),
            last_updated = float(row.get("last_updated", now())),
            signal_count = int(row.get("signal_count", 0)),
            signal_log   = [],
        )



# Zero-Trust Engine


class ZeroTrustEngine:
    """
    Per-entity trust scoring for zero-trust detection.

    Usage:
        zt = ZeroTrustEngine(cfg)

        # Apply a signal (updates score in-memory)
        zt.apply_signal("1.2.3.4", "ip", TrustSignal.BRUTE_FORCE_FAIL)

        # Get the current score
        score = zt.get_score("1.2.3.4", "ip")  # e.g. 0.65

        # Use in threshold evaluation:
        # effective_threshold = ceil(normal_threshold * score)
        effective = zt.effective_threshold("1.2.3.4", "ip", normal_threshold=8)
        # -> e.g. 5 (with score 0.65: ceil(8 * 0.65) = 6)

        # Persist to SQLite
        await zt.save_all(store)
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        zt_cfg = cfg.get("zero_trust", {})
        self.enabled           = bool(zt_cfg.get("enabled", True))
        self.initial_score     = float(zt_cfg.get("initial_score", 0.8))
        self.min_score         = float(zt_cfg.get("min_score", 0.05))
        self.recovery_per_day  = float(zt_cfg.get("recovery_per_day", 0.05))
        self.persist           = bool(zt_cfg.get("persist", True))
        self.max_entities      = int(zt_cfg.get("max_entities", 50000))
        self.apply_to_threshold = bool(zt_cfg.get("apply_to_threshold", True))

        self._scores: Dict[Tuple[str, str], EntityTrust] = {}

    
    # Public API
    

    def apply_signal(
        self,
        entity_id:   str,
        entity_type: str,
        signal:      Tuple[str, float],
    ) -> float:
        """
        Apply a trust signal to an entity. Returns the new score.
        signal is a (name, delta) tuple from TrustSignal constants.
        """
        if not self.enabled or not entity_id:
            return self.initial_score

        name, delta = signal
        record = self._get_or_create(entity_id, entity_type)
        t      = now()

        # Apply decay since last update before applying new signal
        self._apply_decay(record, t)

        new_score = max(self.min_score, min(1.0, record.score + delta))
        record.score        = new_score
        record.last_updated = t
        record.signal_count += 1
        record.signal_log.append((t, name, delta))
        # Keep last 50 signals only
        if len(record.signal_log) > 50:
            record.signal_log = record.signal_log[-50:]

        return new_score

    def get_score(self, entity_id: str, entity_type: str = "ip") -> float:
        """Return the current trust score, with decay applied."""
        if not self.enabled or not entity_id:
            return self.initial_score
        key = (entity_id, entity_type)
        if key not in self._scores:
            return self.initial_score
        record = self._scores[key]
        self._apply_decay(record, now())
        return record.score

    def effective_threshold(
        self,
        entity_id:        str,
        entity_type:      str,
        normal_threshold: int,
    ) -> int:
        """
        Return the adjusted detection threshold for this entity.
        Low-trust entities have a lower effective threshold so fewer
        events are needed to trigger an alert.
        """
        if not self.enabled or not self.apply_to_threshold:
            return normal_threshold
        score = self.get_score(entity_id, entity_type)
        return max(1, math.ceil(normal_threshold * score))

    def get_record(
        self, entity_id: str, entity_type: str = "ip"
    ) -> Optional[EntityTrust]:
        key = (entity_id, entity_type)
        if key not in self._scores:
            return None
        record = self._scores[key]
        self._apply_decay(record, now())
        return record

    def get_all(
        self,
        entity_type: Optional[str] = None,
        min_score:   float         = 0.0,
        max_score:   float         = 1.0,
        limit:       int           = 100,
    ) -> List[EntityTrust]:
        """Return all tracked entities sorted by score ascending (lowest trust first)."""
        t = now()
        records = []
        for record in self._scores.values():
            self._apply_decay(record, t)
            if entity_type and record.entity_type != entity_type:
                continue
            if not (min_score <= record.score <= max_score):
                continue
            records.append(record)
        records.sort(key=lambda r: r.score)
        return records[:limit]

    def reset(self, entity_id: str, entity_type: str = "ip") -> bool:
        """Reset entity to initial_score. Returns True if found."""
        key = (entity_id, entity_type)
        if key not in self._scores:
            return False
        record = self._scores[key]
        record.score        = self.initial_score
        record.last_updated = now()
        record.signal_log.append((now(), "manual_reset", 0.0))
        return True

    def stats(self) -> Dict[str, Any]:
        t = now()
        for record in self._scores.values():
            self._apply_decay(record, t)
        scores = [r.score for r in self._scores.values()]
        n = len(scores)
        if n == 0:
            return {"enabled": self.enabled, "total_entities": 0}
        untrusted  = sum(1 for s in scores if s < 0.2)
        suspicious = sum(1 for s in scores if 0.2 <= s < 0.5)
        moderate   = sum(1 for s in scores if 0.5 <= s < 0.8)
        trusted    = sum(1 for s in scores if s >= 0.8)
        return {
            "enabled":          self.enabled,
            "total_entities":   n,
            "trusted":          trusted,
            "moderate":         moderate,
            "suspicious":       suspicious,
            "untrusted":        untrusted,
            "avg_score":        round(sum(scores) / n, 3),
            "min_score_seen":   round(min(scores), 3),
        }

    
    # SQLite persistence
    

    async def load_all(self, store: Any) -> None:
        if not self.persist or not store:
            return
        try:
            rows = await store.db_fetchall(
                "SELECT * FROM zt_scores ORDER BY score ASC LIMIT ?",
                (self.max_entities,),
            )
            for row in rows:
                record = EntityTrust.from_db_row(row)
                self._scores[(record.entity_id, record.entity_type)] = record
        except Exception:
            pass

    async def save_all(self, store: Any) -> None:
        if not self.persist or not store:
            return
        for record in self._scores.values():
            await self._save_record(store, record)

    async def save_record(self, store: Any, record: EntityTrust) -> None:
        if not self.persist or not store:
            return
        await self._save_record(store, record)

    
    # Internal helpers
    

    def _get_or_create(self, entity_id: str, entity_type: str) -> EntityTrust:
        key = (entity_id, entity_type)
        if key not in self._scores:
            if len(self._scores) >= self.max_entities:
                self._evict_oldest()
            self._scores[key] = EntityTrust(
                entity_id   = entity_id,
                entity_type = entity_type,
                score       = self.initial_score,
            )
        return self._scores[key]

    def _apply_decay(self, record: EntityTrust, t: float) -> None:
        """Recover trust toward initial_score based on time elapsed."""
        elapsed_days = (t - record.last_updated) / 86400.0
        if elapsed_days <= 0:
            return
        recovery = elapsed_days * self.recovery_per_day
        if record.score < self.initial_score:
            record.score = min(self.initial_score, record.score + recovery)
        elif record.score > self.initial_score:
            # Artificially high scores also decay toward initial
            record.score = max(self.initial_score, record.score - recovery)
        record.last_updated = t

    def _evict_oldest(self) -> None:
        if not self._scores:
            return
        oldest = min(self._scores, key=lambda k: self._scores[k].last_updated)
        del self._scores[oldest]

    async def _save_record(self, store: Any, record: EntityTrust) -> None:
        try:
            row = record.to_db_row()
            await store.db_execute(
                """
                INSERT INTO zt_scores
                    (entity_id, entity_type, score, last_updated, signal_count, last_signal)
                VALUES
                    (:entity_id, :entity_type, :score, :last_updated, :signal_count, :last_signal)
                ON CONFLICT(entity_id, entity_type) DO UPDATE SET
                    score        = excluded.score,
                    last_updated = excluded.last_updated,
                    signal_count = excluded.signal_count,
                    last_signal  = excluded.last_signal
                """,
                row,
            )
        except Exception:
            pass