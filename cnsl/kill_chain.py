"""
cnsl/kill_chain.py -- Attack Kill Chain Tracker.

Tracks the progression of each attacker IP through distinct attack
stages and builds a per-IP kill chain graph. This is the intent
graph described in the original CNSL research paper:

    "CNSL: A Correlated Network Security Layer for
     Intent-Based Incident Detection and Response"

How it works:
  Every detection event is mapped to one of seven kill chain stages
  based on the Unified Kill Chain / MITRE ATT&CK framework adapted
  for network-level observability:

    Stage 0  RECONNAISSANCE   -- web scanning, port probing, honeypot hits
    Stage 1  WEAPONIZATION    -- exploit path hits, known-bad feed match
    Stage 2  DELIVERY         -- brute-force credential attempts (SSH/web/DB)
    Stage 3  EXPLOITATION     -- credential breach (success after failures)
    Stage 4  INSTALLATION     -- privilege escalation (sudo/su after login)
    Stage 5  C2               -- persistent reconnection after block
    Stage 6  ACTIONS          -- data exfiltration signals (future)

  For each IP, the tracker records which stages have been observed,
  when each stage was first and last seen, and the event count per
  stage. It also computes a kill chain score (0.0-1.0) reflecting
  how far the attacker has progressed.

  A chain is marked COMPLETE when stages 0, 2, and 3 are all present
  (reconnaissance -> delivery -> exploitation), which is the minimum
  confirmed attack path.

SQLite persistence:
  Tables: kc_chains, kc_stages
  Auto-migrated via Store.init() when kill_chain is passed in.

Config (config.json):
  "kill_chain": {
    "enabled":          true,
    "max_chains":       5000,
    "stage_ttl_sec":    86400,
    "persist":          true
  }

API endpoints (added in dashboard.py):
  GET /api/kill-chain              -- all active chains summary
  GET /api/kill-chain/{ip}         -- full chain detail for one IP
  GET /api/kill-chain/stats        -- aggregate stage distribution
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import iso_time, now



# Kill chain stage definitions


class KCStage:
    RECONNAISSANCE = 0
    WEAPONIZATION  = 1
    DELIVERY       = 2
    EXPLOITATION   = 3
    INSTALLATION   = 4
    C2             = 5
    ACTIONS        = 6

STAGE_NAMES: Dict[int, str] = {
    KCStage.RECONNAISSANCE: "Reconnaissance",
    KCStage.WEAPONIZATION:  "Weaponization",
    KCStage.DELIVERY:       "Delivery",
    KCStage.EXPLOITATION:   "Exploitation",
    KCStage.INSTALLATION:   "Installation",
    KCStage.C2:             "C2",
    KCStage.ACTIONS:        "Actions on Objectives",
}

STAGE_DESCRIPTIONS: Dict[int, str] = {
    KCStage.RECONNAISSANCE: "Web scanning, port probing, honeypot port hits",
    KCStage.WEAPONIZATION:  "Exploit path hits, known-bad threat feed match",
    KCStage.DELIVERY:       "Brute-force credential attempts (SSH, web, DB)",
    KCStage.EXPLOITATION:   "Credential breach: login success after repeated failures",
    KCStage.INSTALLATION:   "Privilege escalation: sudo/su failure after SSH login",
    KCStage.C2:             "Persistent reconnection after block or rate limit",
    KCStage.ACTIONS:        "Post-compromise data access or lateral movement",
}

# Mapping from event kind to kill chain stage
_KIND_TO_STAGE: Dict[str, int] = {
    # Reconnaissance
    "WEB_SCAN":            KCStage.RECONNAISSANCE,
    "FW_HONEYPOT_PORT":    KCStage.RECONNAISSANCE,
    "FW_BLOCK":            KCStage.RECONNAISSANCE,
    "NET_HINT":            KCStage.RECONNAISSANCE,

    # Weaponization
    "WEB_EXPLOIT_ATTEMPT": KCStage.WEAPONIZATION,
    "THREAT_FEED_HIT":     KCStage.WEAPONIZATION,

    # Delivery
    "SSH_FAIL":            KCStage.DELIVERY,
    "WEB_AUTH_FAIL":       KCStage.DELIVERY,
    "DB_AUTH_FAIL":        KCStage.DELIVERY,

    # Exploitation
    "SSH_SUCCESS":         KCStage.EXPLOITATION,

    # Installation
    "SUDO_FAIL":           KCStage.INSTALLATION,
    "SU_FAIL":             KCStage.INSTALLATION,

    # C2 (repeat-offender signals handled via correlation rule name)
    # handled separately in update_from_correlation()
}

# Correlation rule names that map to C2 stage
_CORRELATION_C2_RULES = {
    "persistent_recon",
    "multi_service_brute_force",
}



# SQLite schema


KC_SCHEMA = """
CREATE TABLE IF NOT EXISTS kc_chains (
    ip              TEXT PRIMARY KEY,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    stage_mask      INTEGER DEFAULT 0,
    max_stage       INTEGER DEFAULT 0,
    score           REAL DEFAULT 0.0,
    complete        INTEGER DEFAULT 0,
    event_count     INTEGER DEFAULT 0,
    geo_country     TEXT,
    geo_city        TEXT,
    stage_data      TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_kc_chains_score     ON kc_chains(score DESC);
CREATE INDEX IF NOT EXISTS idx_kc_chains_last_seen ON kc_chains(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_kc_chains_complete  ON kc_chains(complete);
"""



# Data models


@dataclass
class StageRecord:
    """Observation record for a single kill chain stage."""
    stage:       int
    first_seen:  float
    last_seen:   float
    count:       int       = 0
    event_kinds: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage":       self.stage,
            "name":        STAGE_NAMES[self.stage],
            "description": STAGE_DESCRIPTIONS[self.stage],
            "first_seen":  iso_time(self.first_seen),
            "last_seen":   iso_time(self.last_seen),
            "count":       self.count,
            "event_kinds": list(set(self.event_kinds[-20:])),
        }


@dataclass
class KillChain:
    """
    Full kill chain record for one source IP.

    stage_mask is a bitmask of observed stages (bit N = stage N seen).
    score is 0.0-1.0 representing how far the attacker has progressed.
    complete is True when the minimum confirmed attack path is present.
    """
    ip:          str
    first_seen:  float                    = field(default_factory=now)
    last_seen:   float                    = field(default_factory=now)
    stages:      Dict[int, StageRecord]   = field(default_factory=dict)
    stage_mask:  int                      = 0
    max_stage:   int                      = -1
    score:       float                    = 0.0
    complete:    bool                     = False
    event_count: int                      = 0
    geo_country: Optional[str]            = None
    geo_city:    Optional[str]            = None

    # Minimum stages required to mark chain complete
    _COMPLETE_STAGES = {
        KCStage.RECONNAISSANCE,
        KCStage.DELIVERY,
        KCStage.EXPLOITATION,
    }

    def record_stage(self, stage: int, kind: str) -> None:
        t = now()
        if stage not in self.stages:
            self.stages[stage] = StageRecord(
                stage      = stage,
                first_seen = t,
                last_seen  = t,
                count      = 1,
                event_kinds= [kind],
            )
        else:
            sr = self.stages[stage]
            sr.last_seen = t
            sr.count    += 1
            sr.event_kinds.append(kind)

        self.stage_mask  |= (1 << stage)
        self.max_stage    = max(self.max_stage, stage)
        self.last_seen    = t
        self.event_count += 1
        self._recompute()

    def _recompute(self) -> None:
        """Recompute score and complete flag."""
        observed = set(self.stages.keys())
        # Score = highest consecutive stage reached / total stages, weighted
        # by whether the minimum kill path is complete
        highest = self.max_stage if self.max_stage >= 0 else 0
        self.score    = round((highest + 1) / len(STAGE_NAMES), 3)
        self.complete = self._COMPLETE_STAGES.issubset(observed)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip":          self.ip,
            "first_seen":  iso_time(self.first_seen),
            "last_seen":   iso_time(self.last_seen),
            "stage_mask":  self.stage_mask,
            "max_stage":   self.max_stage,
            "max_stage_name": STAGE_NAMES.get(self.max_stage, "None"),
            "score":       self.score,
            "complete":    self.complete,
            "event_count": self.event_count,
            "geo_country": self.geo_country,
            "geo_city":    self.geo_city,
            "stages": {
                str(s): sr.to_dict()
                for s, sr in sorted(self.stages.items())
            },
        }

    def to_db_row(self) -> Dict[str, Any]:
        return {
            "ip":          self.ip,
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
            "stage_mask":  self.stage_mask,
            "max_stage":   self.max_stage,
            "score":       self.score,
            "complete":    1 if self.complete else 0,
            "event_count": self.event_count,
            "geo_country": self.geo_country or "",
            "geo_city":    self.geo_city or "",
            "stage_data":  json.dumps(
                {str(s): sr.to_dict() for s, sr in self.stages.items()}
            ),
        }



# Kill Chain Tracker (main class)


class KillChainTracker:
    """
    Tracks attack kill chain progression for every source IP.

    Usage:
        tracker = KillChainTracker(cfg)
        tracker.update(event)
        chain = tracker.get_chain("1.2.3.4")
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        kc_cfg = cfg.get("kill_chain", {})
        self.enabled    = bool(kc_cfg.get("enabled", True))
        self.max_chains = int(kc_cfg.get("max_chains", 5000))
        self.ttl_sec    = int(kc_cfg.get("stage_ttl_sec", 86400))
        self.persist    = bool(kc_cfg.get("persist", True))

        self._chains: Dict[str, KillChain] = {}

    
    # Public API
    

    def update(
        self,
        ip:    str,
        kind:  str,
        geo:   Optional[Dict[str, Any]] = None,
    ) -> Optional[KillChain]:
        """
        Map an event kind to a kill chain stage and update the IP chain.
        Returns the updated KillChain, or None if kind is not mapped.
        """
        if not self.enabled or not ip:
            return None

        stage = _KIND_TO_STAGE.get(kind)
        if stage is None:
            return None

        chain = self._get_or_create(ip, geo)
        chain.record_stage(stage, kind)
        return chain

    def update_from_correlation(
        self,
        ip:        str,
        rule_name: str,
        geo:       Optional[Dict[str, Any]] = None,
    ) -> Optional[KillChain]:
        """
        Map a correlation rule name to a kill chain stage and update.
        """
        if not self.enabled or not ip:
            return None

        if rule_name in _CORRELATION_C2_RULES:
            stage = KCStage.C2
        elif rule_name == "privilege_escalation":
            stage = KCStage.INSTALLATION
        elif rule_name in ("web_recon_then_ssh", "honeypot_then_ssh"):
            stage = KCStage.RECONNAISSANCE
        else:
            return None

        chain = self._get_or_create(ip, geo)
        chain.record_stage(stage, f"correlation:{rule_name}")
        return chain

    def get_chain(self, ip: str) -> Optional[KillChain]:
        """Return the kill chain for an IP, or None if not seen."""
        return self._chains.get(ip)

    def get_all(
        self,
        limit:         int  = 100,
        min_score:     float = 0.0,
        complete_only: bool  = False,
    ) -> List[KillChain]:
        """Return chains sorted by score descending."""
        chains = list(self._chains.values())
        if complete_only:
            chains = [c for c in chains if c.complete]
        if min_score > 0.0:
            chains = [c for c in chains if c.score >= min_score]
        chains.sort(key=lambda c: (c.score, c.last_seen), reverse=True)
        return chains[:limit]

    def stats(self) -> Dict[str, Any]:
        """Return aggregate statistics across all chains."""
        chains      = list(self._chains.values())
        total       = len(chains)
        complete    = sum(1 for c in chains if c.complete)
        stage_dist: Dict[str, int] = defaultdict(int)
        for c in chains:
            for s in c.stages:
                stage_dist[STAGE_NAMES[s]] += 1

        return {
            "total_chains":    total,
            "complete_chains": complete,
            "stage_distribution": dict(stage_dist),
            "avg_score": round(
                sum(c.score for c in chains) / total, 3
            ) if total else 0.0,
        }

    def prune_expired(self) -> int:
        """Remove chains older than ttl_sec. Returns count removed."""
        cutoff  = now() - self.ttl_sec
        expired = [ip for ip, c in self._chains.items() if c.last_seen < cutoff]
        for ip in expired:
            del self._chains[ip]
        return len(expired)

    
    # SQLite persistence helpers (called by Store)
    

    async def save_all(self, store: Any) -> None:
        """Persist all chains to SQLite via Store."""
        if not self.persist or not store:
            return
        for chain in self._chains.values():
            await self._save_chain(store, chain)

    async def save_chain(self, store: Any, chain: KillChain) -> None:
        """Persist one chain to SQLite."""
        if not self.persist or not store:
            return
        await self._save_chain(store, chain)

    async def load_all(self, store: Any) -> None:
        """Load persisted chains from SQLite on startup."""
        if not self.persist or not store:
            return
        try:
            rows = await store.db_fetchall(
                "SELECT * FROM kc_chains ORDER BY score DESC LIMIT ?",
                (self.max_chains,),
            )
            for row in rows:
                chain = self._row_to_chain(row)
                if chain:
                    self._chains[chain.ip] = chain
        except Exception:
            pass

    
    # Internal helpers
    

    def _get_or_create(
        self,
        ip:  str,
        geo: Optional[Dict[str, Any]],
    ) -> KillChain:
        if ip not in self._chains:
            if len(self._chains) >= self.max_chains:
                self._evict_oldest()
            self._chains[ip] = KillChain(ip=ip)

        chain = self._chains[ip]
        if geo:
            chain.geo_country = chain.geo_country or geo.get("country")
            chain.geo_city    = chain.geo_city    or geo.get("city")
        return chain

    def _evict_oldest(self) -> None:
        if not self._chains:
            return
        oldest = min(self._chains, key=lambda ip: self._chains[ip].last_seen)
        del self._chains[oldest]

    async def _save_chain(self, store: Any, chain: KillChain) -> None:
        try:
            row = chain.to_db_row()
            await store.db_execute(
                """
                INSERT INTO kc_chains
                    (ip, first_seen, last_seen, stage_mask, max_stage,
                     score, complete, event_count, geo_country, geo_city, stage_data)
                VALUES
                    (:ip, :first_seen, :last_seen, :stage_mask, :max_stage,
                     :score, :complete, :event_count, :geo_country, :geo_city, :stage_data)
                ON CONFLICT(ip) DO UPDATE SET
                    last_seen   = excluded.last_seen,
                    stage_mask  = excluded.stage_mask,
                    max_stage   = excluded.max_stage,
                    score       = excluded.score,
                    complete    = excluded.complete,
                    event_count = excluded.event_count,
                    geo_country = excluded.geo_country,
                    geo_city    = excluded.geo_city,
                    stage_data  = excluded.stage_data
                """,
                row,
            )
        except Exception:
            pass

    @staticmethod
    def _row_to_chain(row: Any) -> Optional[KillChain]:
        try:
            stage_data = json.loads(row["stage_data"] or "{}")
            stages: Dict[int, StageRecord] = {}
            for s_str, sd in stage_data.items():
                s = int(s_str)
                stages[s] = StageRecord(
                    stage       = s,
                    first_seen  = time.mktime(
                        time.strptime(sd["first_seen"], "%Y-%m-%dT%H:%M:%SZ")
                    ),
                    last_seen   = time.mktime(
                        time.strptime(sd["last_seen"], "%Y-%m-%dT%H:%M:%SZ")
                    ),
                    count       = sd.get("count", 0),
                    event_kinds = sd.get("event_kinds", []),
                )
            return KillChain(
                ip          = row["ip"],
                first_seen  = row["first_seen"],
                last_seen   = row["last_seen"],
                stages      = stages,
                stage_mask  = row["stage_mask"],
                max_stage   = row["max_stage"],
                score       = row["score"],
                complete    = bool(row["complete"]),
                event_count = row["event_count"],
                geo_country = row.get("geo_country") or None,
                geo_city    = row.get("geo_city")    or None,
            )
        except Exception:
            return None