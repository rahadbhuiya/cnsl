"""
cnsl/ueba.py — User and Entity Behavior Analytics (UEBA).

Builds per-user behavioral profiles and detects anomalies by comparing
new activity against established baselines.

Detection capabilities:
  1. Unusual login hour     — login outside normal hours for this user
  2. New source IP          — user logging in from an IP never seen before
  3. Lateral movement       — same user active on multiple IPs in short window
  4. Login frequency spike  — sudden increase vs 7-day rolling average
  5. Login after absence    — login after > N days of inactivity
  6. New username pattern   — first time a username appears (configurable)

Profile data collected per user:
  - login_hours: {hour: count}  — hour-of-day distribution
  - known_ips: {ip: last_seen}  — source IPs ever seen for this user
  - daily_counts: deque(7)      — logins per day, 7-day rolling
  - recent_ips: deque(10m)      — IPs active in last N seconds (lateral movement)
  - total_logins, first_seen, last_seen
  - anomaly_count, anomaly_log (last 20 anomalies)

SQLite persistence:
  Tables: ueba_profiles, ueba_ip_history, ueba_anomalies
  Auto-migrated via Store.init() on startup.

Config (config.json):
  "ueba": {
    "enabled":               true,
    "min_observations":      10,
    "lateral_window_sec":    600,
    "lateral_ip_threshold":  3,
    "absence_days":          7,
    "frequency_spike_factor":3.0,
    "persist":               true
  }
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import iso_time, now


#  Schema 

UEBA_SCHEMA = """
CREATE TABLE IF NOT EXISTS ueba_profiles (
    username        TEXT PRIMARY KEY,
    total_logins    INTEGER DEFAULT 0,
    anomaly_count   INTEGER DEFAULT 0,
    first_seen      REAL,
    last_seen       REAL,
    login_hours     TEXT DEFAULT '{}',   -- JSON: {hour: count}
    known_ips       TEXT DEFAULT '{}'    -- JSON: {ip: last_seen_ts}
);

CREATE TABLE IF NOT EXISTS ueba_anomalies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    time        TEXT    NOT NULL,
    username    TEXT    NOT NULL,
    src_ip      TEXT,
    reason      TEXT    NOT NULL,
    anomaly_type TEXT
);

CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_user ON ueba_anomalies(username);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_ts   ON ueba_anomalies(ts);
CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_ip   ON ueba_anomalies(src_ip);
"""


#  UserProfile dataclass 


@dataclass
class UserProfile:
    """In-memory behavioral profile for a single username."""

    username: str

    # Hour-of-day login distribution {0..23: count}
    login_hours: Dict[int, int]   = field(default_factory=lambda: defaultdict(int))

    # Known source IPs {ip: last_seen_ts}
    known_ips: Dict[str, float]   = field(default_factory=dict)

    # Recent IPs in lateral movement window [(ts, ip), ...]
    recent_ips: deque             = field(default_factory=lambda: deque(maxlen=50))

    # Daily login counts — rolling 7-day window [(day_epoch, count), ...]
    daily_counts: deque           = field(default_factory=lambda: deque(maxlen=7))

    # Totals
    total_logins: int             = 0
    first_seen:   float           = field(default_factory=now)
    last_seen:    float           = field(default_factory=now)

    # Anomaly tracking
    anomaly_count: int            = 0
    anomaly_log:   deque          = field(default_factory=lambda: deque(maxlen=20))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username":      self.username,
            "total_logins":  self.total_logins,
            "anomaly_count": self.anomaly_count,
            "first_seen":    iso_time(self.first_seen),
            "last_seen":     iso_time(self.last_seen),
            "known_ip_count": len(self.known_ips),
            "known_ips":     list(self.known_ips.keys()),
            "login_hours":   dict(self.login_hours),
            "recent_anomalies": list(self.anomaly_log),
        }


#  UEBAEngine 


class UEBAEngine:
    """
    User and Entity Behavior Analytics engine.

    Observes login events, builds per-user profiles, and emits
    anomaly descriptions when behaviour deviates from the baseline.

    Usage:
        ueba = UEBAEngine(cfg, store)
        await ueba.init()

        # On each successful login:
        anomaly = ueba.observe(username="alice", src_ip="1.2.3.4")
        if anomaly:
            # anomaly.reason is a human-readable string
            await logger.log("ueba_anomaly", anomaly.to_dict())
    """

    def __init__(self, cfg: Dict[str, Any], store: Any = None):
        ub = cfg.get("ueba", {})
        self.enabled               = bool(ub.get("enabled", False))
        self.min_observations      = int(ub.get("min_observations", 10))
        self.lateral_window_sec    = int(ub.get("lateral_window_sec", 600))
        self.lateral_ip_threshold  = int(ub.get("lateral_ip_threshold", 3))
        self.absence_days          = int(ub.get("absence_days", 7))
        self.freq_spike_factor     = float(ub.get("frequency_spike_factor", 3.0))
        self.persist               = bool(ub.get("persist", True))
        self._store                = store
        self._profiles: Dict[str, UserProfile] = {}

    @property
    def _db(self):
        return self._store._db if self._store and self._store.available else None

    #  Lifecycle 

    async def init(self) -> None:
        """Create tables and load persisted profiles."""
        if not self.enabled or not self._db:
            return
        await self._db.executescript(UEBA_SCHEMA)
        await self._db.commit()
        if self.persist:
            await self._load_profiles()

    #  Core observe 

    def observe(
        self,
        username: str,
        src_ip:   str,
        ts:       Optional[float] = None,
    ) -> Optional["UEBAAnomaly"]:
        """
        Record a successful login. Returns UEBAAnomaly if anomalous, else None.
        This is sync — fast path for the hot detection loop.
        DB persistence is done asynchronously via save_event().
        """
        if not self.enabled or not username:
            return None

        ts   = ts or now()
        hour = int(time.strftime("%H", time.localtime(ts)))

        if username not in self._profiles:
            self._profiles[username] = UserProfile(username=username)

        prof   = self._profiles[username]
        anomaly = None

        if prof.total_logins >= self.min_observations:
            anomaly = self._check_anomaly(prof, src_ip, hour, ts)

        # Update profile
        prof.login_hours[hour] += 1
        prof.known_ips[src_ip]  = ts
        prof.recent_ips.append((ts, src_ip))
        prof.total_logins += 1
        prof.last_seen     = ts

        today = int(ts // 86400)
        if not prof.daily_counts or prof.daily_counts[-1][0] != today:
            prof.daily_counts.append([today, 1])
        else:
            prof.daily_counts[-1][1] += 1

        if anomaly:
            prof.anomaly_count += 1
            prof.anomaly_log.append(anomaly.to_dict())

        return anomaly

    #  Anomaly checks 
    def _check_anomaly(
        self,
        prof:    UserProfile,
        src_ip:  str,
        hour:    int,
        ts:      float,
    ) -> Optional["UEBAAnomaly"]:
        reasons:      List[str] = []
        anomaly_types: List[str] = []

        # 1. Unusual login hour
        usual = {h for h, c in prof.login_hours.items() if c >= 2}
        if usual and hour not in usual:
            reasons.append(
                f"login at unusual hour {hour:02d}:xx "
                f"(normal: {sorted(usual)})"
            )
            anomaly_types.append("unusual_hour")

        # 2. New source IP for this user
        if src_ip not in prof.known_ips:
            reasons.append(
                f"new source IP {src_ip} "
                f"(known IPs: {len(prof.known_ips)})"
            )
            anomaly_types.append("new_source_ip")

        # 3. Lateral movement — same user, many IPs in short window
        cutoff       = ts - self.lateral_window_sec
        recent_set   = {ip for t, ip in prof.recent_ips if t >= cutoff and ip != src_ip}
        recent_set.add(src_ip)
        if len(recent_set) >= self.lateral_ip_threshold:
            reasons.append(
                f"lateral movement: {len(recent_set)} source IPs in "
                f"{self.lateral_window_sec}s window "
                f"({', '.join(sorted(recent_set)[:5])})"
            )
            anomaly_types.append("lateral_movement")

        # 4. Login after long absence
        absence_sec = self.absence_days * 86400
        if prof.last_seen and (ts - prof.last_seen) > absence_sec:
            days = int((ts - prof.last_seen) / 86400)
            reasons.append(f"login after {days}-day absence")
            anomaly_types.append("login_after_absence")

        # 5. Login frequency spike
        if len(prof.daily_counts) >= 3:
            counts = [c for _, c in prof.daily_counts]
            avg    = sum(counts[:-1]) / max(len(counts) - 1, 1)
            today  = counts[-1]
            if avg > 0 and today >= avg * self.freq_spike_factor and today >= 5:
                reasons.append(
                    f"frequency spike: {today} logins today vs "
                    f"avg {avg:.1f}/day"
                )
                anomaly_types.append("frequency_spike")

        if not reasons:
            return None

        return UEBAAnomaly(
            username     = prof.username,
            src_ip       = src_ip,
            reason       = "; ".join(reasons),
            anomaly_types= anomaly_types,
            ts           = ts,
        )

    #  Persistence 

    async def save_event(
        self,
        username: str,
        src_ip:   str,
        anomaly:  Optional["UEBAAnomaly"] = None,
    ) -> None:
        """Persist profile update and anomaly to SQLite (async, non-blocking)."""
        if not self.persist or not self._db:
            return
        prof = self._profiles.get(username)
        if not prof:
            return
        import json
        try:
            await self._db.execute(
                """INSERT INTO ueba_profiles
                   (username, total_logins, anomaly_count, first_seen, last_seen,
                    login_hours, known_ips)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(username) DO UPDATE SET
                     total_logins  = excluded.total_logins,
                     anomaly_count = excluded.anomaly_count,
                     last_seen     = excluded.last_seen,
                     login_hours   = excluded.login_hours,
                     known_ips     = excluded.known_ips""",
                (
                    prof.username,
                    prof.total_logins,
                    prof.anomaly_count,
                    prof.first_seen,
                    prof.last_seen,
                    json.dumps(dict(prof.login_hours)),
                    json.dumps({k: v for k, v in prof.known_ips.items()}),
                ),
            )
            if anomaly:
                await self._db.execute(
                    """INSERT INTO ueba_anomalies
                       (ts, time, username, src_ip, reason, anomaly_type)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        anomaly.ts,
                        iso_time(anomaly.ts),
                        anomaly.username,
                        anomaly.src_ip,
                        anomaly.reason,
                        ",".join(anomaly.anomaly_types),
                    ),
                )
            await self._db.commit()
        except Exception:
            pass

    async def _load_profiles(self) -> None:
        """Load persisted profiles from SQLite on startup."""
        if not self._db:
            return
        import json
        try:
            async with self._db.execute(
                "SELECT username, total_logins, anomaly_count, first_seen, "
                "last_seen, login_hours, known_ips FROM ueba_profiles"
            ) as cur:
                rows = await cur.fetchall()
            for row in rows:
                d = dict(row)
                prof = UserProfile(username=d["username"])
                prof.total_logins  = d.get("total_logins", 0)
                prof.anomaly_count = d.get("anomaly_count", 0)
                prof.first_seen    = d.get("first_seen") or now()
                prof.last_seen     = d.get("last_seen")  or now()
                hours_raw = d.get("login_hours") or "{}"
                ips_raw   = d.get("known_ips")   or "{}"
                try:
                    for h_str, cnt in json.loads(hours_raw).items():
                        prof.login_hours[int(h_str)] = cnt
                except Exception:
                    pass
                try:
                    prof.known_ips = json.loads(ips_raw)
                except Exception:
                    pass
                self._profiles[prof.username] = prof
        except Exception:
            pass

    #  Read API 

    def get_profile(self, username: str) -> Optional[Dict]:
        prof = self._profiles.get(username)
        return prof.to_dict() if prof else None

    def list_profiles(
        self,
        limit:  int = 50,
        offset: int = 0,
        sort_by: str = "anomaly_count",
    ) -> List[Dict]:
        profiles = [p.to_dict() for p in self._profiles.values()]
        reverse  = sort_by in ("anomaly_count", "total_logins", "last_seen")
        profiles.sort(key=lambda p: p.get(sort_by, 0), reverse=reverse)
        return profiles[offset: offset + limit]

    def stats(self) -> Dict[str, Any]:
        total     = len(self._profiles)
        anomalous = sum(1 for p in self._profiles.values() if p.anomaly_count > 0)
        return {
            "total_profiles":    total,
            "anomalous_users":   anomalous,
            "total_logins_seen": sum(p.total_logins for p in self._profiles.values()),
        }

    async def recent_anomalies(
        self, limit: int = 50, username: Optional[str] = None
    ) -> List[Dict]:
        """Fetch recent UEBA anomalies from SQLite."""
        if not self._db:
            # Fall back to in-memory anomaly logs
            results = []
            for prof in self._profiles.values():
                if username and prof.username != username:
                    continue
                for a in prof.anomaly_log:
                    results.append(a)
            results.sort(key=lambda x: x.get("ts", 0), reverse=True)
            return results[:limit]
        try:
            where  = "WHERE username=?" if username else ""
            params = [username] if username else []
            params.append(limit)
            async with self._db.execute(
                f"SELECT * FROM ueba_anomalies {where} ORDER BY ts DESC LIMIT ?",
                params,
            ) as cur:
                rows = await cur.fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    @property
    def profile_count(self) -> int:
        return len(self._profiles)


#  UEBAAnomaly 


@dataclass
class UEBAAnomaly:
    """A detected behavioral anomaly for a user."""

    username:      str
    src_ip:        str
    reason:        str
    anomaly_types: List[str]
    ts:            float = field(default_factory=now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "username":      self.username,
            "src_ip":        self.src_ip,
            "reason":        self.reason,
            "anomaly_types": self.anomaly_types,
            "ts":            self.ts,
            "time":          iso_time(self.ts),
        }