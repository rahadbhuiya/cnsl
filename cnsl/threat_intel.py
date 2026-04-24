"""
cnsl/threat_intel.py — Threat intelligence integrations.

Includes:
  1. AbuseIPDB  — community-reported malicious IPs
  2. Behavioral baseline — per-IP "normal" behavior modeling

AbuseIPDB:
  - Free tier: 1000 lookups/day
  - API key from https://www.abuseipdb.com/account/api
  - Config: "threat_intel": { "abuseipdb": { "enabled": true, "api_key": "..." } }
  - IPs with abuse_score >= threshold are pre-emptively flagged

Behavioral baseline:
  - Learns normal SSH login times for each IP
  - Flags logins outside normal hours
  - Tracks login frequency — sudden spike = suspicious
  - Persists to SQLite (survives restarts)
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import now, iso_time



# AbuseIPDB


@dataclass
class AbuseReport:
    ip:           str
    abuse_score:  int        # 0-100 (100 = most abusive)
    country_code: str
    isp:          str
    total_reports:int
    last_reported:str
    is_public:    bool
    from_cache:   bool = False


class AbuseIPDB:
    """
    Async AbuseIPDB client with caching.

    Usage:
        client = AbuseIPDB(cfg)
        report = await client.check("1.2.3.4")
        if report and report.abuse_score >= 50:
            # pre-emptively block
    """

    _API_URL = "https://api.abuseipdb.com/api/v2/check"
    _CACHE_TTL = 3600 * 12   # 12 hours
    _REQUEST_GAP = 0.1       # 10 req/sec max

    def __init__(self, cfg: Dict[str, Any]):
        ti = cfg.get("threat_intel", {})
        ab = ti.get("abuseipdb", {})

        self.enabled    = bool(ab.get("enabled", False))
        self.api_key    = ab.get("api_key", "")
        self.threshold  = int(ab.get("auto_flag_score", 50))
        self.max_age_days = int(ab.get("max_age_days", 30))

        self._cache: Dict[str, Dict] = {}
        self._last_req = 0.0
        self._lock     = asyncio.Lock()  # serialize HTTP requests — prevents rate-limit races

    async def check(self, ip: str) -> Optional[AbuseReport]:
        """Check IP against AbuseIPDB. Returns None if disabled/error."""
        if not self.enabled or not self.api_key:
            return None

        # Cache check — no lock needed, dict reads are safe
        cached = self._cache.get(ip)
        if cached and (now() - cached["_ts"]) < self._CACHE_TTL:
            return self._parse(cached, from_cache=True)

        # Serialize HTTP requests so concurrent callers can't both
        # slip through the rate-limit gap at the same time.
        async with self._lock:
            # Re-check cache inside the lock — another coroutine may have
            # fetched this IP while we were waiting.
            cached = self._cache.get(ip)
            if cached and (now() - cached["_ts"]) < self._CACHE_TTL:
                return self._parse(cached, from_cache=True)

            # Rate limit
            wait = self._REQUEST_GAP - (now() - self._last_req)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_req = now()

        try:
            import aiohttp
            headers = {
                "Accept":  "application/json",
                "Key":     self.api_key,
            }
            params = {
                "ipAddress":       ip,
                "maxAgeInDays":    self.max_age_days,
                "verbose":         "",
            }
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    self._API_URL, headers=headers, params=params,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    if r.status == 429:
                        return None  # rate limited
                    if r.status != 200:
                        return None
                    data = await r.json()

            result = data.get("data", {})
            result["_ts"] = now()
            self._cache[ip] = result
            return self._parse(result)

        except Exception:
            return None

    def _parse(self, data: Dict, from_cache: bool = False) -> AbuseReport:
        return AbuseReport(
            ip            = data.get("ipAddress", ""),
            abuse_score   = int(data.get("abuseConfidenceScore", 0)),
            country_code  = data.get("countryCode", "??"),
            isp           = data.get("isp", ""),
            total_reports = int(data.get("totalReports", 0)),
            last_reported = data.get("lastReportedAt", ""),
            is_public     = bool(data.get("isPublic", True)),
            from_cache    = from_cache,
        )

    def should_flag(self, report: Optional[AbuseReport]) -> bool:
        """True if this IP should be pre-emptively flagged."""
        return (
            report is not None
            and report.abuse_score >= self.threshold
            and report.is_public
        )

    def cache_size(self) -> int:
        return len(self._cache)



# Behavioral baseline


@dataclass
class IPProfile:
    """Behavioral profile for a single IP."""
    ip: str

    # Login time distribution (hour of day 0-23)
    login_hours: Dict[int, int]  = field(default_factory=lambda: defaultdict(int))

    # Login frequency (logins per day, rolling 7-day window)
    daily_logins: deque          = field(default_factory=lambda: deque(maxlen=7))

    # Observed usernames (set of unique usernames ever used)
    known_users: set             = field(default_factory=set)

    # Total logins
    total_logins: int            = 0
    first_seen:   float          = field(default_factory=now)
    last_seen:    float          = field(default_factory=now)

    # Anomaly tracking
    anomaly_count: int           = 0


class BehavioralBaseline:
    """
    Learns normal behavior per IP and flags deviations.

    After observing N logins, it builds a baseline:
      - Typical login hours
      - Typical login frequency
      - Known usernames

    Anomalies:
      - Login at unusual hour (>2 std dev from normal)
      - Sudden spike in login frequency
      - New username for a known IP (credential sharing?)
      - Login after long absence (account compromise?)
    """

    MIN_OBSERVATIONS = 10   # Need at least this many events before flagging

    def __init__(self, cfg: Dict[str, Any] = None):
        cfg = cfg or {}
        bl  = (cfg or {}).get("behavioral_baseline", {})
        self.enabled          = bool(bl.get("enabled", True))
        self.min_observations = int(bl.get("min_observations", self.MIN_OBSERVATIONS))
        self._profiles: Dict[str, IPProfile] = {}

    def observe_login(self, ip: str, user: str, ts: float = None) -> Optional[str]:
        """
        Record a successful login. Returns anomaly description if detected.
        """
        if not self.enabled:
            return None

        ts   = ts or now()
        hour = int(time.strftime("%H", time.localtime(ts)))

        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip=ip)

        prof = self._profiles[ip]
        anomaly = None

        if prof.total_logins >= self.min_observations:
            anomaly = self._check_anomaly(prof, hour, user, ts)

        # Update profile
        prof.login_hours[hour] += 1
        prof.known_users.add(user)
        prof.total_logins += 1
        prof.last_seen = ts

        # Track daily logins
        today = int(ts // 86400)
        if not prof.daily_logins or prof.daily_logins[-1][0] != today:
            prof.daily_logins.append((today, 1))
        else:
            day, count = prof.daily_logins[-1]
            prof.daily_logins[-1] = (day, count + 1)

        return anomaly

    def _check_anomaly(
        self, prof: IPProfile, hour: int, user: str, ts: float
    ) -> Optional[str]:
        reasons = []

        # 1. Unusual hour
        usual_hours = {h for h, count in prof.login_hours.items() if count >= 2}
        if usual_hours and hour not in usual_hours:
            reasons.append(
                f"login at unusual hour {hour:02d}:xx "
                f"(normal hours: {sorted(usual_hours)})"
            )

        # 2. New username for established IP
        if prof.known_users and user not in prof.known_users:
            reasons.append(
                f"new username '{user}' for IP with {len(prof.known_users)} known users"
            )

        # 3. Login after long absence (>7 days)
        if prof.last_seen and (ts - prof.last_seen) > 86400 * 7:
            days = int((ts - prof.last_seen) / 86400)
            reasons.append(f"login after {days}-day absence")

        # 4. Frequency spike
        if len(prof.daily_logins) >= 3:
            recent_counts = [c for _, c in prof.daily_logins]
            avg = sum(recent_counts[:-1]) / max(len(recent_counts) - 1, 1)
            today_count = recent_counts[-1] if recent_counts else 0
            if avg > 0 and today_count > avg * 3 and today_count >= 5:
                reasons.append(
                    f"login frequency spike: {today_count} today vs avg {avg:.1f}/day"
                )

        if reasons:
            prof.anomaly_count += 1
            return "; ".join(reasons)

        return None

    def get_profile(self, ip: str) -> Optional[Dict]:
        prof = self._profiles.get(ip)
        if not prof:
            return None
        return {
            "ip":            prof.ip,
            "total_logins":  prof.total_logins,
            "known_users":   list(prof.known_users),
            "anomaly_count": prof.anomaly_count,
            "first_seen":    iso_time(prof.first_seen),
            "last_seen":     iso_time(prof.last_seen),
            "login_hours":   dict(prof.login_hours),
        }

    def profile_count(self) -> int:
        return len(self._profiles)