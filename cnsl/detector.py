"""
cnsl/detector.py — Stateful, per-IP threat detection.

Detection rules (in increasing severity):

  MEDIUM — Brute-force attempt
    * >= fails_threshold failures from one IP within fails_window_sec

  MEDIUM — Credential stuffing
    * >= unique_users_threshold distinct usernames tried from one IP

  HIGH — Credential breach
    * SSH success from an IP that had >= success_after_fails_threshold
      recent failures (stolen/guessed credentials)

Per-IP cooldown prevents alert storms.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional

from .blocker import Blocker
from .config import safe_int
from .logger import JsonLogger
from .models import Detection, Event, EventKind, Severity, iso_time, now

if TYPE_CHECKING:
    from .geoip import GeoIP
    from .metrics import Metrics
    from .notify import Notifier
    from .store import Store


# Per-IP sliding-window state


@dataclass
class IPState:
    fails:           deque = field(default_factory=deque)
    users:           deque = field(default_factory=deque)
    last_success:    float = 0.0
    last_incident:   float = 0.0
    total_fails:     int   = 0
    total_incidents: int   = 0


def _prune(dq: deque, window_sec: int, t: float) -> None:
    cutoff = t - window_sec
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _unique_users(dq: deque) -> int:
    return len({u for _, u in dq if u})



# Detector


class Detector:
    def __init__(
        self,
        cfg: Dict,
        logger: JsonLogger,
        blocker: Blocker,
        geoip:   Optional["GeoIP"]    = None,
        store:   Optional["Store"]    = None,
        metrics: Optional["Metrics"]  = None,
        notifier:Optional["Notifier"] = None,
    ):
        th = cfg["thresholds"]
        self.window_sec       = safe_int(th.get("fails_window_sec"),             60)
        self.fails_threshold  = safe_int(th.get("fails_threshold"),               8)
        self.user_threshold   = safe_int(th.get("unique_users_threshold"),        4)
        self.breach_threshold = safe_int(th.get("success_after_fails_threshold"), 5)
        self.cooldown_sec     = safe_int(th.get("incident_cooldown_sec"),       120)

        self.log_hints = bool(cfg.get("logging", {}).get("log_net_hints", False))

        self.logger   = logger
        self.blocker  = blocker
        self.geoip    = geoip
        self.store    = store
        self.metrics  = metrics
        self.notifier = notifier

        self._state: Dict[str, IPState] = defaultdict(IPState)

    # Public 

    async def handle(self, ev: Event) -> None:
        if self.metrics:
            self.metrics.inc_event()

        if ev.kind == EventKind.NET_HINT:
            if self.log_hints:
                await self.logger.log("event_net_hint", ev.to_dict())
            return

        if ev.kind not in (EventKind.SSH_FAIL, EventKind.SSH_SUCCESS):
            return

        await self.logger.log("event_auth", ev.to_dict())

        ip = ev.src_ip
        if not ip:
            return

        st = self._state[ip]
        t  = ev.ts
        _prune(st.fails, self.window_sec, t)
        _prune(st.users, self.window_sec, t)

        if ev.kind == EventKind.SSH_FAIL:
            st.fails.append((t, 1))
            st.total_fails += 1
            if ev.user:
                st.users.append((t, ev.user))
            if self.metrics:
                geo = self.geoip.get_cached(ip) if self.geoip else None
                country = geo.get("country", "") if geo else ""
                self.metrics.inc_ssh_fail(ip, country)
            await self._evaluate(ip, st, t, trigger="fail")

        elif ev.kind == EventKind.SSH_SUCCESS:
            st.last_success = t
            await self._evaluate(ip, st, t, trigger="success")

    def get_stats(self) -> List[Dict]:
        result = []
        t = now()
        for ip, st in self._state.items():
            _prune(st.fails, self.window_sec, t)
            _prune(st.users, self.window_sec, t)
            geo = self.geoip.get_cached(ip) if self.geoip else None
            result.append({
                "ip":              ip,
                "fails_in_window": len(st.fails),
                "unique_users":    _unique_users(st.users),
                "total_fails":     st.total_fails,
                "total_incidents": st.total_incidents,
                "last_incident":   iso_time(st.last_incident) if st.last_incident else None,
                "is_blocked":      self.blocker.is_blocked(ip),
                "country":         geo.get("country") if geo else None,
                "flag":            geo.get("flag") if geo else None,
            })
        return sorted(result, key=lambda x: x["total_fails"], reverse=True)

    # Private 

    async def _evaluate(self, ip: str, st: IPState, t: float, trigger: str) -> None:
        _prune(st.fails, self.window_sec, t)
        _prune(st.users, self.window_sec, t)

        fail_count = len(st.fails)
        uniq_users = _unique_users(st.users)

        if st.last_incident and (t - st.last_incident) < self.cooldown_sec:
            return

        sev: Optional[str] = None
        reasons: List[str] = []

        if fail_count >= self.fails_threshold:
            sev = Severity.MEDIUM
            reasons.append(
                f"brute_force: {fail_count} fails in {self.window_sec}s "
                f"(threshold={self.fails_threshold})"
            )

        if uniq_users >= self.user_threshold:
            sev = Severity.MEDIUM
            reasons.append(
                f"credential_stuffing: {uniq_users} unique users in {self.window_sec}s "
                f"(threshold={self.user_threshold})"
            )

        if trigger == "success" and fail_count >= self.breach_threshold:
            sev = Severity.HIGH
            reasons.append(
                f"credential_breach: success after {fail_count} fails "
                f"(threshold={self.breach_threshold})"
            )

        if sev is None:
            return

        st.last_incident   = t
        st.total_incidents += 1

        detection = Detection(
            src_ip=ip, severity=sev, reasons=reasons,
            fail_count=fail_count, uniq_users=uniq_users,
            window_sec=self.window_sec,
        )

        # GeoIP enrichment
        geo: Optional[Dict] = None
        if self.geoip:
            try:
                geo = await self.geoip.lookup(ip)
            except Exception:
                pass

        await self.logger.log("incident", {**detection.to_dict(), "geo": geo or {}})

        plan = _response_plan(sev, ip)
        await self.logger.log("response_plan", {"ip": ip, "severity": sev, "plan": plan})

        # Update metrics
        if self.metrics:
            self.metrics.inc_incident(sev)

        # Persist to SQLite
        if self.store:
            try:
                await self.store.save_incident(detection, geo)
            except Exception:
                pass

        # Send notifications
        if self.notifier:
            try:
                await self.notifier.send(detection, geo)
            except Exception:
                pass

        # Block if HIGH
        if sev == Severity.HIGH:
            blocked = await self.blocker.block_ip(ip, reason="; ".join(reasons))
            if blocked and self.metrics:
                self.metrics.inc_block()
            if blocked and self.store:
                try:
                    unblock_at = now() + self.blocker.block_duration_sec
                    await self.store.save_block(
                        ip, unblock_at,
                        reason="; ".join(reasons),
                        dry_run=self.blocker.dry_run,
                    )
                except Exception:
                    pass



# Response plan


def _response_plan(severity: str, ip: str) -> List[str]:
    if severity == Severity.HIGH:
        return [
            f"[AUTO] TEMP-BLOCK {ip}",
            "[MANUAL] Audit successful session — check what was accessed",
            "[MANUAL] Rotate SSH credentials / keys if breach confirmed",
            "[MANUAL] Review open ports and firewall rules",
        ]
    return [
        f"[PLAN] Consider fail2ban / rate-limiting for {ip}",
        "[PLAN] Increase monitoring for next 15-30 minutes",
        "[PLAN] Check if IP belongs to a known scanner (Shodan, etc.)",
    ]