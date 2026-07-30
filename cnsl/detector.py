"""
cnsl/detector.py — Stateful, per-IP threat detection engine.

Detection pipeline per event:
  1. Route event by kind (SSH, web, DB, firewall, syslog)
  2. Update per-IP sliding-window state
  3. Country-based block check (if enabled, fires before thresholds)
  4. Evaluate detection rules
  5. AbuseIPDB pre-check for known-bad IPs
  6. Enrich with GeoIP
  7. Correlate with cross-source rules (Phase 2)
  8. Check behavioral baseline (Phase 2)
  9. Log incident, persist, notify
  10. Block if HIGH severity

Detection rules:
  SSH:
    MEDIUM  brute_force          >= N fails in T seconds
    MEDIUM  credential_stuffing  >= N distinct usernames
    HIGH    credential_breach    success after >= N fails

  Web (Phase 2):
    MEDIUM  web_scan_flood       >= N 404/scan events
    MEDIUM  web_auth_flood       >= N 401/403 events
    MEDIUM  web_exploit          any exploit-path hit

  Database (Phase 2):
    MEDIUM  db_brute_force       >= N DB auth failures

  Firewall (Phase 2):
    HIGH    honeypot_port        hit on never-legitimate port

  Country-based (Phase 3):
    HIGH    country_block        IP from a country in blocked_countries list

  Cross-source (Phase 2, via Correlator):
    HIGH    web_recon_then_ssh
    HIGH    multi_service_brute_force
    HIGH    honeypot_then_ssh
    HIGH    privilege_escalation
    MEDIUM  web_auth_flood
    MEDIUM  persistent_recon
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, List, Optional, Set

from .blocker import Blocker
from .config  import safe_int, get_thresholds, get_country_block_cfg
from .logger  import JsonLogger
from .models  import Detection, Event, EventKind, Severity, iso_time, now
from .rules   import RuleEngine

if TYPE_CHECKING:
    from .correlator    import Correlator, CorrelationAlert
    from .geoip         import GeoIP
    from .metrics       import Metrics
    from .notify        import Notifier
    from .redis_sync    import RedisSync
    from .store         import Store
    from .threat_intel  import AbuseIPDB, BehavioralBaseline



# Event kinds handled by this detector


# SSH
_SSH_KINDS: Set[str] = {EventKind.SSH_FAIL, EventKind.SSH_SUCCESS}

# Phase 2 multi-log kinds
_WEB_KINDS: Set[str]   = {"WEB_SCAN", "WEB_AUTH_FAIL", "WEB_EXPLOIT_ATTEMPT"}
_DB_KINDS: Set[str]    = {"DB_AUTH_FAIL"}
_FW_KINDS: Set[str]    = {"FW_BLOCK", "FW_HONEYPOT_PORT"}
_SYS_KINDS: Set[str]   = {"SUDO_FAIL", "SU_FAIL"}

# Cloud identity kinds
_CLOUD_KINDS: Set[str] = {
    "CLOUD_SIGNIN_FAIL",
    "CLOUD_SIGNIN_SUCCESS",
    "CLOUD_MFA_FAIL",
    "CLOUD_RISKY_SIGNIN",
    "CLOUD_IMPOSSIBLE_TRAVEL",
}

# OT/ICS kinds
_OT_KINDS: Set[str] = {
    "OT_MODBUS_SCAN",
    "OT_MODBUS_WRITE",
    "OT_MODBUS_EXCEPTION",
    "OT_DNP3_UNSOLICITED",
    "OT_DNP3_AUTH_FAIL",
    "OT_SCADA_ALARM",
    "OT_UNAUTHORIZED_CMD",
}

# Wazuh/OSSEC HIDS integration
_WAZUH_KINDS: Set[str] = {"WAZUH_ALERT"}

_ALL_HANDLED: Set[str] = (
    _SSH_KINDS | _WEB_KINDS | _DB_KINDS | _FW_KINDS | _SYS_KINDS | _CLOUD_KINDS | _OT_KINDS
    | _WAZUH_KINDS
)



# Per-IP sliding-window state


@dataclass
class IPState:
    # SSH
    fails:            deque = field(default_factory=deque)  # (ts, 1)
    users:            deque = field(default_factory=deque)  # (ts, username)
    last_success:     float = 0.0

    # Web (Phase 2)
    web_scans:        deque = field(default_factory=deque)  # (ts, 1)
    web_auth_fails:   deque = field(default_factory=deque)
    web_exploits:     deque = field(default_factory=deque)

    # DB (Phase 2)
    db_fails:         deque = field(default_factory=deque)

    # Incident tracking
    last_incident:    float = 0.0
    total_fails:      int   = 0
    total_incidents:  int   = 0
    incident_times:   deque = field(default_factory=lambda: deque(maxlen=50))


def _prune(dq: deque, window_sec: int, t: float) -> None:
    cutoff = t - window_sec
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _prune_all(st: IPState, window_sec: int, t: float) -> None:
    _prune(st.fails,          window_sec, t)
    _prune(st.users,          window_sec, t)
    _prune(st.web_scans,      window_sec, t)
    _prune(st.web_auth_fails, window_sec, t)
    _prune(st.web_exploits,   window_sec, t)
    _prune(st.db_fails,       window_sec, t)


def _unique_users(dq: deque) -> int:
    return len({u for _, u in dq if u})


def _is_repeat_offender(st: IPState, threshold: int, window_sec: int, t: float) -> bool:
    """True if this IP has had many incidents recently — escalate to HIGH."""
    cutoff  = t - window_sec
    recent  = sum(1 for ts in st.incident_times if ts > cutoff)
    return recent >= threshold



# Detector


class Detector:
    def __init__(
        self,
        cfg:          Dict,
        logger:       JsonLogger,
        blocker:      Blocker,
        geoip:        Optional["GeoIP"]              = None,
        store:        Optional["Store"]              = None,
        metrics:      Optional["Metrics"]            = None,
        notifier:     Optional["Notifier"]           = None,
        correlator:   Optional["Correlator"]         = None,
        abuseipdb:    Optional["AbuseIPDB"]          = None,
        baseline:     Optional["BehavioralBaseline"] = None,
        redis_sync:   Optional["RedisSync"]          = None,
        case_manager: Optional["CaseManager"]        = None,
        threat_feed:  Optional["ThreatFeed"]         = None,
        ueba:         Optional["UEBAEngine"]         = None,
        kill_chain:   Optional[Any]                  = None,
        pattern_learner: Optional[Any]                 = None,
        siem_router:     Optional[Any]                 = None,
        federation:      Optional[Any]                 = None,
        cloud_identity:  Optional[Any]                 = None,
        zero_trust:      Optional[Any]                 = None,
    ):
        # Rule engine — all thresholds are read from here at evaluation time
        self.rules = RuleEngine(cfg)

        th = get_thresholds(cfg)

        # Fallback window (used for pruning state — RuleEngine has per-rule windows)
        self.window_sec       = safe_int(th.get("fails_window_sec"), 60)
        self.cooldown_sec     = safe_int(th.get("incident_cooldown_sec"), 120)

        # Kept for backward compat (correlator, baseline still read these)
        self.fails_threshold  = self.rules.threshold("ssh.brute_force",          8)
        self.user_threshold   = self.rules.threshold("ssh.credential_stuffing",  4)
        self.breach_threshold = self.rules.threshold("ssh.credential_breach",    5)
        self.web_scan_threshold  = self.rules.threshold("web.scan_flood",        20)
        self.web_auth_threshold  = self.rules.threshold("web.auth_flood",        15)
        self.db_fail_threshold   = self.rules.threshold("db.brute_force",         5)

        # Repeat offender escalation — now driven by net.repeat_offender rule
        ac = cfg.get("actions", {})
        # Keep for backward compat with correlator/baseline that may read these
        self.repeat_threshold = self.rules.threshold("net.repeat_offender", 3)
        self.repeat_window    = safe_int(ac.get("repeat_offender_window_sec"), 3600)

        # Country-based blocking
        cb = get_country_block_cfg(cfg)
        self.country_block_enabled   = bool(cb.get("enabled", False))
        self.blocked_countries: Set[str] = set(
            c.upper() for c in cb.get("countries", []) if isinstance(c, str)
        )
        self.country_block_allowlist: Set[str] = set(cb.get("allowlist", []))

        # Logging flags
        lg = cfg.get("logging", {})
        self.log_hints        = bool(lg.get("log_net_hints",    False))
        self.log_correlations = bool(lg.get("log_correlations", True))
        self.log_baseline     = bool(lg.get("log_baseline",     True))

        # Dependencies
        self.logger       = logger
        self.blocker      = blocker
        self.geoip        = geoip
        self.store        = store
        self.metrics      = metrics
        self.notifier     = notifier
        self.correlator   = correlator
        self.abuseipdb    = abuseipdb
        self.baseline     = baseline
        self.redis_sync   = redis_sync
        self.case_manager    = case_manager
        self.threat_feed     = threat_feed
        self.ueba            = ueba
        self.kill_chain      = kill_chain
        self.pattern_learner = pattern_learner
        self.siem_router     = siem_router
        self.federation       = federation
        self.cloud_identity  = cloud_identity
        self.zero_trust      = zero_trust

        self._state: Dict[str, IPState] = defaultdict(IPState)

    #  Public: event ingestion 

    def _zt_threshold(self, entity_id: str, entity_type: str,
                      normal_threshold: int) -> int:
        """
        Return the zero-trust adjusted threshold for this entity.
        If zero_trust is disabled or not wired, returns normal_threshold.
        """
        if self.zero_trust:
            try:
                return self.zero_trust.effective_threshold(
                    entity_id, entity_type, normal_threshold)
            except Exception:
                pass
        return normal_threshold

    def _kc_update(self, ip: str, kind: str, geo: Optional[Dict] = None,
                  severity: str = "LOW") -> None:
        """
        Update local kill chain AND broadcast the signal to federated
        peer nodes (no-op if federation is disabled or unavailable).
        This is the single hook point for every kill-chain-relevant
        event so federation never falls out of sync with local tracking.
        """
        if self.kill_chain:
            try:
                self.kill_chain.update(ip, kind, geo=geo)
            except Exception:
                pass
        if self.federation:
            try:
                asyncio.ensure_future(self.federation.publish(ip, kind, severity))
            except Exception:
                pass

    async def handle(self, ev: Event) -> None:
        """Main entry point — route event to the appropriate handler."""
        if self.metrics:
            self.metrics.inc_event()

        # Pass net hints to correlator for context, but don't run full detection
        if ev.kind == EventKind.NET_HINT:
            if self.log_hints:
                await self.logger.log("event_net_hint", ev.to_dict())
            if self.correlator and ev.src_ip:
                self.correlator.ingest(ev)
            return

        if ev.kind not in _ALL_HANDLED:
            return

        ip = ev.src_ip
        if not ip:
            return

        # Log all auth/multi-log events
        await self.logger.log("event_auth", ev.to_dict())

        # Pattern learner -- record every event for sequence tracking
        if self.pattern_learner:
            try:
                self.pattern_learner.observe_event(ev)
            except Exception:
                pass

        # Threat feed check -- known-bad IPs blocked before any threshold
        if self.threat_feed and self.threat_feed.enabled and ip not in self.country_block_allowlist:
            await self._check_threat_feed(ip, ev)

        # Country-based blocking — check before threshold evaluation
        if self.country_block_enabled and self.blocked_countries and ip not in self.country_block_allowlist:
            await self._check_country_block(ip, ev)

        st = self._state[ip]
        t  = ev.ts
        _prune_all(st, self.window_sec, t)

        #  Route by kind 

        if ev.kind == EventKind.SSH_FAIL:
            await self._on_ssh_fail(ip, ev, st, t)

        elif ev.kind == EventKind.SSH_SUCCESS:
            await self._on_ssh_success(ip, ev, st, t)

        elif ev.kind in _WEB_KINDS:
            await self._on_web_event(ip, ev, st, t)

        elif ev.kind in _DB_KINDS:
            await self._on_db_event(ip, ev, st, t)

        elif ev.kind in _FW_KINDS:
            await self._on_fw_event(ip, ev, st, t)

        elif ev.kind in _SYS_KINDS:
            await self._on_sys_event(ip, ev, st, t)

        elif ev.kind in _CLOUD_KINDS:
            await self._on_cloud_event(ip, ev, st, t)

        elif ev.kind in _OT_KINDS:
            await self._on_ot_event(ip, ev, st, t)

        elif ev.kind in _WAZUH_KINDS:
            await self._on_wazuh_event(ip, ev, st, t)

        #  Correlator (cross-source, Phase 2) 
        if self.correlator:
            alert = self.correlator.ingest(ev)
            if alert and self.log_correlations:
                await self._handle_correlation(alert)

    #  SSH handlers 

    #  Threat feed check 

    async def _check_threat_feed(self, ip: str, ev: Event) -> None:
        """Block IP immediately if it appears in any threat feed."""
        if not self.threat_feed:
            return

        hit = self.threat_feed.check(ip)
        if not hit:
            return

        if self.blocker.is_blocked(ip):
            return

        match_type = hit.get("match_type", "exact")
        cidr       = hit.get("cidr", "")
        reason     = (
            f"threat_feed: IP matched community blocklist "
            f"({'CIDR ' + cidr if cidr else 'exact match'})"
        )

        await self.logger.log("threat_feed_hit", {
            "ip":         ip,
            "match_type": match_type,
            "cidr":       cidr,
            "event_kind": ev.kind,
        })

        severity = self.threat_feed.severity

        detection = Detection(
            src_ip     = ip,
            severity   = severity,
            reasons    = [reason],
            fail_count = 0,
            uniq_users = 0,
            window_sec = 0,
        )

        if self.metrics:
            self.metrics.inc_incident(severity)

        geo = self.geoip.get_cached(ip) if self.geoip else None

        if self.store:
            try:
                await self.store.save_incident(detection, geo)
            except Exception:
                pass

        if self.case_manager:
            try:
                await self.case_manager.create_from_incident(detection, geo)
            except Exception:
                pass

        if self.notifier:
            try:
                await self.notifier.send(detection, geo)
            except Exception:
                pass

        if self.threat_feed.auto_block:
            st = self._state[ip]
            await self._block_ip(ip, reason, st, detection)

    #  Country-based blocking 

    async def _check_country_block(self, ip: str, ev: Event) -> None:
        """Block IP immediately if it originates from a blocked country.

        Uses cached GeoIP to avoid an extra lookup — if the IP has never been
        seen before the geo dict is empty and the check is a no-op (the block
        fires on the next event once the cache is warm, or when the lookup
        completes asynchronously).
        """
        if not self.geoip:
            return

        geo = self.geoip.get_cached(ip)
        if not geo:
            # Trigger a background lookup so future events benefit from the cache
            try:
                geo = await self.geoip.lookup(ip)
            except Exception:
                return

        if not geo:
            return

        code = geo.get("countryCode", "").upper()
        if not code or code not in self.blocked_countries:
            return

        if self.blocker.is_blocked(ip):
            return

        country = geo.get("country", code)
        reason  = f"country_block: {country} ({code}) is in the blocked-countries list"

        await self.logger.log("country_block_triggered", {
            "ip":          ip,
            "country":     country,
            "countryCode": code,
            "event_kind":  ev.kind,
        })

        detection = Detection(
            src_ip=ip,
            severity=Severity.HIGH,
            reasons=[reason],
            fail_count=0,
            uniq_users=0,
            window_sec=0,
        )

        if self.metrics:
            self.metrics.inc_incident(Severity.HIGH)

        if self.store:
            try:
                await self.store.save_incident(detection, geo)

                if self.case_manager:
                    try:
                        await self.case_manager.create_from_incident(detection, geo)
                    except Exception:
                        pass
            except Exception:
                pass

        if self.notifier:
            try:
                await self.notifier.send(detection, geo)
            except Exception:
                pass

        st = self._state[ip]
        await self._block_ip(ip, reason, st, detection)

    async def _on_ssh_fail(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        st.fails.append((t, 1))
        st.total_fails += 1
        if ev.user:
            st.users.append((t, ev.user))

        # Kill chain: SSH fail = Delivery stage
        geo = self.geoip.get_cached(ip) if self.geoip else None
        self._kc_update(ip, "SSH_FAIL", geo=geo, severity="MEDIUM")

        # Zero-trust: brute force fails degrade IP trust
        if self.zero_trust:
            from .zero_trust import TrustSignal
            self.zero_trust.apply_signal(ip, "ip", TrustSignal.BRUTE_FORCE_FAIL)

        if self.metrics:
            geo     = self.geoip.get_cached(ip) if self.geoip else None
            country = geo.get("country", "") if geo else ""
            self.metrics.inc_ssh_fail(ip, country)

        fail_count = len(st.fails)
        uniq_users = _unique_users(st.users)
        sev, reasons = None, []

        r_bf = self.rules.get("ssh.brute_force")
        if r_bf and r_bf.enabled and fail_count >= self._zt_threshold(
                ip, "ip", r_bf.effective_threshold):
            sev = r_bf.effective_severity
            reasons.append(
                f"brute_force: {fail_count} fails in {self.window_sec}s"
            )

        r_cs = self.rules.get("ssh.credential_stuffing")
        if r_cs and r_cs.enabled and uniq_users >= self._zt_threshold(
                ip, "ip", r_cs.effective_threshold):
            sev = r_cs.effective_severity
            reasons.append(
                f"credential_stuffing: {uniq_users} unique users in {self.window_sec}s"
            )

        # Repeat offender escalation
        r_ro = self.rules.get("net.repeat_offender")
        if sev and r_ro and r_ro.enabled and _is_repeat_offender(
            st, r_ro.effective_threshold, r_ro.effective_window, t
        ):
            sev = Severity.HIGH
            reasons.append(
                f"repeat_offender: {r_ro.effective_threshold}+ incidents in last hour"
            )

        await self._maybe_fire(ip, st, t, sev, reasons, trigger="fail",
                               fail_count=fail_count, uniq_users=uniq_users)

    async def _on_ssh_success(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        st.last_success = t
        fail_count = len(st.fails)
        sev, reasons = None, []

        r_cb = self.rules.get("ssh.credential_breach")
        if r_cb and r_cb.enabled and fail_count >= r_cb.effective_threshold:
            sev = r_cb.effective_severity
            reasons.append(
                f"credential_breach: success after {fail_count} fails"
            )

        # UEBA -- observe successful login for behavioral profiling
        if self.ueba and self.ueba.enabled and ev.user:
            try:
                anomaly = self.ueba.observe(username=ev.user, src_ip=ip, ts=t)
                if anomaly:
                    await self.logger.log("ueba_anomaly", anomaly.to_dict())
                    if not sev:
                        sev = "MEDIUM"
                    reasons.append(f"ueba: {anomaly.reason}")
                    # Zero-trust: UEBA anomaly degrades user trust score
                    if self.zero_trust and ev.user:
                        from .zero_trust import TrustSignal
                        self.zero_trust.apply_signal(
                            ev.user, "user", TrustSignal.UEBA_ANOMALY)
                    if self.ueba.persist:
                        import asyncio
                        asyncio.create_task(
                            self.ueba.save_event(ev.user, ip, anomaly)
                        )
                else:
                    # Zero-trust: normal login from known IP improves trust
                    if self.zero_trust and ev.user:
                        from .zero_trust import TrustSignal
                        from .ueba import UserProfile
                        profile = self.ueba.get_profile(ev.user)
                        signal  = (TrustSignal.KNOWN_IP_LOGIN
                                   if (profile and ip in (profile.get("known_ips") or {}))
                                   else TrustSignal.UNKNOWN_IP_LOGIN)
                        self.zero_trust.apply_signal(ev.user, "user", signal)
                    if self.ueba.persist:
                        import asyncio
                        asyncio.create_task(
                            self.ueba.save_event(ev.user, ip)
                        )
            except Exception:
                pass

        # Kill chain: SSH success after failures = Exploitation stage
        geo = self.geoip.get_cached(ip) if self.geoip else None
        self._kc_update(ip, "SSH_SUCCESS", geo=geo, severity="HIGH")

        await self._maybe_fire(ip, st, t, sev, reasons, trigger="success",
                               fail_count=fail_count, uniq_users=_unique_users(st.users),
                               user=ev.user)

    #  Web handler (Phase 2) 

    async def _on_web_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        if ev.kind == "WEB_SCAN":
            st.web_scans.append((t, 1))
        elif ev.kind == "WEB_AUTH_FAIL":
            st.web_auth_fails.append((t, 1))
        elif ev.kind == "WEB_EXPLOIT_ATTEMPT":
            st.web_exploits.append((t, 1))

        scan_count  = len(st.web_scans)
        auth_count  = len(st.web_auth_fails)
        expl_count  = len(st.web_exploits)
        sev, reasons = None, []

        r_sf = self.rules.get("web.scan_flood")
        if r_sf and r_sf.enabled and scan_count >= r_sf.effective_threshold:
            sev = r_sf.effective_severity
            reasons.append(f"web_scan_flood: {scan_count} scan events in {self.window_sec}s")

        r_af = self.rules.get("web.auth_flood")
        if r_af and r_af.enabled and auth_count >= r_af.effective_threshold:
            sev = r_af.effective_severity
            reasons.append(f"web_auth_flood: {auth_count} 401/403 in {self.window_sec}s")

        r_ex = self.rules.get("web.exploit")
        if r_ex and r_ex.enabled and expl_count >= r_ex.effective_threshold:
            sev = r_ex.effective_severity
            path = ev.meta.get("path", "") if ev.meta else ""
            reasons.append(f"web_exploit_attempt: path={path}")

        # Kill chain: map web event kind to appropriate stage
        kc_kind = {
            "WEB_SCAN":            "WEB_SCAN",
            "WEB_AUTH_FAIL":       "WEB_AUTH_FAIL",
            "WEB_EXPLOIT_ATTEMPT": "WEB_EXPLOIT_ATTEMPT",
        }.get(ev.kind)
        if kc_kind:
            geo = self.geoip.get_cached(ip) if self.geoip else None
            kc_sev = "HIGH" if kc_kind == "WEB_EXPLOIT_ATTEMPT" else "LOW"
            self._kc_update(ip, kc_kind, geo=geo, severity=kc_sev)

        await self._maybe_fire(ip, st, t, sev, reasons, trigger="web",
                               fail_count=scan_count + auth_count + expl_count,
                               uniq_users=0)

    #  DB handler (Phase 2) 

    async def _on_db_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        st.db_fails.append((t, 1))
        db_count = len(st.db_fails)
        sev, reasons = None, []

        r_db = self.rules.get("db.brute_force")
        if r_db and r_db.enabled and db_count >= r_db.effective_threshold:
            sev = r_db.effective_severity
            user = ev.user or "unknown"
            reasons.append(
                f"db_brute_force: {db_count} DB auth failures (user={user})"
            )

        # Kill chain: DB auth fail = Delivery stage
        geo = self.geoip.get_cached(ip) if self.geoip else None
        self._kc_update(ip, "DB_AUTH_FAIL", geo=geo, severity="MEDIUM")

        await self._maybe_fire(ip, st, t, sev, reasons, trigger="db",
                               fail_count=db_count, uniq_users=0)

    #  Firewall handler (Phase 2) 

    async def _on_fw_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        r_hp = self.rules.get("fw.honeypot_port")
        if ev.kind == "FW_HONEYPOT_PORT" and r_hp and r_hp.enabled:
            port    = ev.meta.get("dst_port", "?") if ev.meta else "?"
            reasons = [f"honeypot_port: connection to port {port} (never legitimate)"]
            # Kill chain: honeypot hit = Reconnaissance stage
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "FW_HONEYPOT_PORT", geo=geo, severity="HIGH")
            await self._maybe_fire(ip, st, t, r_hp.effective_severity, reasons,
                                   trigger="fw", fail_count=1, uniq_users=0)
        else:
            # Kill chain: FW block = Reconnaissance stage
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "FW_BLOCK", geo=geo, severity="LOW")
            await self.logger.log("fw_block", {"ip": ip, "meta": ev.meta})

    async def _on_sys_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        # Kill chain: sudo/su fail = Installation stage
        if ev.kind in ("SUDO_FAIL", "SU_FAIL"):
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, ev.kind, geo=geo, severity="HIGH")
        # sudo/su fail alone is LOW -- correlator will escalate if SSH login preceded it
        await self.logger.log("privilege_event", {
            "ip":   ip,
            "kind": ev.kind,
            "user": ev.user,
            "meta": ev.meta,
        })

    async def _on_cloud_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        """
        Handle cloud identity events (AWS CloudTrail, Azure AD).
        Routes CLOUD_SIGNIN_FAIL -> detection pipeline (analogous to SSH_FAIL),
        CLOUD_MFA_FAIL and CLOUD_RISKY_SIGNIN -> HIGH severity immediate alert.
        CLOUD_SIGNIN_SUCCESS tracked for breach detection (login after repeated fails).
        """
        sev     = None
        reasons = []
        meta    = ev.meta or {}

        provider = meta.get("provider", "cloud")
        user     = ev.user or "unknown"

        if ev.kind == "CLOUD_SIGNIN_FAIL":
            st.fails.append((t, 1))
            st.total_fails += 1
            if ev.user:
                st.users.append((t, ev.user))

            r_cf = self.rules.get("cloud.signin_brute_force")
            fail_count = sum(1 for ts, _ in st.fails
                             if t - ts <= self.window_sec)
            if r_cf and r_cf.enabled and fail_count >= self._zt_threshold(
                    ip, "ip", r_cf.effective_threshold):
                sev = r_cf.effective_severity
                reasons.append(
                    f"cloud_signin_brute_force ({provider}): "
                    f"{fail_count} failures (user={user})"
                )
            # Kill chain: cloud sign-in fail = Delivery stage
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "CLOUD_SIGNIN_FAIL", geo=geo, severity="MEDIUM")

        elif ev.kind == "CLOUD_MFA_FAIL":
            r_mfa = self.rules.get("cloud.mfa_failure")
            if r_mfa and r_mfa.enabled:
                sev = r_mfa.effective_severity
                reasons.append(
                    f"cloud_mfa_failure ({provider}): MFA failed or bypassed (user={user})"
                )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "CLOUD_MFA_FAIL", geo=geo, severity="HIGH")
            if self.zero_trust and ev.user:
                from .zero_trust import TrustSignal
                self.zero_trust.apply_signal(ev.user, "user", TrustSignal.MFA_FAILURE)
                self.zero_trust.apply_signal(ip, "ip", TrustSignal.MFA_FAILURE)

        elif ev.kind == "CLOUD_RISKY_SIGNIN":
            risk_state = meta.get("risk_state", "unknown")
            r_risk = self.rules.get("cloud.risky_signin")
            if r_risk and r_risk.enabled:
                sev = r_risk.effective_severity
                reasons.append(
                    f"cloud_risky_signin ({provider}): "
                    f"risk_state={risk_state} (user={user})"
                )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "CLOUD_RISKY_SIGNIN", geo=geo, severity="HIGH")
            if self.zero_trust and ev.user:
                from .zero_trust import TrustSignal
                self.zero_trust.apply_signal(ev.user, "user", TrustSignal.CLOUD_RISK_FLAG)
                self.zero_trust.apply_signal(ip, "ip", TrustSignal.CLOUD_RISK_FLAG)

        elif ev.kind == "CLOUD_SIGNIN_SUCCESS":
            # Track success after repeated failures (possible breach)
            if st.total_fails > 0:
                r_breach = self.rules.get("cloud.signin_breach")
                if r_breach and r_breach.enabled and st.total_fails >= r_breach.effective_threshold:
                    sev = r_breach.effective_severity
                    reasons.append(
                        f"cloud_signin_breach ({provider}): "
                        f"success after {st.total_fails} failures (user={user})"
                    )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "CLOUD_SIGNIN_SUCCESS", geo=geo, severity="HIGH")

        elif ev.kind == "CLOUD_IMPOSSIBLE_TRAVEL":
            r_it = self.rules.get("cloud.impossible_travel")
            if r_it and r_it.enabled:
                sev = r_it.effective_severity
                reasons.append(
                    f"cloud_impossible_travel ({provider}): "
                    f"two sign-ins too far apart (user={user})"
                )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "CLOUD_IMPOSSIBLE_TRAVEL", geo=geo, severity="HIGH")

        if sev is not None:
            await self._maybe_fire(ip, st, t, sev, reasons, trigger="cloud",
                                   fail_count=len(st.fails), uniq_users=0)

    async def _on_ot_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        """
        Handle OT/ICS events (Modbus, DNP3, SCADA).

        OT events are treated differently from IT events:
          - A single MODBUS_WRITE from any IP is already suspicious
          - MODBUS_SCAN = reconnaissance (Recon kill chain stage)
          - DNP3_AUTH_FAIL = HIGH, immediate alert
          - SCADA_ALARM = HIGH, immediate alert
          - UNAUTHORIZED_CMD = HIGH, immediate alert
        """
        sev     = None
        reasons = []
        meta    = ev.meta or {}
        proto   = meta.get("protocol", "ot")

        if ev.kind == "OT_MODBUS_WRITE":
            r = self.rules.get("ot.modbus_write")
            if r and r.enabled:
                sev = r.effective_severity
                fc  = meta.get("function_code", "?")
                trusted = meta.get("trusted", False)
                reasons.append(
                    f"ot_modbus_write: FC{fc} write from "
                    f"{'trusted' if trusted else 'UNTRUSTED'} IP"
                )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "OT_MODBUS_WRITE", geo=geo, severity="HIGH")

        elif ev.kind == "OT_MODBUS_SCAN":
            r = self.rules.get("ot.modbus_scan")
            if r and r.enabled:
                st.fails.append((t, 1))
                st.total_fails += 1
                fail_count = sum(1 for ts, _ in st.fails
                                 if t - ts <= self.window_sec)
                if fail_count >= self._zt_threshold(
                        ip, "ip", r.effective_threshold):
                    sev = r.effective_severity
                    reasons.append(
                        f"ot_modbus_scan: {fail_count} read sweeps "
                        f"in {self.window_sec}s"
                    )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, "OT_MODBUS_SCAN", geo=geo, severity="MEDIUM")

        elif ev.kind == "OT_MODBUS_EXCEPTION":
            r = self.rules.get("ot.modbus_write")
            if r and r.enabled:
                sev = "MEDIUM"
                reasons.append("ot_modbus_exception: device returned exception code")

        elif ev.kind in ("OT_DNP3_UNSOLICITED", "OT_DNP3_AUTH_FAIL"):
            r = self.rules.get("ot.scada_alarm")
            if r and r.enabled:
                sev = "HIGH" if ev.kind == "OT_DNP3_AUTH_FAIL" else "MEDIUM"
                reasons.append(
                    f"ot_dnp3: {ev.kind.lower()} from {ip or 'unknown'}"
                )
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, ev.kind, geo=geo, severity=sev or "MEDIUM")

        elif ev.kind in ("OT_SCADA_ALARM", "OT_UNAUTHORIZED_CMD"):
            r = self.rules.get("ot.scada_alarm")
            if r and r.enabled:
                sev = r.effective_severity
                detail = meta.get("detail", ev.kind.lower())
                reasons.append(f"ot_scada: {detail} ({proto})")
            geo = self.geoip.get_cached(ip) if self.geoip else None
            self._kc_update(ip, ev.kind, geo=geo, severity="HIGH")

        # OT events always logged regardless of alert threshold
        await self.logger.log("ot_event", {
            "ip": ip, "kind": ev.kind, "meta": meta, "source": ev.source,
        })

        if sev is not None:
            await self._maybe_fire(ip, st, t, sev, reasons, trigger="ot",
                                   fail_count=len(st.fails), uniq_users=0)

    async def _on_wazuh_event(self, ip: str, ev: Event, st: IPState, t: float) -> None:
        """
        Handle alerts relayed from Wazuh/OSSEC (cnsl/wazuh.py).

        Wazuh has already done its own rule evaluation and assigned a
        severity (rule.level, mapped to CNSL's HIGH/MEDIUM/LOW by the
        parser) -- CNSL's job here is to fold that vetted alert into
        its own kill-chain tracking, correlation, and blocking, not to
        re-run its own threshold logic on top. Every Wazuh alert that
        clears the "wazuh.alert" rule's enabled flag fires immediately
        (threshold=1, no window), same as cloud.risky_signin.
        """
        meta     = ev.meta or {}
        sev      = None
        reasons: List[str] = []

        r = self.rules.get("wazuh.alert")
        if r and r.enabled:
            sev = meta.get("severity", "LOW")
            reasons.append(
                f"wazuh: {meta.get('rule_description', 'alert')} "
                f"(rule {meta.get('rule_id', '?')}, level {meta.get('rule_level', '?')}, "
                f"agent {meta.get('agent_name') or meta.get('agent_id') or 'unknown'})"
            )

        geo = self.geoip.get_cached(ip) if self.geoip else None
        self._kc_update(ip, "WAZUH_ALERT", geo=geo, severity=sev or "LOW")

        # Wazuh alerts always logged regardless of whether the rule fires
        await self.logger.log("wazuh_event", {
            "ip": ip, "meta": meta, "source": ev.source,
        })

        if sev is not None:
            await self._maybe_fire(ip, st, t, sev, reasons, trigger="wazuh",
                                   fail_count=len(st.fails), uniq_users=0,
                                   user=ev.user)

    #  Correlation alert handler (Phase 2) 

    async def _handle_correlation(self, alert: "CorrelationAlert") -> None:
        ip  = alert.src_ip
        st  = self._state[ip]
        geo = await self._get_geo(ip)

        await self.logger.log("correlation_alert", {
            **alert.to_dict(),
            "geo": geo or {},
        })

        if self.metrics:
            self.metrics.inc_incident(alert.severity)

        detection = Detection(
            src_ip     = ip,
            severity   = alert.severity,
            reasons    = [f"[CORRELATION:{alert.rule_name}] {alert.description}"],
            fail_count = 0,
            uniq_users = 0,
            window_sec = self.window_sec,
        )

        if self.store:
            try:
                await self.store.save_incident(detection, geo)

                if self.case_manager:
                    try:
                        await self.case_manager.create_from_incident(detection, geo)
                    except Exception:
                        pass
            except Exception:
                pass

        if self.notifier:
            try:
                await self.notifier.send(detection, geo)
            except Exception:
                pass

        if alert.severity == Severity.HIGH:
            await self._block_ip(ip, f"correlation:{alert.rule_name}", st, detection)

        # Kill chain: map correlation rule to stage
        if self.kill_chain:
            try:
                geo = await self._get_geo(ip)
                self.kill_chain.update_from_correlation(ip, alert.rule_name, geo=geo)
            except Exception:
                pass

    #  Core: fire incident 

    async def _maybe_fire(
        self,
        ip:         str,
        st:         IPState,
        t:          float,
        sev:        Optional[str],
        reasons:    List[str],
        trigger:    str,
        fail_count: int,
        uniq_users: int,
        user:       Optional[str] = None,
    ) -> None:
        """Check AbuseIPDB, then fire incident if severity is set."""

        # AbuseIPDB pre-check — runs regardless of threshold
        # Known-bad IPs get flagged even on first event
        if self.abuseipdb:
            try:
                report = await self.abuseipdb.check(ip)
                if report and self.abuseipdb.should_flag(report):
                    if sev is None:
                        sev = Severity.MEDIUM
                    reasons.append(
                        f"abuseipdb_score={report.abuse_score} "
                        f"reports={report.total_reports} "
                        f"isp={report.isp}"
                    )
                    await self.logger.log("abuseipdb_flagged", {
                        "ip":           ip,
                        "abuse_score":  report.abuse_score,
                        "total_reports":report.total_reports,
                        "isp":          report.isp,
                        "from_cache":   report.from_cache,
                    })
            except Exception:
                pass

        if sev is None:
            return

        # Cooldown per IP (avoid alert storm)
        if st.last_incident and (t - st.last_incident) < self.cooldown_sec:
            return

        st.last_incident   = t
        st.total_incidents += 1
        st.incident_times.append(t)

        detection = Detection(
            src_ip=ip, severity=sev, reasons=reasons,
            fail_count=fail_count, uniq_users=uniq_users,
            window_sec=self.window_sec,
        )

        geo = await self._get_geo(ip)

        await self.logger.log("incident", {**detection.to_dict(), "geo": geo or {}})
        await self.logger.log("response_plan", {
            "ip":       ip,
            "severity": sev,
            "plan":     _response_plan(sev, ip, trigger),
        })

        if self.metrics:
            self.metrics.inc_incident(sev)

        if self.store:
            try:
                await self.store.save_incident(detection, geo)

                if self.case_manager:
                    try:
                        await self.case_manager.create_from_incident(detection, geo)
                    except Exception:
                        pass
            except Exception:
                pass

        if self.notifier:
            try:
                await self.notifier.send(detection, geo)
            except Exception:
                pass

        # Behavioral baseline (on SSH success)
        if trigger == "success" and self.baseline and user:
            try:
                anomaly = self.baseline.observe_login(ip, user, t)
                if anomaly and self.log_baseline:
                    await self.logger.log("baseline_anomaly", {
                        "ip":      ip,
                        "user":    user,
                        "anomaly": anomaly,
                    })
            except Exception:
                pass

        # Block HIGH severity
        if sev == Severity.HIGH:
            await self._block_ip(ip, "; ".join(reasons), st, detection)

        # Pattern learner -- record this alert for pattern discovery
        if self.pattern_learner:
            try:
                self.pattern_learner.on_alert(ip, trigger)
            except Exception:
                pass

        # SIEM/SOAR push -- send detection to all enabled connectors
        if self.siem_router and detection:
            try:
                asyncio.ensure_future(self.siem_router.push(detection))
            except Exception:
                pass

    #  Blocking 

    async def _block_ip(
        self,
        ip:        str,
        reason:    str,
        st:        IPState,
        detection: Detection,
    ) -> None:
        blocked = await self.blocker.block_ip(ip, reason=reason)

        if blocked and self.metrics:
            self.metrics.inc_block()

        if blocked and self.store:
            try:
                unblock_at = now() + self.blocker.block_duration_sec
                await self.store.save_block(
                    ip, unblock_at, reason=reason,
                    dry_run=self.blocker.dry_run,
                )
            except Exception:
                pass

        # Propagate block to Redis cluster (Phase 2)
        if blocked and self.redis_sync and self.redis_sync.connected:
            try:
                await self.redis_sync.publish_block(
                    ip, reason, self.blocker.block_duration_sec
                )
            except Exception:
                pass

    #  GeoIP helper 

    async def _get_geo(self, ip: str) -> Optional[Dict]:
        if not self.geoip:
            return None
        try:
            return await self.geoip.lookup(ip)
        except Exception:
            return None

    #  Public: stats for dashboard 

    def get_stats(self) -> List[Dict]:
        """Return snapshot of all tracked IPs — used by dashboard REST API."""
        result = []
        t = now()
        for ip, st in self._state.items():
            _prune_all(st, self.window_sec, t)
            geo       = self.geoip.get_cached(ip) if self.geoip else None
            abuse     = self.abuseipdb.cache_size() if self.abuseipdb else None
            profile   = self.baseline.get_profile(ip) if self.baseline else None
            corr_sum  = (
                self.correlator.get_ip_summary(ip) if self.correlator else {}
            )

            result.append({
                "ip":              ip,
                "fails_in_window": len(st.fails),
                "unique_users":    _unique_users(st.users),
                "web_scans":       len(st.web_scans),
                "web_auth_fails":  len(st.web_auth_fails),
                "db_fails":        len(st.db_fails),
                "total_fails":     st.total_fails,
                "total_incidents": st.total_incidents,
                "last_incident":   iso_time(st.last_incident) if st.last_incident else None,
                "is_blocked":      self.blocker.is_blocked(ip),
                "country":         geo.get("country") if geo else None,
                "flag":            geo.get("flag")    if geo else None,
                "isp":             geo.get("isp")     if geo else None,
                "correlation_events": corr_sum,
                "baseline_anomalies": profile.get("anomaly_count", 0) if profile else 0,
            })

        return sorted(result, key=lambda x: x["total_fails"], reverse=True)

    def tracked_ip_count(self) -> int:
        return len(self._state)



# Response plan text


def _response_plan(severity: str, ip: str, trigger: str = "") -> List[str]:
    if severity == Severity.HIGH:
        plans = [f"[AUTO] TEMP-BLOCK {ip}"]
        if trigger == "success":
            plans += [
                "[MANUAL] Audit the successful session — check what was accessed",
                "[MANUAL] Rotate SSH credentials and keys immediately",
                "[MANUAL] Check for new cron jobs, authorized_keys, .bashrc changes",
            ]
        elif trigger == "fw":
            plans += [
                "[MANUAL] Check if this IP is scanning other ports too",
                "[MANUAL] Consider permanent block if attack persists",
            ]
        else:
            plans += [
                "[MANUAL] Review open ports and firewall rules",
                "[MANUAL] Check server logs for signs of compromise",
            ]
        return plans

    return [
        f"[PLAN] Monitor {ip} for further activity",
        "[PLAN] Consider fail2ban / rate-limiting",
        "[PLAN] Check AbuseIPDB / Shodan for known-bad IP info",
    ]