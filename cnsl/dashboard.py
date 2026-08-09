"""
cnsl/dashboard.py -- Live web dashboard with JWT auth, WebSocket, SSE, REST API.

Core routes: /, /login, /api/login, /api/logout, /api/health (no auth),
/api/stats, /api/incidents, /api/top-attackers, /api/timeline, /api/blocks,
/api/metrics, /api/ml*, /api/fim, /api/honeypot, /api/block, /api/unblock,
/api/audit, /api/correlation-rules*, /api/federation/hub, /api/export/stix,
/taxii2/* (taxii.py), /api/fingerprint/* (fingerprint.py), /api/graph/*
(graph_correlation.py), /ws, /ws/agent, /stream (SSE).
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .config import safe_int

if TYPE_CHECKING:
    from .auth        import AuthManager
    from .blocker     import Blocker
    from .detector    import Detector
    from .fim         import FIMEngine
    from .logger      import JsonLogger
    from .metrics     import Metrics
    from .ml_detector import MLDetector
    from .store       import Store

# SVG icon helpers 

def _svg(path_d: str, w: int = 16, h: int = 16) -> str:
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round">{path_d}</svg>')

_I = {
    "shield":   _svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 18, 18),
    "alert":    _svg('<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>', 16, 16),
    "lock":     _svg('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>', 16, 16),
    "users":    _svg('<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>', 16, 16),
    "cpu":      _svg('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>', 16, 16),
    "terminal": _svg('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>', 16, 16),
    "file":     _svg('<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>', 16, 16),
    "activity": _svg('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>', 16, 16),
    "target":   _svg('<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>', 16, 16),
    "radio":    _svg('<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 010 8.49m-8.48-.01a6 6 0 010-8.49m11.31-2.82a10 10 0 010 14.14m-14.14 0a10 10 0 010-14.14"/>', 16, 16),
    "clock":    _svg('<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>', 16, 16),
    "download": _svg('<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>', 14, 14),
    "logout":   _svg('<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>', 14, 14),
}

# Login page HTML

from .dashboard_html import _LOGIN_HTML, _HTML  # noqa: F401

class _RateLimiter:
    """In-memory sliding-window limiter for individual endpoints (SSE/API
    below) -- distinct from cnsl.rate_limiter.RateLimiter used elsewhere."""

    def __init__(self, max_calls: int, window_sec: int):
        self._max    = max_calls
        self._window = window_sec
        self._calls: Dict[str, list] = {}

    def is_limited(self, key: str) -> bool:
        now    = time.time()
        cutoff = now - self._window
        calls  = [t for t in self._calls.get(key, []) if t > cutoff]
        self._calls[key] = calls
        if len(calls) >= self._max:
            return True
        calls.append(now)
        return False

async def start_dashboard(
    host:           str,
    port:           int,
    detector:       "Detector",
    blocker:        "Blocker",
    store:          "Store",
    metrics:        "Metrics",
    logger:         "JsonLogger",
    auth:           "AuthManager",
    dry_run:        bool = True,
    rbac:           Any = None,
    assets:         Any = None,
    honeypot:       Any = None,
    ml_detector:    Any = None,
    fim:            Any = None,
    search_engine:  Any = None,
    es_pusher:      Any = None,
    case_manager:   Any = None,
    threat_feed:    Any = None,
    ueba:           Any = None,
    tenant_manager: Any = None,
    rate_limiter:   Any = None,
    kafka:          Any = None,
    huddle:         Any = None,
    notifier:       Any = None,
    kill_chain:     Any = None,
    pattern_learner: Any = None,
    siem_router:     Any = None,
    federation:      Any = None,
    cloud_identity:  Any = None,
    zero_trust:      Any = None,
    queue:           Any = None,
    redis_sync:      Any = None,
    audit_log:       Any = None,
    correlator:      Any = None,
) -> None:
    from . import __version__
    try:
        from aiohttp import web
        import aiohttp
        import json as _json_mod
        json = _json_mod
    except ImportError:
        await logger.log("dashboard_error", {"error": "aiohttp not installed. Run: pip install aiohttp"})
        return

    _subscribers: list = []
    _api_limiter  = _RateLimiter(max_calls=60,  window_sec=60)
    _sse_limiter  = _RateLimiter(max_calls=10,  window_sec=60)

    # Patch logger to fan out to SSE
    _orig_log = logger.log

    async def _patched_log(event_type: str, payload: dict) -> None:
        await _orig_log(event_type, payload)
        msg = json.dumps({"type": event_type, "payload": payload})
        dead = []
        for q in list(_subscribers):
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for d in dead:
            try:
                _subscribers.remove(d)
            except ValueError:
                pass

    logger.log = _patched_log

    router = web.RouteTableDef()
    #  Auth helpers 
    def _get_client_ip(req: web.Request) -> str:
        return req.headers.get("X-Forwarded-For", req.remote or "unknown").split(",")[0].strip()

    async def _audit(req: web.Request, user_payload: dict, action: str,
                      target: Optional[str] = None, details: Optional[dict] = None) -> None:
        """Record a compliance audit entry. Never raises -- auditing must
        not break the action it's recording."""
        if audit_log is None:
            return
        try:
            await audit_log.record(
                actor=user_payload.get("sub", "?"),
                action=action,
                target=target,
                details=details or {},
                source_ip=_get_client_ip(req),
            )
        except Exception:
            pass

    def _require_auth(req: web.Request):
        """Returns (payload, None) or (None, Response)."""
        if not auth.enabled:
            return {"sub": "anonymous", "role": "admin"}, None
        token = req.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            token = req.rel_url.query.get("token", "")
        payload, err = auth.verify_token(token)
        if err:
            return None, web.json_response({"error": err}, status=401)
        return payload, None

    def _require_perm(user_payload, perm: str):
        """Returns None if allowed, or a 403 Response if denied."""
        if rbac is None:
            return None
        role = user_payload.get("role", "viewer")
        err  = rbac.require(role, perm)
        if err:
            return web.json_response(err, status=403)
        return None

    def _rate_check(req: web.Request):
        ip = _get_client_ip(req)
        if _api_limiter.is_limited(ip):
            return web.json_response({"error": "Rate limit exceeded"}, status=429)
        return None

    #  Pages 

    @router.get("/login")
    async def login_page(_: web.Request) -> web.Response:
        return web.Response(text=_LOGIN_HTML, content_type="text/html")

    @router.get("/")
    async def index(req: web.Request) -> web.Response:
        if auth.enabled:
            token = req.cookies.get("cnsl_token") or req.rel_url.query.get("token", "")
            payload, err = auth.verify_token(token)
            if err:
                raise web.HTTPFound("/login")
        return web.Response(text=_HTML, content_type="text/html")

    #  Auth endpoints 

    @router.post("/api/login")
    async def api_login(req: web.Request) -> web.Response:
        ip = _get_client_ip(req)
        body = await req.json()
        username = body.get("username", "")
        password = body.get("password", "")
        token, err, needs_2fa = auth.login(username, password, client_ip=ip)
        if err:
            await logger.log("auth_login_fail", {"ip": ip, "username": username})
            return web.json_response({"error": err}, status=401)
        if needs_2fa:
            await logger.log("auth_2fa_required", {"ip": ip, "username": username})
            return web.json_response({"needs_2fa": True, "partial_token": token})
        payload, _ = auth.verify_token(token)
        await logger.log("auth_login_ok", {"ip": ip, "username": username})
        return web.json_response({
            "token": token,
            "must_change_password": payload.get("mcp", False),
        })

    @router.post("/api/2fa/verify")
    async def api_2fa_verify(req: web.Request) -> web.Response:
        """Exchange partial token + OTP code for a full access token."""
        ip   = _get_client_ip(req)
        body = await req.json()
        partial_token = body.get("partial_token", "")
        code          = body.get("code", "")
        token, err = auth.verify_2fa(partial_token, code, client_ip=ip)
        if err:
            await logger.log("auth_2fa_fail", {"ip": ip})
            return web.json_response({"error": err}, status=401)
        payload, _ = auth.verify_token(token)
        await logger.log("auth_2fa_ok", {"ip": ip, "username": payload.get("sub")})
        return web.json_response({
            "token": token,
            "must_change_password": payload.get("mcp", False),
        })

    @router.post("/api/2fa/setup")
    async def api_2fa_setup(req: web.Request) -> web.Response:
        """Generate a new TOTP secret and return the otpauth:// URI."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        username = payload["sub"]
        uri, err = auth.setup_2fa(username)
        if err:
            return web.json_response({"error": err}, status=400)
        return web.json_response({"uri": uri, "username": username})

    @router.post("/api/2fa/confirm")
    async def api_2fa_confirm(req: web.Request) -> web.Response:
        """Confirm 2FA setup with first OTP — activates 2FA and returns backup codes."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        body     = await req.json()
        code     = body.get("code", "")
        username = payload["sub"]
        backup_codes, err = auth.confirm_2fa(username, code)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("auth_2fa_enabled", {"username": username})
        return web.json_response({"ok": True, "backup_codes": backup_codes})

    @router.post("/api/2fa/disable")
    async def api_2fa_disable(req: web.Request) -> web.Response:
        """Disable 2FA — requires password confirmation."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        body     = await req.json()
        password = body.get("password", "")
        username = payload["sub"]
        err = auth.disable_2fa(username, password)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("auth_2fa_disabled", {"username": username})
        return web.json_response({"ok": True})

    @router.get("/api/2fa/status")
    async def api_2fa_status(req: web.Request) -> web.Response:
        """Return 2FA status for the authenticated user."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        status = auth.get_2fa_status(payload["sub"])
        return web.json_response(status)

    #  HuddleCluster API 

    @router.get("/api/huddle")
    async def api_huddle_stats(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not huddle:
            return web.json_response({"enabled": False})
        return web.json_response(huddle.get_stats())

    #  Rate Limiter API 

    @router.get("/api/rate-limit")
    async def api_rate_limit_stats(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not rate_limiter or not rate_limiter.enabled:
            return web.json_response({"enabled": False})
        return web.json_response(rate_limiter.get_stats())

    @router.get("/api/rate-limit/top")
    async def api_rate_limit_top(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not rate_limiter or not rate_limiter.enabled:
            return web.json_response({"top": []})
        n = int(req.rel_url.query.get("n", 10))
        return web.json_response({"top": rate_limiter.top_requesters(n)})

    @router.post("/api/rate-limit/reset/{ip}")
    async def api_rate_limit_reset(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        ip = req.match_info["ip"]
        if rate_limiter:
            rate_limiter.reset_ip(ip)
        return web.json_response({"ok": True, "ip": ip})

    #  Tenants API 

    @router.get("/api/tenants")
    async def api_tenants_list(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "config:read"):
            return web.json_response(guard, status=403)
        if not tenant_manager:
            return web.json_response({"enabled": False, "tenants": []})
        return web.json_response(tenant_manager.stats())

    @router.post("/api/tenants")
    async def api_tenant_create(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "config:write"):
            return web.json_response(guard, status=403)
        if not tenant_manager:
            return web.json_response({"error": "Tenant manager unavailable"}, status=503)
        body = await req.json()
        tid  = body.get("id", "").strip()
        err  = tenant_manager.add_tenant(tid, body)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("tenant_created", {"id": tid, "by": payload["sub"]})
        return web.json_response({"ok": True, "id": tid}, status=201)

    @router.delete("/api/tenants/{tenant_id}")
    async def api_tenant_delete(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "config:write"):
            return web.json_response(guard, status=403)
        if not tenant_manager:
            return web.json_response({"error": "Tenant manager unavailable"}, status=503)
        tid  = req.match_info["tenant_id"]
        err  = tenant_manager.remove_tenant(tid)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("tenant_deleted", {"id": tid, "by": payload["sub"]})
        return web.json_response({"ok": True})

    #  Kafka API 

    @router.get("/api/kafka")
    async def api_kafka_stats(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not kafka:
            return web.json_response({"enabled": False})
        return web.json_response(kafka.get_stats())

    #  UEBA API 

    @router.get("/api/ueba")
    async def api_ueba_stats(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not ueba or not ueba.enabled:
            return web.json_response({"enabled": False, "total_profiles": 0})
        return web.json_response({"enabled": True, **ueba.stats()})

    @router.get("/api/ueba/profiles")
    async def api_ueba_profiles(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not ueba or not ueba.enabled:
            return web.json_response({"profiles": []})
        q       = req.rel_url.query
        limit   = min(int(q.get("limit", 50)), 200)
        offset  = int(q.get("offset", 0))
        sort_by = q.get("sort_by", "anomaly_count")
        profiles = ueba.list_profiles(limit=limit, offset=offset, sort_by=sort_by)
        return web.json_response({
            "profiles": profiles,
            "total":    ueba.profile_count,
        })

    @router.get("/api/ueba/profiles/{username}")
    async def api_ueba_profile_get(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not ueba or not ueba.enabled:
            return web.json_response({"error": "UEBA not enabled"}, status=503)
        username = req.match_info["username"]
        profile  = ueba.get_profile(username)
        if not profile:
            return web.json_response({"error": "User not found"}, status=404)
        return web.json_response(profile)

    @router.get("/api/ueba/anomalies")
    async def api_ueba_anomalies(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not ueba or not ueba.enabled:
            return web.json_response({"anomalies": []})
        q        = req.rel_url.query
        limit    = min(int(q.get("limit", 50)), 200)
        username = q.get("username")
        anomalies = await ueba.recent_anomalies(limit=limit, username=username)
        return web.json_response({"anomalies": anomalies, "total": len(anomalies)})

    #  Threat Feed API 

    @router.get("/api/threat-feed")
    async def api_threat_feed_status(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not threat_feed:
            return web.json_response({"enabled": False, "total_ips": 0, "feeds": []})
        return web.json_response(threat_feed.get_stats())

    @router.post("/api/threat-feed/refresh")
    async def api_threat_feed_refresh(req: web.Request) -> web.Response:
        """Manually trigger a feed refresh. analyst+ only."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        if not threat_feed or not threat_feed.enabled:
            return web.json_response({"error": "Threat feed not enabled."}, status=400)
        stats = await threat_feed.refresh()
        await logger.log("threat_feed_manual_refresh", {
            "by": payload["sub"], "total_ips": stats.get("total_ips", 0)
        })
        return web.json_response({"ok": True, "stats": stats})

    @router.post("/api/threat-feed/check")
    async def api_threat_feed_check(req: web.Request) -> web.Response:
        """Check a specific IP against the loaded feed."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        body = await req.json()
        ip   = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        if not threat_feed or not threat_feed.enabled:
            return web.json_response({"ip": ip, "listed": False, "hit": None})
        hit = threat_feed.check(ip)
        return web.json_response({"ip": ip, "listed": bool(hit), "hit": hit})

    #  Alert Rule Engine API 

    @router.get("/api/rules")
    async def api_rules_list(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        rules = detector.rules.all_rules()
        return web.json_response({"rules": rules, "total": len(rules)})

    @router.get("/api/rules/{rule_id:.*}")
    async def api_rule_get(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        rule_id = req.match_info["rule_id"]
        rule = detector.rules.get(rule_id)
        if not rule:
            return web.json_response({"error": f"Rule '{rule_id}' not found."}, status=404)
        return web.json_response(rule.to_dict())

    @router.patch("/api/rules/{rule_id:.*}")
    async def api_rule_update(req: web.Request) -> web.Response:
        """Update rule fields: enabled, threshold, severity, window_sec. analyst+ only."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):   # analyst+
            return web.json_response(guard, status=403)
        rule_id = req.match_info["rule_id"]
        body    = await req.json()
        err = detector.rules.update(
            rule_id,
            enabled   = body.get("enabled"),
            threshold = body.get("threshold"),
            severity  = body.get("severity"),
            window    = body.get("window_sec"),
        )
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("rule_updated", {
            "rule_id": rule_id, "by": payload["sub"], "changes": body
        })
        return web.json_response({"ok": True, "rule": detector.rules.get(rule_id).to_dict()})

    @router.post("/api/rules/{rule_id:.*}/enable")
    async def api_rule_enable(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        rule_id = req.match_info["rule_id"]
        err = detector.rules.enable(rule_id)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("rule_enabled", {"rule_id": rule_id, "by": payload["sub"]})
        return web.json_response({"ok": True})

    @router.post("/api/rules/{rule_id:.*}/disable")
    async def api_rule_disable(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        rule_id = req.match_info["rule_id"]
        err = detector.rules.disable(rule_id)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("rule_disabled", {"rule_id": rule_id, "by": payload["sub"]})
        return web.json_response({"ok": True})

    @router.post("/api/rules/{rule_id:.*}/reset")
    async def api_rule_reset(req: web.Request) -> web.Response:
        """Reset rule to built-in defaults. admin only."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "config:write"):
            return web.json_response(guard, status=403)
        rule_id = req.match_info["rule_id"]
        err = detector.rules.reset(rule_id)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("rule_reset", {"rule_id": rule_id, "by": payload["sub"]})
        return web.json_response({"ok": True, "rule": detector.rules.get(rule_id).to_dict()})

    #  Correlation Rules API (routes in dashboard_correlation.py, budget) 
    from .dashboard_correlation import register_correlation_routes
    register_correlation_routes(router, correlator, _require_auth, rbac, logger, _audit)

    #  Case Management API 

    @router.get("/api/cases")
    async def api_cases_list(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:read"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"cases": [], "total": 0})
        q      = req.rel_url.query
        status = q.get("status")
        assigned = q.get("assigned_to")
        severity = q.get("severity")
        limit  = min(int(q.get("limit", 50)), 200)
        offset = int(q.get("offset", 0))
        cases = await case_manager.list_cases(
            status=status, assigned_to=assigned,
            severity=severity, limit=limit, offset=offset,
        )
        total = await case_manager.count(status=status, assigned_to=assigned, severity=severity)
        return web.json_response({"cases": cases, "total": total, "limit": limit, "offset": offset})

    @router.get("/api/cases/stats")
    async def api_cases_stats(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if not case_manager:
            return web.json_response({})
        return web.json_response(await case_manager.stats())

    @router.get("/api/cases/{case_id}")
    async def api_case_get(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:read"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        try:
            case_id = int(req.match_info["case_id"])
        except ValueError:
            return web.json_response({"error": "Invalid case id"}, status=400)
        case = await case_manager.get(case_id)
        if not case:
            return web.json_response({"error": "Not found"}, status=404)
        return web.json_response(case)

    @router.post("/api/cases")
    async def api_case_create(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:write"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        body = await req.json()
        title    = body.get("title", "").strip()
        severity = body.get("severity", "MEDIUM").upper()
        if not title:
            return web.json_response({"error": "title is required"}, status=400)
        case_id = await case_manager.create_manual(
            title=title,
            severity=severity,
            src_ip=body.get("src_ip", ""),
            assigned_to=body.get("assigned_to"),
            created_by=payload["sub"],
            incident_id=body.get("incident_id"),
            reasons=body.get("reasons", []),
            country=body.get("country", ""),
            isp=body.get("isp", ""),
        )
        await logger.log("case_created", {"id": case_id, "by": payload["sub"], "title": title})
        return web.json_response({"ok": True, "case_id": case_id}, status=201)

    @router.patch("/api/cases/{case_id}/status")
    async def api_case_status(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:write"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        try:
            case_id = int(req.match_info["case_id"])
        except ValueError:
            return web.json_response({"error": "Invalid case id"}, status=400)
        body   = await req.json()
        status = body.get("status", "")
        err = await case_manager.update_status(case_id, status, actor=payload["sub"])
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("case_status_updated", {"id": case_id, "status": status, "by": payload["sub"]})
        return web.json_response({"ok": True})

    @router.patch("/api/cases/{case_id}/assign")
    async def api_case_assign(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:write"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        try:
            case_id = int(req.match_info["case_id"])
        except ValueError:
            return web.json_response({"error": "Invalid case id"}, status=400)
        body     = await req.json()
        assignee = body.get("assigned_to")   # None = unassign
        err = await case_manager.assign(case_id, assignee, actor=payload["sub"])
        if err:
            return web.json_response({"error": err}, status=400)
        return web.json_response({"ok": True})

    @router.post("/api/cases/{case_id}/notes")
    async def api_case_add_note(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:write"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        try:
            case_id = int(req.match_info["case_id"])
        except ValueError:
            return web.json_response({"error": "Invalid case id"}, status=400)
        body = await req.json()
        note_body = body.get("body", "").strip()
        err = await case_manager.add_note(case_id, author=payload["sub"], body=note_body)
        if err:
            return web.json_response({"error": err}, status=400)
        return web.json_response({"ok": True})

    @router.delete("/api/cases/{case_id}")
    async def api_case_delete(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "cases:delete"):
            return web.json_response(guard, status=403)
        if not case_manager:
            return web.json_response({"error": "Case management unavailable"}, status=503)
        try:
            case_id = int(req.match_info["case_id"])
        except ValueError:
            return web.json_response({"error": "Invalid case id"}, status=400)
        err = await case_manager.delete(case_id)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("case_deleted", {"id": case_id, "by": payload["sub"]})
        return web.json_response({"ok": True})

    @router.post("/api/logout")
    async def api_logout(req: web.Request) -> web.Response:
        token_str = req.headers.get("Authorization", "").replace("Bearer ", "")
        auth.logout(token_str)
        return web.json_response({"ok": True})

    @router.get("/api/auth-info")
    async def api_auth_info(_: web.Request) -> web.Response:
        return web.json_response({
            "enabled":         auth.enabled,
            "default_password": auth.is_default_password(),
        })

    #  API endpoints 

    @router.get("/api/stats")
    async def api_stats(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        db = await store.stats() if store.available else {}
        return web.json_response({
            "total":            db.get("total", 0),
            "high":             db.get("high", 0),
            "medium":           db.get("medium", 0),
            "low":              db.get("low", 0),
            "unique_ips":       db.get("unique_ips", len(detector._state)),
            "active_blocks":    len(blocker.active_blocks),
            "dry_run":          dry_run,
            "default_password": auth.is_default_password(),
        })

    @router.get("/api/incidents")
    async def api_incidents(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 50))
            limit = max(1, min(limit, 500))  # clamp: 1–500
        except (ValueError, TypeError):
            limit = 50
        rows  = await store.recent_incidents(limit) if store.available else []
        return web.json_response(rows)

    @router.get("/api/top-attackers")
    async def api_top(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.top_attackers() if store.available else []
        return web.json_response(rows)

    @router.get("/api/timeline")
    async def api_timeline(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.timeline_24h() if store.available else []
        return web.json_response(rows)

    @router.get("/api/blocks")
    async def api_blocks(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.active_blocks() if store.available else []
        if not rows:
            rows = [
                {"ip": ip, "unblock_at": exp,
                 "blocked_at": exp - blocker.block_duration_sec}
                for ip, exp in blocker.active_blocks.items()
            ]
        return web.json_response(rows)

    @router.get("/api/events")
    async def api_events(req: web.Request) -> web.Response:
        """Raw recent events — alias for /api/incidents with richer fields."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 50))
            limit = max(1, min(limit, 500))
        except (ValueError, TypeError):
            limit = 50
        rows = await store.recent_incidents(limit) if store.available else []
        return web.json_response(rows)

    @router.get("/api/search")
    async def api_search(req: web.Request) -> web.Response:
        """
        Full-text search over incidents.

        Query params:
          q         KQL-like query string (e.g. "severity:HIGH", "country:China", "1.2.3.4")
          severity  Filter by severity (HIGH / MEDIUM / LOW)
          since     Unix timestamp — events after this time
          until     Unix timestamp — events before this time
          limit     Max results (default 50, max 500)
          offset    Pagination offset (default 0)
        """
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        q        = req.rel_url.query.get("q", "")
        severity = req.rel_url.query.get("severity")
        try:
            since  = float(req.rel_url.query["since"]) if "since" in req.rel_url.query else None
            until  = float(req.rel_url.query["until"]) if "until" in req.rel_url.query else None
            limit  = int(req.rel_url.query.get("limit", 50))
            offset = int(req.rel_url.query.get("offset", 0))
            limit  = max(1, min(limit, 500))
            offset = max(0, offset)
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid numeric parameter"}, status=400)

        if search_engine and search_engine.available:
            result = await search_engine.search(
                query=q, since=since, until=until,
                severity=severity, limit=limit, offset=offset,
            )
        else:
            # Fallback to store when search engine not available
            rows   = await store.recent_incidents(limit) if store.available else []
            result = {"total": len(rows), "hits": rows, "took_ms": 0}

        return web.json_response(result)

    @router.get("/api/aggregate")
    async def api_aggregate(req: web.Request) -> web.Response:
        """
        Aggregations over incidents.

        Query params:
          since  Unix timestamp
          until  Unix timestamp

        Returns: by_severity, top_ips, top_countries, hourly buckets
        """
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        try:
            since = float(req.rel_url.query["since"]) if "since" in req.rel_url.query else None
            until = float(req.rel_url.query["until"]) if "until" in req.rel_url.query else None
        except (ValueError, TypeError):
            return web.json_response({"error": "Invalid numeric parameter"}, status=400)

        if search_engine and search_engine.available:
            result = await search_engine.aggregate(since=since, until=until)
        else:
            result = {}

        return web.json_response(result)

    @router.get("/api/search/es-status")
    async def api_es_status(req: web.Request) -> web.Response:
        """Elasticsearch/OpenSearch cluster health."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        if es_pusher and es_pusher.enabled:
            health = await es_pusher.health()
        else:
            health = {"enabled": False}

        return web.json_response(health)

    @router.post("/api/search/es-push")
    async def api_es_push(req: web.Request) -> web.Response:
        """Manually push recent incidents to Elasticsearch."""
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "block:write")): return r

        if not es_pusher or not es_pusher.enabled:
            return web.json_response({"error": "Elasticsearch not enabled"}, status=400)

        try:
            body  = await req.json()
            limit = int(body.get("limit", 100))
            limit = max(1, min(limit, 1000))
        except Exception:
            limit = 100

        rows = await store.recent_incidents(limit) if store.available else []
        from .normalizer import normalize
        from .models import Event, now as _now
        norms = []
        for row in rows:
            ev = Event(
                ts     = float(row.get("ts", _now())),
                source = row.get("source", "cnsl"),
                kind   = row.get("kind") or row.get("cnsl_kind", "SSH_FAIL"),
                src_ip = row.get("src_ip"),
                user   = row.get("user"),
                meta   = {},
            )
            norms.append(normalize(ev))

        result = await es_pusher.push(norms)
        return web.json_response(result)

    #  Graph API

    @router.get("/api/graph")
    async def api_graph(req: web.Request) -> web.Response:
        """
        Return pre-computed behavior graph data (nodes + edges).
        Used by external consumers; the dashboard builds its own graph
        client-side by combining /api/attackers, /api/kill-chain, etc.
        """
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        limit    = int(req.rel_url.query.get("limit", 50))
        min_inc  = int(req.rel_url.query.get("min_incidents", 1))
        attackers = await store.top_attackers(limit=limit * 2)
        filtered  = [a for a in attackers if (a.get("incident_count") or 1) >= min_inc][:limit]
        ip_set    = {a["src_ip"] for a in filtered}

        # Kill chain data
        kc_map = {}
        if kill_chain:
            for chain in kill_chain.get_all(limit=limit):
                kc_map[chain.ip] = chain.to_dict()

        # Zero-trust data
        zt_map = {}
        if zero_trust:
            for rec in zero_trust.get_all(entity_type="ip", limit=limit*2):
                zt_map[rec.entity_id] = rec.to_dict()

        nodes = []
        for a in filtered:
            ip = a["src_ip"]
            nodes.append({
                "ip":            ip,
                "incident_count": a.get("incident_count", 0),
                "max_severity":   a.get("max_severity", ""),
                "country":        a.get("country", ""),
                "kill_chain":     kc_map.get(ip),
                "trust":          zt_map.get(ip),
            })

        # Edges: shared rules
        incidents = await store.recent_incidents(limit=200)
        rules_by_ip = {}
        for inc in incidents:
            if inc.get("src_ip") not in ip_set:
                continue
            for r in (inc.get("reasons") or []):
                rule = r.split(":")[0].strip()
                rules_by_ip.setdefault(inc["src_ip"], set()).add(rule)

        ip_list = [n["ip"] for n in nodes]
        edges   = []
        for i in range(len(ip_list)):
            for j in range(i+1, len(ip_list)):
                a_rules = rules_by_ip.get(ip_list[i], set())
                b_rules = rules_by_ip.get(ip_list[j], set())
                shared  = sorted(a_rules & b_rules)
                if shared:
                    edges.append({"source": ip_list[i], "target": ip_list[j],
                                  "shared_rules": shared})

        return web.json_response({"nodes": nodes, "edges": edges})

    #  Zero-Trust API

    @router.get("/api/zero-trust/stats")
    async def api_zt_stats(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if zero_trust is None:
            return web.json_response({"error": "Zero-trust not enabled"}, status=400)
        return web.json_response(zero_trust.stats())

    @router.get("/api/zero-trust/scores")
    async def api_zt_scores(req: web.Request) -> web.Response:
        """Return all scored entities sorted by score ascending (untrusted first)."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if zero_trust is None:
            return web.json_response({"error": "Zero-trust not enabled"}, status=400)
        entity_type = req.rel_url.query.get("type")   # "ip" or "user"
        max_score   = float(req.rel_url.query.get("max_score", 1.0))
        limit       = int(req.rel_url.query.get("limit", 100))
        records     = zero_trust.get_all(entity_type=entity_type,
                                         max_score=max_score, limit=limit)
        return web.json_response([r.to_dict() for r in records])

    @router.get("/api/zero-trust/scores/{entity_id:.*}")
    async def api_zt_score_entity(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if zero_trust is None:
            return web.json_response({"error": "Zero-trust not enabled"}, status=400)
        entity_id   = req.match_info.get("entity_id", "")
        entity_type = req.rel_url.query.get("type", "ip")
        record      = zero_trust.get_record(entity_id, entity_type)
        if record is None:
            return web.json_response({"error": f"No score for {entity_id}"}, status=404)
        return web.json_response(record.to_dict())

    @router.post("/api/zero-trust/scores/{entity_id:.*}/reset")
    async def api_zt_reset(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if zero_trust is None:
            return web.json_response({"error": "Zero-trust not enabled"}, status=400)
        entity_id   = req.match_info.get("entity_id", "")
        entity_type = req.rel_url.query.get("type", "ip")
        ok = zero_trust.reset(entity_id, entity_type)
        if not ok:
            return web.json_response({"error": f"Not found: {entity_id}"}, status=404)
        await logger.log("zero_trust_reset", {"entity_id": entity_id, "entity_type": entity_type})
        return web.json_response({"ok": True})

    #  Cloud Identity API

    @router.get("/api/cloud-identity/status")
    async def api_cloud_identity_status(req: web.Request) -> web.Response:
        """Return cloud identity connector health and event counts."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if cloud_identity is None:
            return web.json_response({"error": "Cloud identity not enabled"}, status=400)
        return web.json_response(cloud_identity.status())

    #  Federation API

    @router.get("/api/federation/status")
    async def api_federation_status(req: web.Request) -> web.Response:
        """Return this node's federation health and stats."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if federation is None:
            return web.json_response({"error": "Federation not enabled"}, status=400)
        return web.json_response(federation.status())

    @router.get("/api/federation/nodes")
    async def api_federation_nodes(req: web.Request) -> web.Response:
        """Return all peer nodes this node has heard from."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if federation is None:
            return web.json_response({"error": "Federation not enabled"}, status=400)
        return web.json_response({"nodes": federation.known_nodes()})

    @router.get("/api/federation/cross-node")
    async def api_federation_cross_node(req: web.Request) -> web.Response:
        """Return IPs that have been reported by 2+ distinct nodes."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if federation is None:
            return web.json_response({"error": "Federation not enabled"}, status=400)
        limit   = int(req.rel_url.query.get("limit", 50))
        records = federation.get_cross_node_ips(limit=limit)
        return web.json_response([r.to_dict() for r in records])

    @router.get("/api/federation/ip/{ip}")
    async def api_federation_ip(req: web.Request) -> web.Response:
        """Return the combined cross-node view for one IP."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if federation is None:
            return web.json_response({"error": "Federation not enabled"}, status=400)
        ip     = req.match_info.get("ip", "")
        record = federation.get_ip_record(ip)
        if record is None:
            return web.json_response({"error": f"No federation record for {ip}"}, status=404)
        return web.json_response(record.to_dict())

    from .dashboard_hub import register_hub_routes
    register_hub_routes(router, redis_sync, federation, _require_auth, _rate_check)

    from .dashboard_fingerprint import register_fingerprint_routes
    register_fingerprint_routes(router, store, _require_auth, _rate_check)

    from .dashboard_graph_correlation import register_graph_correlation_routes
    register_graph_correlation_routes(router, store, kill_chain, _require_auth, _rate_check)

    #  SIEM Connector API

    @router.get("/api/siem/status")
    async def api_siem_status(req: web.Request) -> web.Response:
        """Return health and queue stats for all SIEM connectors."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if siem_router is None:
            return web.json_response({"error": "SIEM router not enabled"}, status=400)
        status = await siem_router.status()
        return web.json_response(status)

    @router.post("/api/siem/test/{name}")
    async def api_siem_test(req: web.Request) -> web.Response:
        """Send a synthetic test event to one connector (splunk|sentinel|webhook)."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if siem_router is None:
            return web.json_response({"error": "SIEM router not enabled"}, status=400)
        name = req.match_info.get("name", "").lower()
        connector_map = {
            "splunk":   siem_router.splunk,
            "sentinel": siem_router.sentinel,
            "webhook":  siem_router.webhook,
        }
        connector = connector_map.get(name)
        if not connector:
            return web.json_response(
                {"error": f"Unknown connector: {name}. Valid: splunk, sentinel, webhook"},
                status=400,
            )
        if not connector.enabled:
            return web.json_response({"error": f"Connector {name} is not enabled"}, status=400)
        test_event = {
            "ip":       "127.0.0.1",
            "severity": "LOW",
            "ts":       now(),
            "reasons":  ["CNSL test event"],
            "rule":     "test",
            "_test":    True,
        }
        ok = await connector.push(test_event)
        await logger.log("siem_test", {"connector": name, "ok": ok})
        return web.json_response({"ok": ok, "connector": name})

    @router.post("/api/siem/flush")
    async def api_siem_flush(req: web.Request) -> web.Response:
        """Force flush the SIEM retry queue."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if siem_router is None:
            return web.json_response({"error": "SIEM router not enabled"}, status=400)
        counts = await siem_router.flush_queue()
        await logger.log("siem_flush", {"counts": counts})
        return web.json_response({"flushed": counts})

    #  Pattern Learner API

    @router.get("/api/pattern-suggestions")
    async def api_pattern_suggestions_list(req: web.Request) -> web.Response:
        """Return all active (non-dismissed, non-promoted) suggestions."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if pattern_learner is None:
            return web.json_response({"error": "Pattern learner not enabled"}, status=400)
        include_dismissed = req.rel_url.query.get("dismissed", "").lower() == "true"
        include_promoted  = req.rel_url.query.get("promoted",  "").lower() == "true"
        suggestions = pattern_learner.get_suggestions(
            include_dismissed=include_dismissed,
            include_promoted=include_promoted,
        )
        return web.json_response([s.to_dict() for s in suggestions])

    @router.get("/api/pattern-suggestions/stats")
    async def api_pattern_suggestions_stats(req: web.Request) -> web.Response:
        """Return aggregate pattern learner statistics."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if pattern_learner is None:
            return web.json_response({"error": "Pattern learner not enabled"}, status=400)
        return web.json_response(pattern_learner.stats())

    @router.post("/api/pattern-suggestions/{sid}/promote")
    async def api_pattern_suggestions_promote(req: web.Request) -> web.Response:
        """Promote a suggestion -- marks it as promoted and returns the rule dict."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if pattern_learner is None:
            return web.json_response({"error": "Pattern learner not enabled"}, status=400)
        sid  = req.match_info.get("sid", "")
        sugg = pattern_learner.get_suggestion(sid)
        if not sugg:
            return web.json_response({"error": f"Suggestion {sid} not found"}, status=404)
        pattern_learner.mark_promoted(sid)
        if store.available:
            await pattern_learner.save_suggestion(store, sugg)
        await logger.log("pattern_promoted", {"id": sid, "pattern": sugg.pattern_key})
        return web.json_response(sugg.to_dict())

    @router.post("/api/pattern-suggestions/{sid}/dismiss")
    async def api_pattern_suggestions_dismiss(req: web.Request) -> web.Response:
        """Dismiss a suggestion -- suppresses it permanently."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if pattern_learner is None:
            return web.json_response({"error": "Pattern learner not enabled"}, status=400)
        sid = req.match_info.get("sid", "")
        ok  = pattern_learner.dismiss(sid)
        if not ok:
            return web.json_response({"error": f"Suggestion {sid} not found"}, status=404)
        sugg = pattern_learner.get_suggestion(sid)
        if sugg and store.available:
            await pattern_learner.save_suggestion(store, sugg)
        await logger.log("pattern_dismissed", {"id": sid})
        return web.json_response({"ok": True})

    #  Kill Chain API

    @router.get("/api/kill-chain")
    async def api_kill_chain_list(req: web.Request) -> web.Response:
        """Return all active kill chains sorted by score descending."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if kill_chain is None:
            return web.json_response({"error": "Kill chain tracker not enabled"}, status=400)
        limit         = int(req.rel_url.query.get("limit", 100))
        min_score     = float(req.rel_url.query.get("min_score", 0.0))
        complete_only = req.rel_url.query.get("complete_only", "").lower() == "true"
        chains = kill_chain.get_all(
            limit=limit,
            min_score=min_score,
            complete_only=complete_only,
        )
        return web.json_response([c.to_dict() for c in chains])

    @router.get("/api/kill-chain/stats")
    async def api_kill_chain_stats(req: web.Request) -> web.Response:
        """Return aggregate kill chain statistics."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if kill_chain is None:
            return web.json_response({"error": "Kill chain tracker not enabled"}, status=400)
        return web.json_response(kill_chain.stats())

    @router.get("/api/kill-chain/{ip}")
    async def api_kill_chain_ip(req: web.Request) -> web.Response:
        """Return full kill chain detail for one source IP."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if kill_chain is None:
            return web.json_response({"error": "Kill chain tracker not enabled"}, status=400)
        ip    = req.match_info.get("ip", "")
        chain = kill_chain.get_chain(ip)
        if chain is None:
            return web.json_response({"error": f"No kill chain found for {ip}"}, status=404)
        return web.json_response(chain.to_dict())

    @router.get("/api/debug")
    async def api_debug(req: web.Request) -> web.Response:
        """Diagnostic endpoint — shows what modules are wired."""
        return web.json_response({
            "ml_detector_wired":       ml_detector is not None,
            "ml_detector_enabled":     getattr(ml_detector, "enabled", None),
            "fim_wired":               fim is not None,
            "fim_enabled":             getattr(fim, "enabled", None),
            "honeypot_wired":          honeypot is not None,
            "honeypot_enabled":        getattr(honeypot, "enabled", None),
            "assets_wired":            assets is not None,
            "search_engine_wired":     search_engine is not None,
            "search_engine_ready":     getattr(search_engine, "available", False),
            "es_pusher_wired":         es_pusher is not None,
            "es_pusher_enabled":       getattr(es_pusher, "enabled", False),
            "kill_chain_wired":        kill_chain is not None,
            "kill_chain_enabled":      getattr(kill_chain, "enabled", False),
            "pattern_learner_wired":   pattern_learner is not None,
            "pattern_learner_enabled": getattr(pattern_learner, "enabled", False),
            "siem_splunk_enabled":     getattr(getattr(siem_router, "splunk",   None), "enabled", False),
            "siem_sentinel_enabled":   getattr(getattr(siem_router, "sentinel", None), "enabled", False),
            "siem_webhook_enabled":    getattr(getattr(siem_router, "webhook",  None), "enabled", False),
            "federation_wired":        federation is not None,
            "federation_enabled":      getattr(federation, "enabled", False),
            "federation_connected":    getattr(federation, "is_connected", False),
            "cloud_identity_wired":    cloud_identity is not None,
            "cloud_identity_enabled":  getattr(cloud_identity, "enabled", False),
            "cloud_aws_enabled":       getattr(getattr(cloud_identity, "aws",      None), "enabled", False),
            "cloud_azure_enabled":     getattr(getattr(cloud_identity, "azure_ad", None), "enabled", False),
            "zero_trust_wired":        zero_trust is not None,
            "zero_trust_enabled":      getattr(zero_trust, "enabled", False),
        })

    @router.get("/api/ml-status")
    async def api_ml_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response({"enabled": False})
        return web.json_response(ml_detector.status())

    @router.patch("/api/ml/params")
    async def api_ml_params(req: web.Request) -> web.Response:
        """Live-update ML parameters without restart."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response({"error": "ML not enabled"}, status=400)
        try:
            body = await req.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)
        result = ml_detector.update_params(
            contamination        = body.get("contamination"),
            threshold            = body.get("threshold"),
            min_samples          = body.get("min_samples"),
            retrain_interval_sec = body.get("retrain_interval_sec"),
        )
        await logger.log("ml_params_updated", result.get("updated", {}))
        return web.json_response(result)

    @router.post("/api/ml/retrain")
    async def api_ml_retrain(req: web.Request) -> web.Response:
        """Force an immediate ML retrain."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response({"error": "ML not enabled"}, status=400)
        result = await ml_detector.trigger_retrain()
        await logger.log("ml_retrain_triggered", result)
        return web.json_response(result)

    @router.get("/api/ml/alerts")
    async def api_ml_alerts(req: web.Request) -> web.Response:
        """Return recent ML anomaly alerts."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response([])
        limit = int(req.rel_url.query.get("limit", 50))
        return web.json_response(ml_detector.recent_alerts_list(limit=limit))

    @router.get("/api/ml/feature-stats")
    async def api_ml_feature_stats(req: web.Request) -> web.Response:
        """Return feature importance counts from recent ML alerts."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response({})
        return web.json_response(ml_detector.feature_stats())

    from .dashboard_ml import register_ml_feedback_routes
    register_ml_feedback_routes(router, ml_detector, _require_auth, rbac, logger, _audit, _rate_check)

    @router.get("/api/honeypot")
    async def api_honeypot_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if honeypot is None:
            return web.json_response({"enabled": False, "sessions": []})
        try:
            limit = int(req.rel_url.query.get("limit", 20))
        except (ValueError, TypeError):
            limit = 20
        return web.json_response({
            **honeypot.status(),
            "sessions": honeypot.recent_sessions(limit),
        })

    @router.get("/api/fim")
    async def api_fim(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if fim is None or not getattr(fim, "enabled", False):
            return web.json_response({"enabled": False, "alerts": []})
        try:
            limit = int(req.rel_url.query.get("limit", 30))
        except (ValueError, TypeError):
            limit = 30
        alerts = fim.recent_alerts(limit)
        return web.json_response({
            "enabled":     fim.enabled,
            "watch_paths": getattr(fim, "_watch_paths", []),
            "alerts":      alerts,
        })

    @router.get("/api/health")
    async def api_health(req: web.Request) -> web.Response:
        """
        Health check endpoint for load balancers and Kubernetes probes.

        Does NOT require authentication -- liveness probes must work
        without credentials.

        Returns HTTP 200 with status="healthy" or status="degraded"
        when CNSL is functioning. Returns HTTP 503 when unhealthy.

        Status levels:
          healthy   -- all checks passing
          degraded  -- optional components unavailable (Redis, ML)
                       but core detection is functioning
          unhealthy -- database unavailable or event queue backed up;
                       Kubernetes will restart the pod
        """
        import time as _t

        checks = {}
        overall = "healthy"

        # -- Database check --
        if store.available:
            t0 = _t.monotonic()
            try:
                await store.db_fetchall("SELECT 1", None)
                db_latency = round((_t.monotonic() - t0) * 1000, 1)
                checks["database"] = {"status": "ok", "latency_ms": db_latency}
            except Exception as e:
                checks["database"] = {"status": "error", "error": str(e)[:80]}
                overall = "unhealthy"
        else:
            checks["database"] = {"status": "unavailable"}
            # DB unavailable is only unhealthy if persistence was expected
            if overall == "healthy":
                overall = "degraded"

        # -- Redis check --
        if redis_sync is not None and redis_sync.connected:
            t0 = _t.monotonic()
            try:
                await redis_sync._redis.ping()
                redis_latency = round((_t.monotonic() - t0) * 1000, 1)
                checks["redis"] = {"status": "ok", "latency_ms": redis_latency}
            except Exception as e:
                checks["redis"] = {"status": "error", "error": str(e)[:80]}
                if overall == "healthy":
                    overall = "degraded"
        else:
            checks["redis"] = {"status": "disabled"}

        # -- Event queue check --
        try:
            q_depth = queue.qsize() if hasattr(queue, "qsize") else -1
            q_status = "ok"
            if q_depth > 5000:
                q_status = "backlogged"
                overall = "degraded"
            elif q_depth > 20000:
                q_status = "critical"
                overall = "unhealthy"
            checks["event_queue"] = {"status": q_status, "depth": q_depth}
        except Exception:
            checks["event_queue"] = {"status": "unknown"}

        # -- Last event age check --
        try:
            last_ts = getattr(metrics, "_last_event_ts", None)
            if last_ts:
                age = int(_t.time() - last_ts)
                checks["last_event"] = {"status": "ok", "age_sec": age}
            else:
                checks["last_event"] = {"status": "no_events_yet"}
        except Exception:
            checks["last_event"] = {"status": "unknown"}

        # -- Detector check --
        try:
            tracked = len(detector._state) if hasattr(detector, "_state") else -1
            checks["detector"] = {"status": "ok", "tracked_ips": tracked}
        except Exception:
            checks["detector"] = {"status": "unknown"}

        # -- ML check (degraded only, never unhealthy) --
        if ml_detector:
            ml_st = ml_detector.status()
            checks["ml"] = {
                "status":  "ok" if ml_st.get("enabled") else "disabled",
                "trained": ml_st.get("trained", False),
            }
            if ml_st.get("enabled") and not ml_st.get("trained"):
                checks["ml"]["status"] = "training"

        import time as _t2
        uptime = int(_t2.time() - metrics._start) if hasattr(metrics, "_start") else 0

        body = {
            "status":      overall,
            "version":     __version__,
            "uptime_sec":  uptime,
            "checks":      checks,
        }

        http_status = 200 if overall in ("healthy", "degraded") else 503
        return web.json_response(body, status=http_status)

    @router.get("/api/system")
    async def api_system(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        import time as _t
        uptime = int(_t.time() - metrics._start)
        return web.json_response({
            "uptime_sec":       uptime,
            "ssh_fails_total":  metrics.ssh_fails_total,
            "events_processed": metrics.events_processed,
            "blocks_total":     metrics.blocks_total,
        })

    @router.get("/api/events/normalized")
    async def api_events_normalized(req: web.Request) -> web.Response:
        """Return recent incidents as ECS-normalized JSON documents."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 50))
            limit = max(1, min(limit, 500))
        except (ValueError, TypeError):
            limit = 50
        rows = await store.recent_incidents(limit) if store.available else []
        from .normalizer import normalize
        from .models import Event, now as _now
        normalized = []
        for row in rows:
            # Reconstruct a minimal Event from stored incident for normalization
            ev = Event(
                ts     = float(row.get("ts", _now())),
                source = row.get("source", "cnsl"),
                kind   = row.get("kind") or row.get("cnsl_kind", "SSH_FAIL"),
                src_ip = row.get("src_ip"),
                user   = row.get("user"),
                raw    = row.get("raw"),
                meta   = {},
            )
            norm = normalize(ev)
            d    = norm.to_dict()
            # Merge stored incident fields
            d["cnsl"]["severity"]   = row.get("severity")
            d["cnsl"]["reasons"]    = row.get("reasons", [])
            d["cnsl"]["fail_count"] = row.get("fail_count", 0)
            d["cnsl"]["country"]    = row.get("country")
            normalized.append(d)
        return web.json_response(normalized)

    @router.get("/api/export/ecs")
    async def api_export_ecs(req: web.Request) -> web.Response:
        """Export recent incidents as Elasticsearch bulk-index NDJSON."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 200))
            limit = max(1, min(limit, 1000))
        except (ValueError, TypeError):
            limit = 200
        index = req.rel_url.query.get("index", "cnsl-events")
        rows  = await store.recent_incidents(limit) if store.available else []
        from .normalizer import normalize
        from .models import Event, now as _now
        import json as _json
        lines = []
        for row in rows:
            ev = Event(
                ts     = float(row.get("ts", _now())),
                source = row.get("source", "cnsl"),
                kind   = row.get("kind") or row.get("cnsl_kind", "SSH_FAIL"),
                src_ip = row.get("src_ip"),
                user   = row.get("user"),
                meta   = {},
            )
            norm   = normalize(ev)
            action = _json.dumps({"index": {"_index": index}})
            doc    = norm.to_ecs_json()
            lines.append(action)
            lines.append(doc)
        body = "\n".join(lines) + "\n"
        return web.Response(
            text         = body,
            content_type = "application/x-ndjson",
            headers      = {"Content-Disposition": "attachment; filename=cnsl-events.ndjson"},
        )

    @router.get("/api/export/cef")
    async def api_export_cef(req: web.Request) -> web.Response:
        """Export recent incidents as CEF (ArcSight/Splunk compatible) text."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 200))
            limit = max(1, min(limit, 1000))
        except (ValueError, TypeError):
            limit = 200
        rows = await store.recent_incidents(limit) if store.available else []
        from .normalizer import normalize
        from .models import Event, now as _now
        lines = []
        for row in rows:
            ev = Event(
                ts     = float(row.get("ts", _now())),
                source = row.get("source", "cnsl"),
                kind   = row.get("kind") or row.get("cnsl_kind", "SSH_FAIL"),
                src_ip = row.get("src_ip"),
                user   = row.get("user"),
                meta   = {},
            )
            norm = normalize(ev)
            lines.append(norm.to_cef())
        body = "\n".join(lines) + "\n"
        return web.Response(
            text         = body,
            content_type = "text/plain",
            headers      = {"Content-Disposition": "attachment; filename=cnsl-events.cef"},
        )

    from .taxii import register_stix_export_route, register_taxii_routes
    register_stix_export_route(router, store, _require_auth, _rate_check)
    register_taxii_routes(router, store, _require_auth, _rate_check)

    @router.get("/api/metrics")
    async def api_metrics(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return web.Response(text=metrics.render(), content_type="text/plain")

    @router.post("/api/block")
    async def api_block(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "block:write")): return r
        body = await req.json()
        ip   = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return web.json_response({"error": f"invalid IP address: {ip!r}"}, status=400)
        ok = await blocker.block_ip(ip, reason=f"manual:{user_payload.get('sub','?')}")
        await logger.log("dashboard_manual_block", {"ip": ip, "by": user_payload.get("sub"), "ok": ok})
        await _audit(req, user_payload, "block", target=ip, details={"ok": ok})
        return web.json_response({"blocked": ok, "ip": ip})

    @router.post("/api/unblock")
    async def api_unblock(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "unblock:write")): return r
        body = await req.json()
        ip   = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        await blocker._unblock_ip(ip)
        await logger.log("dashboard_manual_unblock", {"ip": ip, "by": user_payload.get("sub")})
        await _audit(req, user_payload, "unblock", target=ip)
        return web.json_response({"unblocked": True, "ip": ip})

    #  SSE (kept for backward compatibility) 

    @router.get("/stream")
    async def sse_stream(req: web.Request) -> web.Response:
        ip = _get_client_ip(req)
        if _sse_limiter.is_limited(ip):
            return web.json_response({"error": "Too many SSE connections"}, status=429)

        _, err = _require_auth(req)
        if err: return err

        resp = web.StreamResponse(headers={
            "Content-Type":      "text/event-stream",
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        })
        await resp.prepare(req)

        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        _subscribers.append(q)

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    await resp.write(f"data: {msg}\n\n".encode())
                except asyncio.TimeoutError:
                    await resp.write(b": heartbeat\n\n")
        except Exception:
            pass
        finally:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass

        return resp

    #  WebSocket — bidirectional live feed + actions 

    @router.get("/ws")
    async def ws_handler(req: web.Request) -> web.WebSocketResponse:
        """
        WebSocket endpoint — replaces SSE with a bidirectional channel.

        Auth: send {"type":"auth","token":"..."} as first message.

        Server → client messages:
          {"type":"event",  "data": {...}}   — live detection event
          {"type":"ping"}                    — keepalive

        Client → server messages:
          {"type":"block",   "ip": "1.2.3.4"}
          {"type":"unblock", "ip": "1.2.3.4"}
          {"type":"ping"}
        """
        ws = web.WebSocketResponse(heartbeat=20)
        await ws.prepare(req)

        # Auth handshake — first message must be {"type":"auth","token":"..."}
        ws_payload = None
        try:
            first = await asyncio.wait_for(ws.receive(), timeout=10)
            if first.type != aiohttp.WSMsgType.TEXT:
                await ws.close(code=4001, message=b"expected auth message")
                return ws
            data = json.loads(first.data)
            if data.get("type") != "auth" or not data.get("token"):
                await ws.close(code=4001, message=b"missing auth token")
                return ws
            ws_payload, err = auth.verify_token(data["token"])
            if err:
                await ws.close(code=4003, message=err.encode())
                return ws
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
            await ws.close(code=4001, message=b"auth timeout")
            return ws

        await ws.send_json({"type": "auth_ok", "role": ws_payload["role"]})

        # Subscribe to live events
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        _subscribers.append(q)

        async def _reader() -> None:
            """Handle inbound client messages (block/unblock actions)."""
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    break
                try:
                    cmd = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                cmd_type = cmd.get("type", "")
                ip       = cmd.get("ip", "").strip()

                if cmd_type == "block" and ip:
                    if rbac.can(ws_payload["role"], "block:write"):
                        blocker.block(ip, duration=900, reason="manual_ws")
                        await logger.log("ws_block", {"ip": ip, "by": ws_payload["sub"]})
                        await ws.send_json({"type": "block_ok", "ip": ip})
                    else:
                        await ws.send_json({"type": "error", "msg": "insufficient permissions"})

                elif cmd_type == "unblock" and ip:
                    if rbac.can(ws_payload["role"], "unblock:write"):
                        blocker.unblock(ip)
                        await logger.log("ws_unblock", {"ip": ip, "by": ws_payload["sub"]})
                        await ws.send_json({"type": "unblock_ok", "ip": ip})
                    else:
                        await ws.send_json({"type": "error", "msg": "insufficient permissions"})

                elif cmd_type == "ping":
                    await ws.send_json({"type": "pong"})

        async def _writer() -> None:
            """Push queued events to the client."""
            while not ws.closed:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    await ws.send_str(f'{{"type":"event","data":{msg}}}')
                except asyncio.TimeoutError:
                    try:
                        await ws.send_json({"type": "ping"})
                    except Exception:
                        break
                except Exception:
                    break

        try:
            await asyncio.gather(_reader(), _writer(), return_exceptions=True)
        finally:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass

        return ws

    #  WebSocket — Agent ingestion endpoint 

    @router.get("/ws/agent")
    async def ws_agent_handler(req: web.Request) -> web.WebSocketResponse:
        """
        WebSocket endpoint for CNSL agents running on remote servers.

        Agents connect here, authenticate via Bearer token in headers,
        then stream batches of log events.

        Agent → server: {"type":"agent_events","host":"...","events":[...]}
        Server → agent: {"ok":true} (handshake ack) or {"type":"pong"}
        """
        # Auth from header (agents don't do an interactive handshake)
        token_str = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not token_str:
            # Try query param for agent connections
            token_str = req.rel_url.query.get("token", "")
        ws_payload, err = auth.verify_token(token_str)
        if err:
            # Return 401 before upgrading
            raise web.HTTPUnauthorized(reason=err)

        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(req)

        agent_host = "unknown"

        async for msg in ws:
            if msg.type != aiohttp.WSMsgType.TEXT:
                break
            try:
                data = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type", "")

            if msg_type == "agent_hello":
                agent_host = data.get("hostname", "unknown")
                await logger.log("agent_connected", {
                    "host": agent_host, "version": data.get("version"),
                    "platform": data.get("platform"),
                })
                await ws.send_json({"ok": True, "msg": f"Welcome {agent_host}"})

            elif msg_type == "agent_events":
                events = data.get("events", [])
                agent_host = data.get("host", agent_host)
                for ev_dict in events:
                    try:
                        from .models import Event
                        # Reconstruct Event from dict, tag with agent host
                        ev_dict.setdefault("source", f"agent:{agent_host}")
                        ev_dict.setdefault("meta", {})
                        if isinstance(ev_dict.get("meta"), dict):
                            ev_dict["meta"]["_agent_host"] = agent_host
                        ev = Event(
                            ts     = ev_dict.get("ts", 0),
                            source = ev_dict.get("source", "agent"),
                            kind   = ev_dict.get("kind", "UNKNOWN"),
                            src_ip = ev_dict.get("src_ip", ""),
                            user   = ev_dict.get("user"),
                            meta   = ev_dict.get("meta", {}),
                        )
                        if ev.src_ip:
                            await detector.handle(ev)
                    except Exception:
                        pass

            elif msg_type == "ping":
                await ws.send_json({"type": "pong"})

        await logger.log("agent_disconnected", {"host": agent_host})
        return ws

    @router.post("/api/notify/test")
    async def api_notify_test(req: web.Request) -> web.Response:
        """Send a test message to all enabled notification channels."""
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "block:write")): return r
        if notifier is None:
            return web.json_response({"error": "Notifier not wired"}, status=400)
        results = await notifier.test_channels()
        return web.json_response({"results": results})

    @router.post("/api/auth/rotate-secret")
    async def api_rotate_secret(req: web.Request) -> web.Response:
        """Rotate JWT signing secret — invalidates ALL active sessions."""
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "admin")): return r
        auth.rotate_secret()
        await _audit(req, user_payload, "rotate_secret")
        return web.json_response({"ok": True, "message": "Secret rotated — all sessions invalidated."})

    @router.get("/api/audit")
    async def api_audit(req: web.Request) -> web.Response:
        """Compliance audit trail — who did what, when. Requires logs:read."""
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "logs:read")): return r
        if audit_log is None:
            return web.json_response({"entries": [], "total": 0})
        q = req.rel_url.query
        actor  = q.get("actor")
        action = q.get("action")
        target = q.get("target")
        limit  = safe_int(q.get("limit"), 100)
        offset = safe_int(q.get("offset"), 0)
        entries = await audit_log.list(actor=actor, action=action, target=target,
                                        limit=limit, offset=offset)
        total = await audit_log.count(actor=actor, action=action)
        return web.json_response({"entries": entries, "total": total})

    #  Start 

    # 4 MB request size limit -- prevents large-payload memory spikes
    app = web.Application(client_max_size=4 * 1024 * 1024)
    app.add_routes(router)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    auth_status = "enabled" if auth.enabled else "disabled (open access)"
    await logger.log("dashboard_started", {
        "url":  f"http://{host}:{port}",
        "auth": auth_status,
    })
    print(f"\n  Dashboard → http://{host}:{port}  (auth: {auth_status})\n", flush=True)

    await asyncio.Event().wait()