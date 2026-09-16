"""
cnsl/dashboard_source_health.py -- log source health API route.

Split out of cnsl/dashboard.py (same pattern as dashboard_sigma.py,
dashboard_attack.py, dashboard_oidc.py, ...) to keep dashboard.py
under its enforced line-count budget.

Route:
  GET /api/source-health   Current activity status of every registered
                            log source (see cnsl/source_health.py).
"""

from __future__ import annotations

from typing import Any, Callable


def register_source_health_routes(
    router:         Any,
    source_health:  Any,
    _require_auth:  Callable,
    _rate_check:    Callable,
) -> None:
    """Attach /api/source-health to `router`.

    Called once from start_dashboard(). `source_health` may be None
    (feature disabled in config) -- the route reports that plainly
    rather than raising.
    """
    from aiohttp import web

    @router.get("/api/source-health")
    async def api_source_health(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if source_health is None or not source_health.enabled:
            return web.json_response({"enabled": False, "sources": []})
        return web.json_response({
            "enabled": True,
            "check_interval_sec": source_health.check_interval_sec,
            "sources": source_health.status_snapshot(),
        })