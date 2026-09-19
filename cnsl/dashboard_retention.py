"""
cnsl/dashboard_retention.py -- data retention API routes.

Split out of cnsl/dashboard.py (same pattern as dashboard_sigma.py,
dashboard_attack.py, dashboard_oidc.py, dashboard_source_health.py, ...)
to keep dashboard.py under its enforced line-count budget.

Routes:
  GET  /api/retention/status   Current config + last run's result
  POST /api/retention/run      Manually trigger a retention pass now
                                (e.g. right after lowering
                                incidents_max_age_days, rather than
                                waiting for the next scheduled run)

See cnsl/retention.py for the actual purge/archive logic.
"""

from __future__ import annotations

from typing import Any, Callable


def register_retention_routes(
    router:         Any,
    retention:      Any,
    store:          Any,
    audit_log:      Any,
    logger:         Any,
    rbac:           Any,
    _require_auth:  Callable,
    _rate_check:    Callable,
) -> None:
    """Attach /api/retention/* to `router`.

    Called once from start_dashboard(). `retention` may be None
    (feature disabled in config) -- both routes report that plainly
    rather than raising.
    """
    from aiohttp import web

    @router.get("/api/retention/status")
    async def api_retention_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if retention is None:
            return web.json_response({"enabled": False})
        return web.json_response(retention.status())

    @router.post("/api/retention/run")
    async def api_retention_run(req: web.Request) -> web.Response:
        """Run a retention pass immediately, on demand -- requires config:write (admin)."""
        if (r := _rate_check(req)): return r
        payload, err = _require_auth(req)
        if err: return err
        if guard := rbac.require(payload["role"], "config:write"):
            return guard
        if retention is None:
            return web.json_response({"error": "Retention is not enabled"}, status=400)
        if store is None or not getattr(store, "available", False):
            return web.json_response({"error": "Store is not available"}, status=400)
        result = await retention.run_once(store, audit_log, logger)
        return web.json_response(result)