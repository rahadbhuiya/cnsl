"""
cnsl/dashboard_case_sla.py -- case SLA API routes.

Split out of cnsl/dashboard.py (same pattern as the other dashboard_*.py
modules) to keep dashboard.py under its enforced line-count budget.

Routes:
  GET  /api/case-sla/status   Current config + last check's result
  POST /api/case-sla/check    Manually run an SLA check now, instead
                                of waiting for the next scheduled pass

See cnsl/case_sla.py for the actual breach-detection and escalation logic.
"""

from __future__ import annotations

from typing import Any, Callable


def register_case_sla_routes(
    router:         Any,
    case_sla:       Any,
    case_manager:   Any,
    logger:         Any,
    rbac:           Any,
    _require_auth:  Callable,
    _rate_check:    Callable,
) -> None:
    """Attach /api/case-sla/* to `router`.

    Called once from start_dashboard(). `case_sla` may be None
    (feature disabled in config) -- both routes report that plainly
    rather than raising.
    """
    from aiohttp import web

    @router.get("/api/case-sla/status")
    async def api_case_sla_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if case_sla is None:
            return web.json_response({"enabled": False})
        return web.json_response(case_sla.status())

    @router.post("/api/case-sla/check")
    async def api_case_sla_check(req: web.Request) -> web.Response:
        """Run an SLA check immediately -- requires config:write (analyst+ level oversight of cases already needs cases:read; escalation is a config-level action)."""
        if (r := _rate_check(req)): return r
        payload, err = _require_auth(req)
        if err: return err
        if guard := rbac.require(payload["role"], "config:write"):
            return guard
        if case_sla is None:
            return web.json_response({"error": "Case SLA is not enabled"}, status=400)
        if case_manager is None or not getattr(case_manager, "available", False):
            return web.json_response({"error": "Case manager is not available"}, status=400)
        result = await case_sla.check_once(case_manager, logger)
        return web.json_response(result)