"""
cnsl/dashboard_correlation.py -- Correlation Rules API routes.

Split out of cnsl/dashboard.py (same pattern as dashboard_html.py) to
keep dashboard.py under its enforced line-count budget. Registers the
/api/correlation-rules routes onto the dashboard's aiohttp router.

Routes (see cnsl/correlator.py for the underlying Correlator/rule model):
  GET   /api/correlation-rules              List all cross-source rules
  GET   /api/correlation-rules/{name}       Single rule detail
  PATCH /api/correlation-rules/{name}       Tune enabled/window/cooldown/confidence
  POST  /api/correlation-rules/{name}/enable
  POST  /api/correlation-rules/{name}/disable
  POST  /api/correlation-rules/{name}/reset
"""

from __future__ import annotations

from typing import Any, Callable


def register_correlation_routes(
    router:       Any,
    correlator:   Any,
    _require_auth: Callable,
    rbac:         Any,
    logger:       Any,
    _audit:       Callable,
) -> None:
    """Attach the /api/correlation-rules routes to `router`.

    Called once from start_dashboard(). `correlator` may be None (e.g.
    in tests that don't wire one up) -- every handler degrades to an
    empty list / 404 rather than raising.
    """
    from aiohttp import web

    @router.get("/api/correlation-rules")
    async def api_correlation_rules_list(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if correlator is None:
            return web.json_response({"rules": [], "total": 0})
        rules = correlator.all_rules()
        return web.json_response({"rules": rules, "total": len(rules)})

    @router.get("/api/correlation-rules/{name}")
    async def api_correlation_rule_get(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if correlator is None:
            return web.json_response({"error": "Correlator not available."}, status=404)
        name = req.match_info["name"]
        rule = correlator.get_rule(name)
        if not rule:
            return web.json_response({"error": f"Correlation rule '{name}' not found."}, status=404)
        return web.json_response(rule.to_dict())

    @router.patch("/api/correlation-rules/{name}")
    async def api_correlation_rule_update(req: web.Request) -> web.Response:
        """Update: enabled, window_sec, cooldown_sec, confidence. analyst+ only."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):   # analyst+
            return web.json_response(guard, status=403)
        if correlator is None:
            return web.json_response({"error": "Correlator not available."}, status=404)
        name = req.match_info["name"]
        body = await req.json()
        err = correlator.update(
            name,
            enabled      = body.get("enabled"),
            window_sec   = body.get("window_sec"),
            cooldown_sec = body.get("cooldown_sec"),
            confidence   = body.get("confidence"),
        )
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("correlation_rule_updated", {
            "rule": name, "by": payload["sub"], "changes": body
        })
        await _audit(req, payload, "correlation_rule_update", target=name, details=body)
        return web.json_response({"ok": True, "rule": correlator.get_rule(name).to_dict()})

    @router.post("/api/correlation-rules/{name}/enable")
    async def api_correlation_rule_enable(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        if correlator is None:
            return web.json_response({"error": "Correlator not available."}, status=404)
        name = req.match_info["name"]
        err = correlator.enable(name)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("correlation_rule_enabled", {"rule": name, "by": payload["sub"]})
        await _audit(req, payload, "correlation_rule_enable", target=name)
        return web.json_response({"ok": True})

    @router.post("/api/correlation-rules/{name}/disable")
    async def api_correlation_rule_disable(req: web.Request) -> web.Response:
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "block:write"):
            return web.json_response(guard, status=403)
        if correlator is None:
            return web.json_response({"error": "Correlator not available."}, status=404)
        name = req.match_info["name"]
        err = correlator.disable(name)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("correlation_rule_disabled", {"rule": name, "by": payload["sub"]})
        await _audit(req, payload, "correlation_rule_disable", target=name)
        return web.json_response({"ok": True})

    @router.post("/api/correlation-rules/{name}/reset")
    async def api_correlation_rule_reset(req: web.Request) -> web.Response:
        """Reset correlation rule to built-in defaults. admin only."""
        payload, err = _require_auth(req)
        if err:
            return web.json_response({"error": err}, status=401)
        if guard := rbac.require(payload["role"], "config:write"):
            return web.json_response(guard, status=403)
        if correlator is None:
            return web.json_response({"error": "Correlator not available."}, status=404)
        name = req.match_info["name"]
        err = correlator.reset(name)
        if err:
            return web.json_response({"error": err}, status=400)
        await logger.log("correlation_rule_reset", {"rule": name, "by": payload["sub"]})
        await _audit(req, payload, "correlation_rule_reset", target=name)
        return web.json_response({"ok": True, "rule": correlator.get_rule(name).to_dict()})