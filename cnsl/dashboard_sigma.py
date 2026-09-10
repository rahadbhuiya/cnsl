"""
cnsl/dashboard_sigma.py -- Sigma rule import/management routes.

Split out of cnsl/dashboard.py (same pattern as dashboard_hub.py,
dashboard_fingerprint.py, dashboard_graph_correlation.py) to keep
dashboard.py under its enforced line-count budget.

Routes:
  GET  /api/sigma/rules                    List every imported rule + import errors
  POST /api/sigma/rules/{rule_id}/enable    Enable one imported rule
  POST /api/sigma/rules/{rule_id}/disable   Disable one imported rule
  POST /api/sigma/import                    Import a single rule from a raw YAML body

See cnsl/sigma.py for the rule format, matching engine, and store.
"""

from __future__ import annotations

from typing import Any, Callable


def register_sigma_routes(
    router:        Any,
    sigma:         Any,
    logger:        Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach the /api/sigma/* routes to `router`.

    Called once from start_dashboard(). `sigma` may be None (Sigma
    import disabled in config) -- every handler degrades to a clear
    400 rather than raising.
    """
    from aiohttp import web

    @router.get("/api/sigma/rules")
    async def api_sigma_rules(req: web.Request) -> web.Response:
        """List every imported Sigma rule and its enabled state."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if sigma is None:
            return web.json_response({"error": "Sigma import not enabled"}, status=400)
        return web.json_response({
            "count":  len(sigma),
            "errors": sigma.import_errors(),
            "rules":  sigma.all_rules(),
        })

    @router.post("/api/sigma/rules/{rule_id:.*}/enable")
    async def api_sigma_enable(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if sigma is None:
            return web.json_response({"error": "Sigma import not enabled"}, status=400)
        rule_id = req.match_info.get("rule_id", "")
        err = sigma.enable(rule_id)
        if err:
            return web.json_response({"error": err}, status=404)
        await logger.log("sigma_rule_enabled", {"rule_id": rule_id})
        return web.json_response({"ok": True})

    @router.post("/api/sigma/rules/{rule_id:.*}/disable")
    async def api_sigma_disable(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if sigma is None:
            return web.json_response({"error": "Sigma import not enabled"}, status=400)
        rule_id = req.match_info.get("rule_id", "")
        err = sigma.disable(rule_id)
        if err:
            return web.json_response({"error": err}, status=404)
        await logger.log("sigma_rule_disabled", {"rule_id": rule_id})
        return web.json_response({"ok": True})

    @router.post("/api/sigma/import")
    async def api_sigma_import(req: web.Request) -> web.Response:
        """Import a single Sigma rule from a raw YAML request body (dashboard upload)."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if sigma is None:
            return web.json_response({"error": "Sigma import not enabled"}, status=400)
        body = await req.text()
        if not body.strip():
            return web.json_response({"error": "Empty request body"}, status=400)
        label = req.rel_url.query.get("label", "<dashboard-upload>")
        rule = sigma.import_text(body, label=label)
        if rule is None:
            errs = sigma.import_errors()
            reason = errs[-1]["error"] if errs else "Unknown import error"
            return web.json_response({"error": reason}, status=400)
        await logger.log("sigma_rule_imported", {"rule_id": rule.id, "title": rule.title})
        return web.json_response({"ok": True, "rule": rule.to_dict()})