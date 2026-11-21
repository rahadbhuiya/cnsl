"""
cnsl/dashboard_soar.py -- SOAR, MITRE ATT&CK, and AI Copilot API endpoints.

Kept in a dedicated module to preserve dashboard.py line budget.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
from aiohttp import web

from .mitre_attack import MitreAttackEngine
from .soar import SOAREngine
from .ai_copilot import AICopilot


def register_soar_routes(
    router: Any,
    soar_engine: Optional[SOAREngine],
    copilot: Optional[AICopilot],
    mitre_engine: Optional[Any],
    _require_auth: Callable,
    _rate_check: Callable,
) -> None:
    soar = soar_engine or SOAREngine()
    ai = copilot or AICopilot()

    @router.get("/api/soar/playbooks")
    async def api_soar_playbooks(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return web.json_response({
            "enabled": soar.enabled,
            "auto_remediate": soar.auto_remediate,
            "playbooks": soar.playbooks,
        })

    @router.get("/api/soar/history")
    async def api_soar_history(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return web.json_response({
            "history": soar.execution_history[-100:],
            "total_executed": len(soar.execution_history),
        })

    @router.post("/api/soar/evaluate")
    async def api_soar_evaluate(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            body = await req.json()
            results = await soar.evaluate_incident(body)
            return web.json_response({"results": results})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    @router.post("/api/copilot/analyze")
    async def api_copilot_analyze(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            incident = await req.json()
            analysis = await ai.analyze_incident(incident)
            return web.json_response(analysis)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    @router.get("/api/mitre/heatmap")
    async def api_mitre_heatmap(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        # If active incidents were stored or passed, we can calculate dynamic heatmap
        heatmap = MitreAttackEngine.generate_heatmap([])
        return web.json_response(heatmap)

    @router.get("/api/mitre/mapping/{rule}")
    async def api_mitre_mapping(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rule = req.match_info.get("rule", "")
        mapping = MitreAttackEngine.get_rule_mapping(rule)
        return web.json_response({"rule": rule, "mapping": mapping})
