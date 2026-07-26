"""
cnsl/dashboard_hub.py -- Multi-node hub route.

Split out of cnsl/dashboard.py (same pattern as dashboard_html.py,
dashboard_correlation.py, dashboard_ml.py) to keep dashboard.py under
its enforced line-count budget.

Route:
  GET /api/federation/hub
      Aggregated view of every known node's health/stats (via Redis
      heartbeats) plus this node's federation cross-node IP data.
      See cnsl/hub.py for the aggregation logic.
"""

from __future__ import annotations

from typing import Any, Callable


def register_hub_routes(
    router:        Any,
    redis_sync:    Any,
    federation:    Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach the /api/federation/hub route to `router`.

    Called once from start_dashboard(). `redis_sync` may be None or
    disconnected (single-node deployment) -- the handler degrades to a
    single-node view rather than raising; `federation` may be None too.
    """
    from aiohttp import web
    from .hub import get_hub_view

    @router.get("/api/federation/hub")
    async def api_federation_hub(req: web.Request) -> web.Response:
        """Aggregated multi-node health + cross-node attacker view."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if redis_sync is None or not getattr(redis_sync, "connected", False):
            return web.json_response({
                "error": "Redis not connected -- hub view requires multi-node setup.",
            }, status=400)
        limit = int(req.rel_url.query.get("limit", 50))
        view = await get_hub_view(redis_sync, federation, cross_node_limit=limit)
        return web.json_response(view)