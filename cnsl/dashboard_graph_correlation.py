"""
cnsl/dashboard_graph_correlation.py -- Graph-structured campaign
detection routes.

Split out of cnsl/dashboard.py (same pattern as the other dashboard_*.py
extractions) to keep dashboard.py under its enforced line-count budget.

Routes (see cnsl/graph_correlation.py for the underlying graph/campaign
logic):
  GET /api/graph/campaigns             Groups of 3+ IPs transitively
                                        linked through shared rules/
                                        kill-chain stages
  GET /api/graph/explain/{ip_a}/{ip_b} What two specific IPs directly
                                        have in common in the graph
"""

from __future__ import annotations

from typing import Any, Callable


def register_graph_correlation_routes(
    router:            Any,
    store:             Any,
    kill_chain_tracker: Any,
    _require_auth:     Callable,
    _rate_check:       Callable,
) -> None:
    """Attach the /api/graph/campaigns and /api/graph/explain/... routes
    to `router`. Called once from start_dashboard(). `store` may be
    unavailable and `kill_chain_tracker` may be None -- both handlers
    degrade gracefully (empty results) rather than raising.
    """
    from aiohttp import web
    from .graph_correlation import build_attack_graph, find_campaigns, explain_connection

    def _parse_int(req: web.Request, name: str, default: int, cap: int) -> int:
        # Shared by both routes below for every query-string int param --
        # bad/missing input falls back to `default` instead of erroring,
        # and the result is always clamped to [1, cap] so a caller can't
        # force an unbounded incident scan via the URL.
        try:
            v = int(req.rel_url.query.get(name, default))
        except (ValueError, TypeError):
            v = default
        return max(1, min(v, cap))

    async def _load_graph(req: web.Request):
        if not getattr(store, "available", False):
            return {"nodes": [], "edges": []}
        limit = _parse_int(req, "incident_limit", 5000, 20000)
        incidents = await store.recent_incidents(limit=limit)
        # kill_chain_tracker.get_all() has no query-param override -- 10000
        # is just a fixed upper bound on how much chain history feeds the graph.
        chains = kill_chain_tracker.get_all(limit=10000) if kill_chain_tracker else None
        return build_attack_graph(incidents, kill_chains=chains)

    @router.get("/api/graph/campaigns")
    async def api_graph_campaigns(req: web.Request) -> web.Response:
        """Groups of 3+ IPs transitively linked through shared rules or
        kill-chain stages -- correlated even when no two of them look
        directly similar to each other."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        min_ips = _parse_int(req, "min_ips", 3, 100)
        min_shared_degree = _parse_int(req, "min_shared_degree", 2, 50)

        graph = await _load_graph(req)
        campaigns = find_campaigns(graph, min_ips=min_ips,
                                    min_shared_degree=min_shared_degree)
        return web.json_response({
            "campaigns": campaigns,
            "total_campaigns": len(campaigns),
            "graph_nodes": len(graph["nodes"]),
            "graph_edges": len(graph["edges"]),
        })

    @router.get("/api/graph/explain/{ip_a}/{ip_b}")
    async def api_graph_explain(req: web.Request) -> web.Response:
        """What ip_a and ip_b directly share in the attack graph (rule
        or kill-chain-stage nodes both connect to)."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        ip_a = req.match_info["ip_a"]
        ip_b = req.match_info["ip_b"]

        graph = await _load_graph(req)
        shared = explain_connection(ip_a, ip_b, graph)
        return web.json_response({
            "ip_a": ip_a,
            "ip_b": ip_b,
            "shared_nodes": shared,
            "directly_connected": len(shared) > 0,
        })