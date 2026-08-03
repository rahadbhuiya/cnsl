"""
cnsl/dashboard_fingerprint.py -- Attacker fingerprinting & cross-IP
clustering routes.

Split out of cnsl/dashboard.py (same pattern as dashboard_correlation.py,
dashboard_ml.py, dashboard_hub.py) to keep dashboard.py under its
enforced line-count budget.

Routes (see cnsl/fingerprint.py for the underlying similarity/clustering
logic):
  GET /api/fingerprint/clusters       Groups of IPs that look like the
                                       same actor (behavioral similarity)
  GET /api/fingerprint/similar/{ip}   IPs similar to one given IP
"""

from __future__ import annotations

from typing import Any, Callable


def register_fingerprint_routes(
    router:        Any,
    store:         Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach the /api/fingerprint/... routes to `router`.

    Called once from start_dashboard(). `store` may be unavailable (no
    DB configured) -- both handlers then return empty results rather
    than raising.
    """
    from aiohttp import web
    from .fingerprint import (
        build_fingerprints, cluster_attackers, find_similar,
        MIN_INCIDENTS_FOR_FINGERPRINT,
    )

    def _parse_float(req: web.Request, name: str, default: float) -> float:
        try:
            return float(req.rel_url.query.get(name, default))
        except (ValueError, TypeError):
            return default

    def _parse_int(req: web.Request, name: str, default: int, cap: int) -> int:
        try:
            v = int(req.rel_url.query.get(name, default))
        except (ValueError, TypeError):
            v = default
        return max(1, min(v, cap))

    async def _load_fingerprints(req: web.Request):
        if not getattr(store, "available", False):
            return {}
        limit = _parse_int(req, "incident_limit", 5000, 20000)
        incidents = await store.recent_incidents(limit=limit)
        return build_fingerprints(incidents)

    @router.get("/api/fingerprint/clusters")
    async def api_fingerprint_clusters(req: web.Request) -> web.Response:
        """Groups of IPs whose behavioral fingerprints are similar enough
        to plausibly be the same actor rotating through different IPs."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        threshold = _parse_float(req, "threshold", 0.80)
        threshold = max(0.0, min(threshold, 1.0))

        fingerprints = await _load_fingerprints(req)
        clusters_ips = cluster_attackers(fingerprints, threshold=threshold)
        clusters = [
            {
                "ips": ips,
                "size": len(ips),
                "fingerprints": [fingerprints[ip].to_dict() for ip in ips],
            }
            for ips in clusters_ips
        ]
        return web.json_response({
            "clusters": clusters,
            "total_clusters": len(clusters),
            "total_fingerprinted_ips": len(fingerprints),
            "threshold": threshold,
        })

    @router.get("/api/fingerprint/similar/{ip}")
    async def api_fingerprint_similar(req: web.Request) -> web.Response:
        """IPs whose behavioral fingerprint is similar to the given one."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        ip = req.match_info["ip"]
        threshold = _parse_float(req, "threshold", 0.75)
        threshold = max(0.0, min(threshold, 1.0))
        limit = _parse_int(req, "limit", 20, 200)

        fingerprints = await _load_fingerprints(req)
        if ip not in fingerprints:
            return web.json_response({
                "error": f"No fingerprint for {ip} -- needs at least "
                         f"{MIN_INCIDENTS_FOR_FINGERPRINT} incidents to "
                         f"fingerprint reliably.",
            }, status=404)

        similar = find_similar(ip, fingerprints, threshold=threshold, limit=limit)
        return web.json_response({
            "ip": ip,
            "fingerprint": fingerprints[ip].to_dict(),
            "similar": [
                {"ip": other_ip, "score": round(score, 3),
                 "fingerprint": fingerprints[other_ip].to_dict()}
                for other_ip, score in similar
            ],
            "threshold": threshold,
        })