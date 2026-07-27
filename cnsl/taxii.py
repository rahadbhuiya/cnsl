"""
cnsl/taxii.py — Minimal read-only TAXII 2.1 server.

Exposes CNSL's detected attacker IPs (via cnsl/stix_export.py) through
a single-collection, read-only TAXII 2.1 API, so any TAXII 2.1 client
(SOAR platforms, threat intel platforms, other SIEMs) can pull them
automatically instead of a human downloading a bundle file by hand.

TAXII 2.1 spec: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html

Scope, deliberately kept small:
  - One API root ("cnsl"), one collection ("attacker-ips") -- read-only
    (can_write is always false; there is no ingestion path).
  - No `added_after` cursoring or paging beyond a simple `limit` --
    fine for a self-hosted single-node feed; a future revision can add
    real pagination if a consumer needs it.
  - Auth reuses the dashboard's existing Bearer/JWT auth (the same
    _require_auth used by the REST API), not HTTP Basic Auth as many
    TAXII clients default to. This is documented in docs/api.md; most
    TAXII client libraries support configuring a bearer token.

Routes:
  GET /taxii2/                                  Discovery
  GET /taxii2/{api_root}/                       API Root info
  GET /taxii2/{api_root}/collections/           List collections
  GET /taxii2/{api_root}/collections/{id}/      Collection detail
  GET /taxii2/{api_root}/collections/{id}/objects/   STIX objects (the IOCs)
"""

from __future__ import annotations

from typing import Any, Callable

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE  = "application/stix+json;version=2.1"

API_ROOT_NAME    = "cnsl"
COLLECTION_ID    = "attacker-ips"
COLLECTION_TITLE = "CNSL Detected Attacker IPs"


def register_taxii_routes(
    router:        Any,
    store:         Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach the /taxii2/... routes to `router`.

    Called once from start_dashboard(). `store` may be unavailable
    (no DB configured) -- the objects endpoint then returns an empty
    collection rather than raising.
    """
    from aiohttp import web
    from .stix_export import build_stix_bundle

    def _taxii_json(data: dict, status: int = 200) -> web.Response:
        import json as _json
        return web.Response(
            text=_json.dumps(data), status=status, content_type=TAXII_MEDIA_TYPE,
        )

    @router.get("/taxii2/")
    async def taxii_discovery(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return _taxii_json({
            "title":       "CNSL TAXII 2.1 Server",
            "description": "Read-only feed of IPs CNSL has detected attacking this host.",
            "default":     f"/taxii2/{API_ROOT_NAME}/",
            "api_roots":   [f"/taxii2/{API_ROOT_NAME}/"],
        })

    @router.get(f"/taxii2/{API_ROOT_NAME}/")
    async def taxii_api_root(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return _taxii_json({
            "title":              "CNSL",
            "description":        "This CNSL instance's threat intel",
            "versions":           ["application/taxii+json;version=2.1"],
            "max_content_length": 10_000_000,
        })

    @router.get(f"/taxii2/{API_ROOT_NAME}/collections/")
    async def taxii_collections(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return _taxii_json({"collections": [_collection_dict()]})

    @router.get(f"/taxii2/{API_ROOT_NAME}/collections/{{collection_id}}/")
    async def taxii_collection_detail(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        collection_id = req.match_info["collection_id"]
        if collection_id != COLLECTION_ID:
            return _taxii_json({"title": "Collection not found"}, status=404)
        return _taxii_json(_collection_dict())

    @router.get(f"/taxii2/{API_ROOT_NAME}/collections/{{collection_id}}/objects/")
    async def taxii_objects(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        collection_id = req.match_info["collection_id"]
        if collection_id != COLLECTION_ID:
            return _taxii_json({"title": "Collection not found"}, status=404)

        try:
            limit = int(req.rel_url.query.get("limit", 100))
            limit = max(1, min(limit, 1000))
        except (ValueError, TypeError):
            limit = 100

        attackers = await store.top_attackers(limit=limit) if getattr(store, "available", False) else []
        bundle    = build_stix_bundle(attackers)
        # TAXII's objects endpoint returns a flat objects list (not a
        # full bundle envelope) per spec -- the Identity object is
        # still included so consumers can resolve created_by_ref.
        import json as _json
        return web.Response(
            text=_json.dumps({"objects": bundle["objects"]}),
            content_type=STIX_MEDIA_TYPE,
        )


def _collection_dict() -> dict:
    return {
        "id":          COLLECTION_ID,
        "title":       COLLECTION_TITLE,
        "description": "IPs CNSL has flagged for malicious activity, exported as STIX indicators.",
        "can_read":    True,
        "can_write":   False,
        "media_types": [STIX_MEDIA_TYPE],
    }


def register_stix_export_route(
    router:        Any,
    store:         Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach GET /api/export/stix -- a downloadable STIX 2.1 bundle
    (as opposed to the TAXII objects endpoint above, which returns the
    same data as a live feed for automated TAXII clients)."""
    from aiohttp import web
    from .stix_export import build_stix_bundle

    @router.get("/api/export/stix")
    async def api_export_stix(req: web.Request) -> web.Response:
        """Export detected attacker IPs as a downloadable STIX 2.1 bundle."""
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 200))
            limit = max(1, min(limit, 1000))
        except (ValueError, TypeError):
            limit = 200
        attackers = await store.top_attackers(limit=limit) if getattr(store, "available", False) else []
        bundle    = build_stix_bundle(attackers)
        import json as _json
        return web.Response(
            text=_json.dumps(bundle, indent=2),
            content_type="application/json",
            headers={"Content-Disposition": "attachment; filename=cnsl-iocs.stix2.json"},
        )