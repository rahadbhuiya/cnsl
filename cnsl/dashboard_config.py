"""
cnsl/dashboard_config.py -- Visual config editor API endpoints.

Kept in a dedicated module to preserve dashboard.py line budget.
"""

from __future__ import annotations

from typing import Any, Callable, Optional
from aiohttp import web

from .config_service import ConfigService


def register_config_routes(
    router: Any,
    config_service_or_path: Any,
    _require_auth: Callable,
    _rate_check: Callable,
    _audit: Optional[Callable] = None,
    _require_perm: Optional[Callable] = None,
) -> None:
    if isinstance(config_service_or_path, ConfigService):
        config_service = config_service_or_path
    elif isinstance(config_service_or_path, str) or config_service_or_path is None:
        config_service = ConfigService(config_service_or_path)
    else:
        config_service = ConfigService(None)

    def _config_permission(user_payload: dict, permission: str):
        if _require_perm:
            return _require_perm(user_payload, permission)
        return None

    async def _safe_audit(req: web.Request, user: dict, action: str, **kwargs):
        if _audit:
            try:
                await _audit(req, user, action, **kwargs)
            except Exception:
                pass

    @router.get("/api/config/schema")
    async def api_config_schema(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        return web.json_response(config_service.schema())

    @router.get("/api/config/current")
    async def api_config_current(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        result = config_service.current()
        await _safe_audit(req, user, "config_read", details={"config_hash": result["config_hash"]})
        return web.json_response(result)

    @router.get("/api/config/status")
    async def api_config_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        return web.json_response(config_service.status())

    @router.get("/api/config/versions")
    async def api_config_versions(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        return web.json_response({"versions": config_service.versions()})

    @router.get("/api/config/versions/{version_id}")
    async def api_config_version(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        try:
            return web.json_response(config_service.get_version(req.match_info["version_id"]))
        except KeyError:
            return web.json_response({"error": "Version not found"}, status=404)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=409)

    @router.post("/api/config/draft")
    async def api_config_create_draft(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:write")): return r
        try:
            body = await req.json()
            if not isinstance(body, dict):
                return web.json_response({"error": "Request body must be an object"}, status=400)
            result = config_service.create_draft(
                user.get("sub", "?"), body.get("config"), body.get("base_file_hash")
            )
        except (ValueError, TypeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        except RuntimeError as exc:
            return web.json_response({"error": str(exc)}, status=409)
        await _safe_audit(
            req, user, "config_draft_created", target=result["draft_id"],
            details={"changed_paths": [c["path"] for c in result["changes"]]}
        )
        return web.json_response(result, status=201)

    @router.put("/api/config/draft/{draft_id}")
    async def api_config_update_draft(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:write")): return r
        try:
            body = await req.json()
            if not isinstance(body, dict):
                return web.json_response({"error": "Request body must be an object"}, status=400)
            result = config_service.update_draft(
                req.match_info["draft_id"], user.get("sub", "?"), body.get("config")
            )
        except KeyError:
            return web.json_response({"error": "Draft not found"}, status=404)
        except (ValueError, TypeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response(result)

    @router.get("/api/config/diff/{draft_id}")
    async def api_config_diff(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:read")): return r
        try:
            return web.json_response(config_service.get_draft(req.match_info["draft_id"], user.get("sub", "?")))
        except KeyError:
            return web.json_response({"error": "Draft not found"}, status=404)

    @router.post("/api/config/validate")
    async def api_config_validate(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:write")): return r
        try:
            body = await req.json()
            if not isinstance(body, dict):
                return web.json_response({"error": "Request body must be an object"}, status=400)
            result = config_service.validate(body.get("draft_id", ""), user.get("sub", "?"))
        except KeyError:
            return web.json_response({"error": "Draft not found"}, status=404)
        except (ValueError, TypeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        await _safe_audit(
            req, user, "config_validated", target=body.get("draft_id"),
            details={"valid": result["valid"], "changed_paths": [c["path"] for c in result["changes"]]}
        )
        return web.json_response(result)

    @router.post("/api/config/versions")
    async def api_config_generate_version(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user, err = _require_auth(req)
        if err: return err
        if (r := _config_permission(user, "config:write")): return r
        try:
            body = await req.json()
            if not isinstance(body, dict):
                return web.json_response({"error": "Request body must be an object"}, status=400)
            result = config_service.generate_version(
                body.get("draft_id", ""), user.get("sub", "?"), body.get("config_hash")
            )
        except KeyError:
            return web.json_response({"error": "Draft not found"}, status=404)
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=422)
        except RuntimeError as exc:
            return web.json_response({"error": str(exc)}, status=409)
        await _safe_audit(
            req, user, "config_version_generated", target=result["version_id"],
            details={"sha256": result["sha256"], "config_hash": result["config_hash"]}
        )
        return web.json_response(result, status=201)
