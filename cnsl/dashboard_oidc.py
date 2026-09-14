"""
cnsl/dashboard_oidc.py -- OIDC SSO login routes for the dashboard.

Split out of cnsl/dashboard.py (same pattern as dashboard_sigma.py,
dashboard_attack.py, ...) to keep dashboard.py under its enforced
line-count budget.

Routes:
  GET /auth/oidc/login      Redirect the browser to the IdP
  GET /auth/oidc/callback   IdP redirects back here with ?code&state
  GET /api/oidc/status      Whether SSO is configured (drives the
                             login page's "Login with SSO" button)

See cnsl/oidc.py for the actual OIDC client logic (discovery, PKCE,
JWKS-based ID token verification, role mapping) -- this module is the
thin route wrapper plus the tiny HTML bounce page the callback returns
(mirrors what the password/2FA login page's own JS already does:
localStorage.setItem then navigate to "/").
"""

from __future__ import annotations

from typing import Any, Callable


_BOUNCE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing in...</title></head>
<body style="background:#0d0d10;color:#ddd;font-family:sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div>Signing in...</div>
<script>
localStorage.setItem('cnsl_token', {token!r});
location.href = '/';
</script>
</body></html>"""


def register_oidc_routes(
    router:        Any,
    auth:          Any,
    oidc:          Any,
    logger:        Any,
    _get_client_ip: Callable,
) -> None:
    """Attach the /auth/oidc/* and /api/oidc/status routes to `router`.

    Called once from start_dashboard(). `oidc` may be None (SSO
    disabled in config) -- every handler degrades to a clear error
    page/response rather than raising.
    """
    from aiohttp import web
    from .oidc import OIDCError

    @router.get("/api/oidc/status")
    async def api_oidc_status(req: web.Request) -> web.Response:
        if oidc is None:
            return web.json_response({"enabled": False, "configured": False})
        return web.json_response(oidc.status())

    @router.get("/auth/oidc/login")
    async def oidc_login(req: web.Request) -> web.Response:
        if oidc is None or not oidc.enabled:
            return web.Response(text="OIDC SSO is not enabled on this server.", status=400)
        try:
            url = await oidc.build_authorization_url()
        except OIDCError as e:
            await logger.log("oidc_login_error", {"ip": _get_client_ip(req), "error": str(e)})
            return web.Response(text=f"OIDC login could not start: {e}", status=500)
        raise web.HTTPFound(url)

    @router.get("/auth/oidc/callback")
    async def oidc_callback(req: web.Request) -> web.Response:
        ip = _get_client_ip(req)
        if oidc is None or not oidc.enabled:
            return web.Response(text="OIDC SSO is not enabled on this server.", status=400)

        error = req.rel_url.query.get("error")
        if error:
            desc = req.rel_url.query.get("error_description", error)
            await logger.log("oidc_callback_error", {"ip": ip, "error": desc})
            return web.Response(text=f"Identity provider returned an error: {desc}", status=400)

        code  = req.rel_url.query.get("code", "")
        state = req.rel_url.query.get("state", "")
        if not code or not state:
            return web.Response(text="Missing code or state in OIDC callback.", status=400)

        try:
            claims = await oidc.exchange_code(code, state)
        except OIDCError as e:
            await logger.log("oidc_callback_error", {"ip": ip, "error": str(e)})
            return web.Response(text=f"OIDC login failed: {e}", status=400)

        username = oidc.username_from_claims(claims)
        if not username:
            await logger.log("oidc_callback_error", {"ip": ip, "error": "no usable username claim"})
            return web.Response(text="Identity provider response had no usable username claim.", status=400)

        role  = oidc.map_role(claims)
        token = auth.issue_token_for_sso_user(username, role)
        await logger.log("oidc_login_ok", {"ip": ip, "username": username, "role": role})

        return web.Response(
            text=_BOUNCE_HTML.format(token=token),
            content_type="text/html",
        )