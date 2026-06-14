"""
cnsl/api.py — Lightweight REST API (optional, requires aiohttp).

Endpoints:
  GET  /health              — liveness probe
  GET  /status              — engine summary + tracked IPs
  POST /block   {"ip": ...} — manually block an IP   [requires X-CNSL-Secret]
  POST /unblock {"ip": ...} — manually remove a block [requires X-CNSL-Secret]

Enable with --api flag (or api.enabled=true in config).
Bind only to 127.0.0.1 by default — do NOT expose to the internet.
Add nginx/auth proxy in front if you need remote access.

Authentication:
  /block and /unblock require the X-CNSL-Secret header to match
  api.secret_value in config. If api.secret_value is unset, these
  endpoints return 403 to prevent accidental open access.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .detector import Detector
    from .blocker import Blocker
    from .logger import JsonLogger


def _validate_ip(ip: str) -> Optional[str]:
    """Return normalised IP string or None if invalid."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


async def start_api(
    host:     str,
    port:     int,
    detector: "Detector",
    blocker:  "Blocker",
    logger:   "JsonLogger",
    secret:   str = "",
) -> None:
    try:
        from aiohttp import web  # type: ignore
    except ImportError:
        await logger.log("api_error", {"error": "aiohttp not installed. Run: pip install aiohttp"})
        return

    router = web.RouteTableDef()

    def _check_secret(request: "web.Request") -> bool:
        """Return True if the request carries the correct secret header."""
        if not secret:
            return False  # no secret configured → deny write endpoints
        return request.headers.get("X-CNSL-Secret", "") == secret

    @router.get("/health")
    async def health(request: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    @router.get("/status")
    async def status(request: web.Request) -> web.Response:
        return web.json_response({
            "tracked_ips":    detector.get_stats(),
            "active_blocks":  [
                {"ip": ip, "unblock_at": blocker.active_blocks[ip]}
                for ip in blocker.active_blocks
            ],
        })

    @router.post("/block")
    async def manual_block(request: web.Request) -> web.Response:
        if not _check_secret(request):
            await logger.log("api_auth_failure", {"endpoint": "/block", "remote": str(request.remote)})
            return web.json_response({"error": "forbidden"}, status=403)
        body = await request.json()
        raw_ip = body.get("ip", "").strip()
        if not raw_ip:
            return web.json_response({"error": "ip required"}, status=400)
        ip = _validate_ip(raw_ip)
        if ip is None:
            return web.json_response({"error": "invalid IP address"}, status=400)
        ok = await blocker.block_ip(ip, reason="manual")
        await logger.log("api_manual_block", {"ip": ip, "ok": ok})
        return web.json_response({"blocked": ok, "ip": ip})

    @router.post("/unblock")
    async def manual_unblock(request: web.Request) -> web.Response:
        if not _check_secret(request):
            await logger.log("api_auth_failure", {"endpoint": "/unblock", "remote": str(request.remote)})
            return web.json_response({"error": "forbidden"}, status=403)
        body = await request.json()
        raw_ip = body.get("ip", "").strip()
        if not raw_ip:
            return web.json_response({"error": "ip required"}, status=400)
        ip = _validate_ip(raw_ip)
        if ip is None:
            return web.json_response({"error": "invalid IP address"}, status=400)
        if ip not in blocker.active_blocks:
            return web.json_response({"error": "not blocked", "ip": ip}, status=404)
        await blocker._unblock_ip(ip)
        await logger.log("api_manual_unblock", {"ip": ip})
        return web.json_response({"unblocked": True, "ip": ip})

    app = web.Application()
    app.add_routes(router)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    await logger.log("api_started", {"host": host, "port": port})

    # Block forever (the task is cancelled on shutdown)
    await asyncio.Event().wait()