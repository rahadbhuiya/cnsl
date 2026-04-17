"""
cnsl/api.py — Lightweight REST API (optional, requires aiohttp).

Endpoints:
  GET  /health              — liveness probe
  GET  /status              — engine summary + tracked IPs
  POST /block   {"ip": ...} — manually block an IP
  POST /unblock {"ip": ...} — manually remove a block

Enable with --api flag (or api.enabled=true in config).
Bind only to 127.0.0.1 by default — do NOT expose to the internet.
Add nginx/auth proxy in front if you need remote access.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .detector import Detector
    from .blocker import Blocker
    from .logger import JsonLogger


async def start_api(
    host:     str,
    port:     int,
    detector: "Detector",
    blocker:  "Blocker",
    logger:   "JsonLogger",
) -> None:
    try:
        from aiohttp import web  # type: ignore
    except ImportError:
        await logger.log("api_error", {"error": "aiohttp not installed. Run: pip install aiohttp"})
        return

    router = web.RouteTableDef()

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
        body = await request.json()
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        ok = await blocker.block_ip(ip, reason="manual")
        await logger.log("api_manual_block", {"ip": ip, "ok": ok})
        return web.json_response({"blocked": ok, "ip": ip})

    @router.post("/unblock")
    async def manual_unblock(request: web.Request) -> web.Response:
        body = await request.json()
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
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