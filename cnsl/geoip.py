"""
cnsl/geoip.py — GeoIP enrichment for attacker IPs.

Uses ip-api.com (free, no API key needed, 45 req/min limit).
Results are cached in-memory + optionally persisted to SQLite.

Private/reserved IPs (10.x, 192.168.x, etc.) are resolved locally
without hitting the API.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from typing import Dict, Optional, Any

# ── Private IP ranges (never query API for these) ────────────────────────────
_PRIVATE = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting"
_CACHE_TTL = 3600 * 6   # 6 hours
_REQUEST_INTERVAL = 1.5  # stay under 45 req/min


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE)
    except ValueError:
        return False


class GeoIP:
    """
    Async GeoIP resolver with in-memory cache.

    Usage:
        geo = GeoIP()
        info = await geo.lookup("1.2.3.4")
        # {"country": "China", "city": "Beijing", "isp": "...", "flag": "🇨🇳"}
    """

    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def lookup(self, ip: str) -> Dict[str, Any]:
        """Return geo info for an IP. Returns cached result if available."""
        if _is_private(ip):
            return {"country": "Local/Private", "countryCode": "LO",
                    "city": "", "isp": "", "flag": "🏠", "proxy": False, "hosting": False}

        async with self._lock:
            cached = self._cache.get(ip)
            if cached and (time.time() - cached["_ts"]) < _CACHE_TTL:
                return cached

        result = await self._fetch(ip)

        async with self._lock:
            result["_ts"] = time.time()
            self._cache[ip] = result

        return result

    async def _fetch(self, ip: str) -> Dict[str, Any]:
        # Rate-limit: stay under 45 req/min
        wait = _REQUEST_INTERVAL - (time.time() - self._last_request)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_request = time.time()

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    _API_URL.format(ip=ip), timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    data = await resp.json(content_type=None)

            if data.get("status") == "success":
                return {
                    "country":     data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "??"),
                    "city":        data.get("city", ""),
                    "isp":         data.get("isp", ""),
                    "org":         data.get("org", ""),
                    "as":          data.get("as", ""),
                    "proxy":       bool(data.get("proxy", False)),
                    "hosting":     bool(data.get("hosting", False)),
                    "flag":        _flag(data.get("countryCode", "")),
                }
        except Exception:
            pass

        return {"country": "Unknown", "countryCode": "??", "city": "",
                "isp": "", "org": "", "as": "", "proxy": False,
                "hosting": False, "flag": "🌐"}

    def cache_size(self) -> int:
        return len(self._cache)

    def get_cached(self, ip: str) -> Optional[Dict[str, Any]]:
        return self._cache.get(ip)


def _flag(code: str) -> str:
    """Convert ISO 3166-1 alpha-2 country code to flag emoji."""
    if len(code) != 2:
        return "🌐"
    return chr(0x1F1E0 + ord(code[0]) - ord('A')) + \
           chr(0x1F1E0 + ord(code[1]) - ord('A'))