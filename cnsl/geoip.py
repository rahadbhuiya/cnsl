"""
cnsl/geoip.py — GeoIP enrichment (offline MaxMind + online fallback).

Priority:
  1. MaxMind GeoLite2-City.mmdb  (offline, fast, accurate)
  2. ip-api.com                  (online, free, no key — fallback)

MaxMind setup (free):
  1. Register at https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-City.mmdb
  3. Set in config: "geoip": { "mmdb_path": "/etc/cnsl/GeoLite2-City.mmdb" }
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any, Dict, Optional

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_API_URL     = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting"
_CACHE_TTL   = 3600 * 6
_REQUEST_GAP = 1.4


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _flag(code: str) -> str:
    if len(code) != 2:
        return "🌐"
    return chr(0x1F1E0 + ord(code[0]) - ord("A")) + \
           chr(0x1F1E0 + ord(code[1]) - ord("A"))


class GeoIP:
    def __init__(self, cfg: Dict[str, Any] = None):
        cfg = cfg or {}
        geo_cfg = cfg.get("geoip", {})
        self._mmdb_path: Optional[str] = geo_cfg.get("mmdb_path")
        self._reader    = None
        self._cache: Dict[str, Dict] = {}
        self._lock      = asyncio.Lock()
        self._last_req  = 0.0

        if self._mmdb_path:
            self._reader = self._load_mmdb(self._mmdb_path)

    def _load_mmdb(self, path: str):
        try:
            import geoip2.database
            return geoip2.database.Reader(path)
        except ImportError:
            print("[CNSL] geoip2 not installed. Run: pip install geoip2")
            return None
        except Exception as e:
            print(f"[CNSL] Could not load MaxMind DB at {path}: {e}")
            return None

    @property
    def backend(self) -> str:
        return "maxmind" if self._reader else "ip-api"

    async def lookup(self, ip: str) -> Dict[str, Any]:
        if _is_private(ip):
            return {
                "country": "Local/Private", "countryCode": "LO",
                "city": "", "isp": "Local network",
                "flag": "🏠", "proxy": False, "hosting": False,
                "backend": "local",
            }

        async with self._lock:
            cached = self._cache.get(ip)
            if cached and (time.time() - cached.get("_ts", 0)) < _CACHE_TTL:
                return cached

        result = self._lookup_maxmind(ip) if self._reader else await self._lookup_ipapi(ip)
        result["_ts"] = time.time()

        async with self._lock:
            self._cache[ip] = result

        return result

    def _lookup_maxmind(self, ip: str) -> Dict[str, Any]:
        try:
            resp = self._reader.city(ip)
            code = resp.country.iso_code or "??"
            return {
                "country":     resp.country.name or "Unknown",
                "countryCode": code,
                "city":        resp.city.name or "",
                "isp":         "",
                "org":         resp.traits.organization or "",
                "as":          str(resp.traits.autonomous_system_number or ""),
                "proxy":       False,
                "hosting":     False,
                "flag":        _flag(code),
                "backend":     "maxmind",
            }
        except Exception:
            return self._unknown()

    async def _lookup_ipapi(self, ip: str) -> Dict[str, Any]:
        wait = _REQUEST_GAP - (time.time() - self._last_req)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_req = time.time()
        try:
            import aiohttp
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    _API_URL.format(ip=ip),
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as r:
                    data = await r.json(content_type=None)
            if data.get("status") == "success":
                code = data.get("countryCode", "??")
                return {
                    "country":     data.get("country", "Unknown"),
                    "countryCode": code,
                    "city":        data.get("city", ""),
                    "isp":         data.get("isp", ""),
                    "org":         data.get("org", ""),
                    "as":          data.get("as", ""),
                    "proxy":       bool(data.get("proxy")),
                    "hosting":     bool(data.get("hosting")),
                    "flag":        _flag(code),
                    "backend":     "ip-api",
                }
        except Exception:
            pass
        return self._unknown()

    def _unknown(self) -> Dict[str, Any]:
        return {
            "country": "Unknown", "countryCode": "??", "city": "",
            "isp": "", "org": "", "as": "", "proxy": False,
            "hosting": False, "flag": "🌐", "backend": "unknown",
        }

    def get_cached(self, ip: str) -> Optional[Dict]:
        return self._cache.get(ip)

    def cache_size(self) -> int:
        return len(self._cache)

    def close(self) -> None:
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass