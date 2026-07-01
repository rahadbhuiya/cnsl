"""
cnsl/rate_limiter.py — Web Request Rate Limiting and DDoS Protection.

Provides per-IP request rate limiting for the web dashboard and
incoming HTTP events. Detects and auto-blocks connection floods.

Features:
  - Per-IP sliding window rate limiting (configurable threshold + window)
  - Connection flood detection (too many connections in short time)
  - Per-endpoint rate limiting (stricter limits for /api/login)
  - Whitelist support (never rate-limit these IPs)
  - Auto-block integration (block IP via Blocker on DDoS threshold)
  - Dashboard API endpoints for rate limit stats and management
  - In-memory state (fast, no persistence needed)

Config (config.json):
  "rate_limiting": {
    "enabled":           true,
    "requests_per_min":  60,
    "burst":             20,
    "window_sec":        60,
    "ddos_threshold":    500,
    "ddos_window_sec":   10,
    "auto_block":        true,
    "auto_block_duration_sec": 900,
    "whitelist":         ["127.0.0.1"],
    "endpoints": {
      "/api/login": {"requests_per_min": 10, "window_sec": 60}
    }
  }
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple


#  RateLimiter 


class RateLimiter:
    """
    Sliding window rate limiter with DDoS detection.

    Usage:
        rl = RateLimiter(cfg)

        # Check before serving request
        allowed, retry_after = rl.check(ip, endpoint="/api/login")
        if not allowed:
            return 429 response

        # Check for DDoS
        is_ddos = rl.check_ddos(ip)
    """

    def __init__(self, cfg: Dict[str, Any], redis_sync=None):
        rl = cfg.get("rate_limiting", {})

        self.enabled            = bool(rl.get("enabled", False))
        self.requests_per_min   = int(rl.get("requests_per_min", 60))
        self.burst              = int(rl.get("burst", 20))
        self.window_sec         = int(rl.get("window_sec", 60))
        self.ddos_threshold     = int(rl.get("ddos_threshold", 500))
        self.ddos_window_sec    = int(rl.get("ddos_window_sec", 10))
        self.auto_block         = bool(rl.get("auto_block", True))
        self.auto_block_duration = int(rl.get("auto_block_duration_sec", 900))
        self.whitelist: Set[str] = set(rl.get("whitelist", ["127.0.0.1", "::1"]))
        self.endpoint_cfg: Dict[str, Dict] = rl.get("endpoints", {})

        # Optional Redis backend for distributed rate limiting.
        # When redis_sync is provided and connected, counters are stored
        # in Redis so all cluster nodes share the same rate limit state.
        # Falls back to local in-memory counting when Redis is unavailable.
        self._redis_sync = redis_sync

        # Per-IP sliding window: {ip: deque([(ts, count), ...])}
        self._windows: Dict[str, deque] = defaultdict(lambda: deque())
        # DDoS detection window: {ip: deque([ts, ...])}
        self._ddos_windows: Dict[str, deque] = defaultdict(lambda: deque())
        # Temporarily rate-limited IPs: {ip: unblock_ts}
        self._blocked_until: Dict[str, float] = {}
        # Stats
        self._stats: Dict[str, int] = defaultdict(int)

    @property
    def _redis(self):
        """Return Redis connection if available, else None."""
        if self._redis_sync and getattr(self._redis_sync, "connected", False):
            return getattr(self._redis_sync, "_redis", None)
        return None

    async def increment_distributed(self, ip: str, window_sec: int) -> int:
        """
        Increment and return the request count for this IP in Redis.
        Used when Redis is available for distributed rate limiting.
        Returns -1 if Redis is unavailable (caller falls back to local).
        """
        redis = self._redis
        if redis is None:
            return -1
        try:
            prefix = getattr(self._redis_sync, "prefix", "cnsl")
            key    = f"{prefix}:rl:{ip}"
            count  = await redis.incr(key)
            if count == 1:
                await redis.expire(key, window_sec)
            return int(count)
        except Exception:
            return -1

    #  Core check 

    def check(
        self, ip: str, endpoint: str = "/", weight: int = 1
    ) -> Tuple[bool, float]:
        """
        Check if this IP is within rate limits.

        Returns (allowed, retry_after_seconds).
        retry_after is 0 if allowed, >0 if rate-limited.
        """
        if not self.enabled:
            return True, 0.0

        if ip in self.whitelist:
            return True, 0.0

        now = time.time()

        # Check if temporarily blocked
        block_until = self._blocked_until.get(ip, 0)
        if now < block_until:
            return False, block_until - now

        # Per-endpoint config
        ep_cfg    = self.endpoint_cfg.get(endpoint, {})
        threshold = int(ep_cfg.get("requests_per_min", self.requests_per_min))
        window    = int(ep_cfg.get("window_sec", self.window_sec))

        # Prune old entries
        cutoff = now - window
        dq = self._windows[ip]
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # Count requests in window
        count = sum(c for _, c in dq) + weight

        if count > threshold + self.burst:
            self._stats["rate_limited_requests"] += 1
            # Soft block for the remainder of the window
            retry = window - (now - (dq[0][0] if dq else now))
            return False, max(retry, 1.0)

        dq.append((now, weight))
        return True, 0.0

    def check_ddos(self, ip: str) -> bool:
        """
        Check if an IP is flooding connections (DDoS detection).
        Returns True if DDoS threshold exceeded.
        """
        if not self.enabled or ip in self.whitelist:
            return False

        now    = time.time()
        cutoff = now - self.ddos_window_sec
        dq     = self._ddos_windows[ip]

        while dq and dq[0] < cutoff:
            dq.popleft()

        dq.append(now)

        if len(dq) >= self.ddos_threshold:
            self._stats["ddos_detections"] += 1
            return True

        return False

    def record(self, ip: str, endpoint: str = "/", weight: int = 1) -> None:
        """Record a request (call after check() returns True)."""
        if not self.enabled or ip in self.whitelist:
            return
        self._stats["total_requests"] += 1

    def block_ip(self, ip: str, duration_sec: Optional[int] = None) -> None:
        """Temporarily block an IP from making requests."""
        dur = duration_sec or self.auto_block_duration
        self._blocked_until[ip] = time.time() + dur
        self._stats["auto_blocked"] += 1

    def unblock_ip(self, ip: str) -> None:
        """Remove a temporary rate-limit block."""
        self._blocked_until.pop(ip, None)

    def reset_ip(self, ip: str) -> None:
        """Reset rate-limit state for an IP."""
        self._windows.pop(ip, None)
        self._ddos_windows.pop(ip, None)
        self._blocked_until.pop(ip, None)

    #  Stats 

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        active_limits = {
            ip: round(ts - now, 1)
            for ip, ts in self._blocked_until.items()
            if ts > now
        }
        return {
            "enabled":            self.enabled,
            "requests_per_min":   self.requests_per_min,
            "ddos_threshold":     self.ddos_threshold,
            "auto_block":         self.auto_block,
            "active_blocks":      len(active_limits),
            "active_block_ips":   active_limits,
            "total_requests":     self._stats["total_requests"],
            "rate_limited":       self._stats["rate_limited_requests"],
            "ddos_detections":    self._stats["ddos_detections"],
            "auto_blocked_total": self._stats["auto_blocked"],
        }

    def top_requesters(self, n: int = 10) -> List[Dict[str, Any]]:
        """Return the IPs with the most requests in the current window."""
        now = time.time()
        counts = []
        for ip, dq in self._windows.items():
            cutoff = now - self.window_sec
            count  = sum(c for ts, c in dq if ts >= cutoff)
            if count > 0:
                counts.append({"ip": ip, "requests": count})
        counts.sort(key=lambda x: x["requests"], reverse=True)
        return counts[:n]


#  aiohttp middleware 


def make_rate_limit_middleware(rate_limiter: RateLimiter, blocker=None):
    """
    Create an aiohttp middleware that enforces rate limits.

    Usage:
        app = web.Application(middlewares=[
            make_rate_limit_middleware(rate_limiter, blocker)
        ])
    """
    from aiohttp import web

    @web.middleware
    async def rate_limit_middleware(request: web.Request, handler):
        if not rate_limiter.enabled:
            return await handler(request)

        ip       = _get_ip(request)
        endpoint = request.path

        # DDoS check
        if rate_limiter.check_ddos(ip):
            if rate_limiter.auto_block and blocker:
                blocker.block(ip, duration=rate_limiter.auto_block_duration,
                              reason="ddos_protection")
            raise web.HTTPTooManyRequests(
                reason="DDoS protection: too many connections"
            )

        # Rate limit check
        allowed, retry_after = rate_limiter.check(ip, endpoint)
        if not allowed:
            headers = {"Retry-After": str(int(retry_after))}
            raise web.HTTPTooManyRequests(
                headers=headers,
                reason=f"Rate limit exceeded. Retry after {int(retry_after)}s",
            )

        rate_limiter.record(ip, endpoint)
        return await handler(request)

    return rate_limit_middleware


def _get_ip(request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote or "0.0.0.0"