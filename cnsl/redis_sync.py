"""
cnsl/redis_sync.py — Redis distributed blocklist.

Allows multiple CNSL instances (on different servers) to share
a common blocklist. When server A blocks an IP, servers B and C
automatically block it too within seconds.

Features:
  - Pub/Sub for instant propagation
  - Persistent blocklist in Redis hash
  - Auto-expiry via Redis TTL
  - Graceful fallback if Redis is unavailable (local-only mode)
  - Node identity (each server has a unique ID)

Config example:
  "redis": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 6379,
    "password": "optional",
    "db": 0,
    "key_prefix": "cnsl",
    "sync_blocks": true,
    "sync_allowlist": false
  }

Redis key layout:
  cnsl:blocks           HASH  { ip -> json(reason, ts, node_id) }
  cnsl:events           PUBSUB channel for real-time sync
  cnsl:node:<id>        STRING heartbeat (TTL 30s)
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import Any, Callable, Dict, List, Optional

from .logger import JsonLogger
from .models import iso_time, now


class RedisSync:
    """
    Distributed block synchronization via Redis.

    Usage:
        rs = RedisSync(cfg, logger)
        await rs.connect()

        # When blocking locally:
        await rs.publish_block(ip, reason, ttl_sec)

        # Subscribe to blocks from other nodes:
        rs.on_remote_block = my_callback  # async fn(ip, reason, ttl)

        # Check if IP is blocked anywhere in the cluster:
        blocked = await rs.is_blocked(ip)
    """

    def __init__(self, cfg: Dict[str, Any], logger: JsonLogger):
        rc = cfg.get("redis", {})

        self.enabled      = bool(rc.get("enabled", False))
        self.host         = rc.get("host", "127.0.0.1")
        self.port         = int(rc.get("port", 6379))
        self.password     = rc.get("password")
        self.db           = int(rc.get("db", 0))
        self.prefix       = rc.get("key_prefix", "cnsl")
        self.sync_blocks  = bool(rc.get("sync_blocks", True))

        self.node_id      = rc.get("node_id") or secrets.token_hex(4)
        self.logger       = logger

        self._redis       = None
        self._pubsub      = None
        self._connected   = False

        # Callback: called when a remote node publishes a block
        self.on_remote_block:   Optional[Callable] = None
        # Callback: called when a remote node publishes an unblock
        self.on_remote_unblock: Optional[Callable] = None

    # ── Keys ──────────────────────────────────────────────────────────────────

    @property
    def _blocks_key(self) -> str:
        return f"{self.prefix}:blocks"

    @property
    def _events_channel(self) -> str:
        return f"{self.prefix}:events"

    def _node_key(self) -> str:
        return f"{self.prefix}:node:{self.node_id}"

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        """Connect to Redis. Returns True on success."""
        if not self.enabled:
            return False
        try:
            import redis.asyncio as aioredis

            self._redis = await aioredis.from_url(
                f"redis://{self.host}:{self.port}/{self.db}",
                password=self.password,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            await self._redis.ping()
            self._connected = True

            await self.logger.log("redis_connected", {
                "host":    self.host,
                "port":    self.port,
                "node_id": self.node_id,
            })
            return True

        except ImportError:
            await self.logger.log("redis_error", {
                "error": "redis package not installed. Run: pip install redis"
            })
            return False

        except Exception as e:
            await self.logger.log("redis_error", {
                "error": str(e), "host": self.host, "port": self.port
            })
            self._connected = False
            return False

    @property
    def connected(self) -> bool:
        return self._connected

    # ── Block operations ──────────────────────────────────────────────────────

    async def publish_block(self, ip: str, reason: str, ttl_sec: int) -> bool:
        """Publish a block to the cluster."""
        if not self._connected or not self.sync_blocks:
            return False
        try:
            payload = json.dumps({
                "action":  "block",
                "ip":      ip,
                "reason":  reason,
                "ttl":     ttl_sec,
                "node_id": self.node_id,
                "ts":      now(),
            })
            # Store in hash with TTL via expireat
            expire_at = int(now() + ttl_sec)
            await self._redis.hset(self._blocks_key, ip, json.dumps({
                "reason":    reason,
                "node_id":   self.node_id,
                "blocked_at": iso_time(),
                "expire_at": expire_at,
            }))
            # Publish to other nodes
            await self._redis.publish(self._events_channel, payload)
            await self.logger.log("redis_block_published", {
                "ip": ip, "ttl": ttl_sec, "node_id": self.node_id
            })
            return True
        except Exception as e:
            await self.logger.log("redis_error", {"op": "publish_block", "error": str(e)})
            self._connected = False
            return False

    async def publish_unblock(self, ip: str) -> bool:
        """Publish an unblock to the cluster."""
        if not self._connected:
            return False
        try:
            payload = json.dumps({
                "action":  "unblock",
                "ip":      ip,
                "node_id": self.node_id,
                "ts":      now(),
            })
            await self._redis.hdel(self._blocks_key, ip)
            await self._redis.publish(self._events_channel, payload)
            return True
        except Exception as e:
            await self.logger.log("redis_error", {"op": "publish_unblock", "error": str(e)})
            return False

    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is in the cluster blocklist."""
        if not self._connected:
            return False
        try:
            val = await self._redis.hget(self._blocks_key, ip)
            if not val:
                return False
            data = json.loads(val)
            # Check expiry
            if data.get("expire_at", 0) < now():
                await self._redis.hdel(self._blocks_key, ip)
                return False
            return True
        except Exception:
            return False

    async def get_all_blocks(self) -> List[Dict]:
        """Get all active blocks from the cluster."""
        if not self._connected:
            return []
        try:
            raw = await self._redis.hgetall(self._blocks_key)
            result = []
            t      = now()
            for ip, val in raw.items():
                data = json.loads(val)
                if data.get("expire_at", 0) > t:
                    result.append({"ip": ip, **data})
                else:
                    await self._redis.hdel(self._blocks_key, ip)
            return result
        except Exception:
            return []

    # ── Subscribe loop ────────────────────────────────────────────────────────

    async def subscribe_loop(self) -> None:
        """
        Long-running task that listens for block events from other nodes.
        Calls self.on_remote_block(ip, reason, ttl) for each remote block.
        """
        if not self._connected:
            return

        while True:
            try:
                import redis.asyncio as aioredis

                pubsub = self._redis.pubsub()
                await pubsub.subscribe(self._events_channel)

                await self.logger.log("redis_subscribed", {
                    "channel": self._events_channel
                })

                async for message in pubsub.listen():
                    if message["type"] != "message":
                        continue
                    try:
                        data = json.loads(message["data"])
                    except Exception:
                        continue

                    # Ignore our own events
                    if data.get("node_id") == self.node_id:
                        continue

                    action = data.get("action")
                    ip     = data.get("ip")

                    await self.logger.log("redis_remote_event", {
                        "action": action, "ip": ip,
                        "from_node": data.get("node_id"),
                    })

                    if action == "block" and ip and self.on_remote_block:
                        ttl    = data.get("ttl", 900)
                        reason = data.get("reason", "remote_block")
                        try:
                            await self.on_remote_block(ip, reason, ttl)
                        except Exception as e:
                            await self.logger.log("redis_callback_error", {"error": str(e)})

                    elif action == "unblock" and ip and self.on_remote_unblock:
                        try:
                            await self.on_remote_unblock(ip)
                        except Exception as e:
                            await self.logger.log("redis_callback_error", {"error": str(e)})

            except asyncio.CancelledError:
                raise
            except Exception as e:
                await self.logger.log("redis_error", {
                    "op": "subscribe_loop", "error": str(e)
                })
                self._connected = False
                await asyncio.sleep(10)
                # Try to reconnect
                await self.connect()
                if not self._connected:
                    await asyncio.sleep(30)

    # ── Heartbeat ─────────────────────────────────────────────────────────────

    async def heartbeat_loop(self) -> None:
        """Announce this node's presence every 15 seconds."""
        while True:
            try:
                if self._connected:
                    await self._redis.setex(self._node_key(), 30, iso_time())
            except Exception:
                pass
            await asyncio.sleep(15)

    async def active_nodes(self) -> List[str]:
        """Return list of active node IDs in the cluster."""
        if not self._connected:
            return [self.node_id]
        try:
            pattern = f"{self.prefix}:node:*"
            keys    = await self._redis.keys(pattern)
            return [k.split(":")[-1] for k in keys]
        except Exception:
            return [self.node_id]

    # ── Cleanup ─────────────────────────────────────────────────────────────── rahad bhuiya

    async def close(self) -> None:
        if self._redis:
            try:
                await self._redis.delete(self._node_key())
                await self._redis.aclose()
            except Exception:
                pass