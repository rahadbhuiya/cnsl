"""
cnsl/federation.py -- Multi-Node Federation (cross-node correlation).

Extends the existing Redis-based block synchronization (redis_sync.py) to
also share *detection signals* between independently-running CNSL nodes,
not just blocklist entries.

This closes the federation gap noted in the original CNSL research paper:

    "CNSL: A Cognitive Network Security Layer for
     Intent-Based Incident Detection and Response"

    "Future work includes multi-node federation, allowing CNSL instances
     across different hosts to correlate attacker behavior collectively
     rather than in isolation."

Why this is needed:

  Before federation, two CNSL nodes (e.g. web-01 and db-01) each see only
  their own logs. If an attacker scans web-01's nginx and then brute-forces
  db-01's MySQL, neither node alone has enough signal to recognize this as
  one coordinated attack -- each just sees a single-source event below
  its own threshold.

  RedisSync (redis_sync.py) already gives every node a shared connection
  and pub/sub channel, but it only synchronizes the *blocklist*. It has no
  concept of sharing detection events, kill chain stages, or correlation
  state between nodes.

How federation works:

  1. FederationBus reuses the same Redis connection as RedisSync (no new
     infrastructure dependency). It subscribes to a new channel,
     "{prefix}:federation", separate from the existing "{prefix}:events"
     blocklist channel.

  2. Every time a local detection or kill-chain stage update happens for
     an IP, the bus publishes a compact FederatedSignal to the channel:
     {node_id, ip, kind, severity, ts}.

  3. Every other node receives the signal and feeds it into its own LOCAL
     kill_chain.update() and correlator state for that IP -- as if the
     event had happened locally, but tagged with the origin node_id.
     This means an attacker's full kill chain becomes visible on every
     node, not just the one that saw a particular stage.

  4. When a node's local correlator combines its own signal with a
     federated signal from another node and crosses a correlation
     threshold, it raises a CorrelationAlert tagged with
     rule_name="federated_<original_rule>" so operators can see the
     alert required cross-node evidence.

  5. FederationBus tracks per-node statistics (signals sent/received,
     last seen) and exposes them for the dashboard Federation panel.

Failure mode: if Redis is unavailable, federation silently degrades to
single-node mode -- this never blocks local detection.

Config (config.json):
  "federation": {
    "enabled":          true,
    "min_severity":     "LOW",
    "dedupe_window_sec": 5,
    "max_remote_ips":   10000
  }

  Federation reuses cfg["redis"] for connection details (host, port,
  password, db, key_prefix) -- it does not introduce a separate
  connection block.

API endpoints (added in dashboard.py):
  GET /api/federation/status     -- this node's federation health
  GET /api/federation/nodes      -- all known peer nodes + last seen
  GET /api/federation/ip/{ip}    -- combined view of signals for one IP
                                     across all nodes (which node saw what)
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional

from .models import iso_time, now



# Federated signal -- the unit broadcast between nodes


@dataclass
class FederatedSignal:
    """
    A compact detection signal shared between CNSL nodes.

    Intentionally minimal -- this is not a full Event or Detection object.
    It carries just enough for a receiving node to update its own
    kill_chain and correlator state for the IP.
    """
    node_id:  str
    ip:       str
    kind:     str             # event kind, e.g. "SSH_FAIL", "WEB_SCAN"
    severity: str   = "LOW"
    ts:       float = field(default_factory=now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":  self.node_id,
            "ip":       self.ip,
            "kind":     self.kind,
            "severity": self.severity,
            "ts":       self.ts,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> Optional["FederatedSignal"]:
        try:
            return FederatedSignal(
                node_id  = d["node_id"],
                ip       = d["ip"],
                kind     = d["kind"],
                severity = d.get("severity", "LOW"),
                ts       = d.get("ts", now()),
            )
        except (KeyError, TypeError):
            return None



# Per-IP federation record -- tracks which node saw what


@dataclass
class FederatedIPRecord:
    """
    Tracks which nodes have reported signals for a given IP, and what
    kinds of events each node saw. Used to answer "is this IP being
    attacked across multiple nodes right now?"
    """
    ip:           str
    node_signals: Dict[str, List[FederatedSignal]] = field(default_factory=dict)
    first_seen:   float = field(default_factory=now)
    last_seen:    float = field(default_factory=now)

    def add(self, signal: FederatedSignal) -> None:
        self.node_signals.setdefault(signal.node_id, [])
        self.node_signals[signal.node_id].append(signal)
        # Keep last 50 signals per node to bound memory
        if len(self.node_signals[signal.node_id]) > 50:
            self.node_signals[signal.node_id] = self.node_signals[signal.node_id][-50:]
        self.last_seen = signal.ts

    @property
    def node_count(self) -> int:
        return len(self.node_signals)

    @property
    def is_cross_node(self) -> bool:
        """True if 2+ distinct nodes have reported signals for this IP."""
        return self.node_count >= 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip":           self.ip,
            "first_seen":   iso_time(self.first_seen),
            "last_seen":    iso_time(self.last_seen),
            "node_count":   self.node_count,
            "is_cross_node": self.is_cross_node,
            "nodes": {
                node_id: {
                    "signal_count": len(signals),
                    "kinds":        sorted(set(s.kind for s in signals)),
                    "last_seen":    iso_time(max(s.ts for s in signals)),
                }
                for node_id, signals in self.node_signals.items()
            },
        }



# Federation Bus -- main class


class FederationBus:
    """
    Shares detection signals between CNSL nodes over the existing Redis
    connection. Reuses redis_sync's connection rather than opening a
    second one.

    Usage:
        bus = FederationBus(cfg, redis_sync, logger)
        bus.on_remote_signal = my_callback  # async fn(FederatedSignal)
        await bus.start()                   # starts subscribe loop

        # When a local detection happens:
        await bus.publish(ip, kind, severity)

        status = bus.status()
    """

    CHANNEL_SUFFIX = "federation"

    def __init__(self, cfg: Dict[str, Any], redis_sync: Any, logger: Any) -> None:
        fed_cfg = cfg.get("federation", {})
        self.enabled           = bool(fed_cfg.get("enabled", True))
        self.min_severity      = fed_cfg.get("min_severity", "LOW")
        self.dedupe_window_sec = int(fed_cfg.get("dedupe_window_sec", 5))
        self.max_remote_ips    = int(fed_cfg.get("max_remote_ips", 10000))

        self._redis_sync = redis_sync
        self._logger     = logger
        self.node_id      = getattr(redis_sync, "node_id", "local")

        # Callback invoked for every remote signal received
        self.on_remote_signal: Optional[Callable] = None

        # Per-IP federation state
        self._ip_records: Dict[str, FederatedIPRecord] = {}

        # Per-node stats
        self._node_last_seen: Dict[str, float] = {}
        self._signals_sent     = 0
        self._signals_received = 0

        # Dedup cache -- avoid re-publishing the exact same (ip, kind)
        # within dedupe_window_sec
        self._recent_publishes: Dict[str, float] = {}

        self._subscribe_task: Optional[asyncio.Task] = None
        self._running = False

    @property
    def _channel(self) -> str:
        prefix = getattr(self._redis_sync, "prefix", "cnsl")
        return f"{prefix}:{self.CHANNEL_SUFFIX}"

    @property
    def is_connected(self) -> bool:
        return bool(self.enabled and getattr(self._redis_sync, "connected", False))

    
    # Lifecycle
    

    async def start(self) -> None:
        """Start the background subscribe loop. No-op if disabled or
        redis_sync is not connected."""
        if not self.enabled or self._running:
            return
        self._running = True
        self._subscribe_task = asyncio.ensure_future(self._subscribe_loop())

    async def stop(self) -> None:
        self._running = False
        if self._subscribe_task:
            self._subscribe_task.cancel()
            try:
                await self._subscribe_task
            except (asyncio.CancelledError, Exception):
                pass

    
    # Publishing
    

    async def publish(self, ip: str, kind: str, severity: str = "LOW") -> bool:
        """
        Publish a local detection signal to the federation channel.
        Returns True if published (or if federation is disabled --
        disabled federation should never look like a failure upstream).
        """
        if not self.enabled or not ip:
            return True
        if not self.is_connected:
            return False

        dedupe_key = f"{ip}:{kind}"
        last_pub   = self._recent_publishes.get(dedupe_key, 0)
        if now() - last_pub < self.dedupe_window_sec:
            return True  # deduped, not an error

        signal = FederatedSignal(
            node_id  = self.node_id,
            ip       = ip,
            kind     = kind,
            severity = severity,
        )

        try:
            redis_conn = getattr(self._redis_sync, "_redis", None)
            if redis_conn is None:
                return False
            await redis_conn.publish(self._channel, json.dumps(signal.to_dict()))
            self._recent_publishes[dedupe_key] = now()
            self._signals_sent += 1
            return True
        except Exception as e:
            if self._logger:
                await self._logger.log("federation_publish_error", {"error": str(e)})
            return False

    
    # Receiving
    

    async def _subscribe_loop(self) -> None:
        """Long-running task that listens for signals from other nodes."""
        while self._running:
            if not self.is_connected:
                await asyncio.sleep(5)
                continue
            try:
                redis_conn = getattr(self._redis_sync, "_redis", None)
                if redis_conn is None:
                    await asyncio.sleep(5)
                    continue

                pubsub = redis_conn.pubsub()
                await pubsub.subscribe(self._channel)

                if self._logger:
                    await self._logger.log("federation_subscribed", {
                        "channel": self._channel, "node_id": self.node_id,
                    })

                async for message in pubsub.listen():
                    if not self._running:
                        break
                    if message["type"] != "message":
                        continue
                    try:
                        data = json.loads(message["data"])
                    except Exception:
                        continue

                    signal = FederatedSignal.from_dict(data)
                    if signal is None:
                        continue

                    # Ignore our own published signals
                    if signal.node_id == self.node_id:
                        continue

                    await self._handle_remote_signal(signal)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                if self._logger:
                    await self._logger.log("federation_error", {
                        "op": "subscribe_loop", "error": str(e),
                    })
                await asyncio.sleep(10)

    async def _handle_remote_signal(self, signal: FederatedSignal) -> None:
        """Process one incoming remote signal."""
        self._signals_received += 1
        self._node_last_seen[signal.node_id] = now()

        record = self._ip_records.get(signal.ip)
        if record is None:
            if len(self._ip_records) >= self.max_remote_ips:
                self._evict_oldest_record()
            record = FederatedIPRecord(ip=signal.ip)
            self._ip_records[signal.ip] = record
        record.add(signal)

        if self.on_remote_signal:
            try:
                await self.on_remote_signal(signal)
            except Exception as e:
                if self._logger:
                    await self._logger.log("federation_callback_error", {"error": str(e)})

    def _evict_oldest_record(self) -> None:
        if not self._ip_records:
            return
        oldest = min(self._ip_records, key=lambda ip: self._ip_records[ip].last_seen)
        del self._ip_records[oldest]

    
    # Queries
    

    def get_ip_record(self, ip: str) -> Optional[FederatedIPRecord]:
        return self._ip_records.get(ip)

    def get_cross_node_ips(self, limit: int = 50) -> List[FederatedIPRecord]:
        """Return IPs that have been seen by 2+ distinct nodes."""
        records = [r for r in self._ip_records.values() if r.is_cross_node]
        records.sort(key=lambda r: r.last_seen, reverse=True)
        return records[:limit]

    def known_nodes(self) -> List[Dict[str, Any]]:
        """Return all peer nodes this bus has heard from, with last seen."""
        return [
            {"node_id": node_id, "last_seen": iso_time(ts)}
            for node_id, ts in sorted(
                self._node_last_seen.items(), key=lambda kv: kv[1], reverse=True
            )
        ]

    def status(self) -> Dict[str, Any]:
        """Health and stats for the dashboard Federation panel."""
        return {
            "enabled":          self.enabled,
            "connected":        self.is_connected,
            "node_id":          self.node_id,
            "channel":          self._channel if self.enabled else None,
            "signals_sent":     self._signals_sent,
            "signals_received": self._signals_received,
            "known_peer_count": len(self._node_last_seen),
            "ips_tracked":      len(self._ip_records),
            "cross_node_ips":   sum(1 for r in self._ip_records.values() if r.is_cross_node),
        }