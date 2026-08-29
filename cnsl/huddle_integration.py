"""
cnsl/huddle_integration.py — HuddleCluster Integration for CNSL.

Connects CNSL with HuddleCluster (github.com/rahadbhuiya/HuddleCluster)
to provide intelligent load balancing across multiple CNSL instances.

Features:
  1. CNSL as HuddleCluster backend server
     - Multiple CNSL nodes registered in HuddleCluster
     - Temperature score = CNSL event load + queue size + incident rate
     - Overloaded CNSL node auto-evicted to outer ring (resting)
     - Coolest node promoted to inner ring (active)

  2. HuddleCluster as CNSL API gateway
     - Incoming dashboard/agent WebSocket connections load-balanced
     - Sticky sessions via affinity_key (client IP)
     - Health-check integration (GET /api/stats)

  3. CNSL metrics → HuddleCluster temperature
     - events_per_sec × 0.40
     - queue_fullness  × 0.35
     - active_incidents× 0.25
     - Clamped to [0.0, 1.0]

  4. HuddleCluster eviction webhook → CNSL alert
     - When a CNSL node is evicted (overheated), CNSL logs it
     - Alert sent via notification channels
     - Case auto-created for manual investigation

  5. GossipAgent (optional)
     - CNSL nodes share temperature over UDP multicast
     - No central coordinator needed
     - Works across subnets with multicast routing

Config (config.json):
  "huddle": {
    "enabled":          false,
    "nodes": [
      {"id": "cnsl-01", "host": "10.0.0.1", "port": 8765},
      {"id": "cnsl-02", "host": "10.0.0.2", "port": 8765},
      {"id": "cnsl-03", "host": "10.0.0.3", "port": 8765}
    ],
    "max_inner_size":   2,
    "heat_threshold":   0.75,
    "cool_threshold":   0.35,
    "gossip":           true,
    "gossip_port":      7946,
    "health_check":     true,
    "health_check_interval_sec": 15,
    "state_file":       "/var/lib/cnsl/huddle_state.json",
    "webhook_secret":   null
  }

Install HuddleCluster:
  pip install git+https://github.com/rahadbhuiya/HuddleCluster.git
  OR copy huddle_cluster.py into your project.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .metrics import Metrics
    from .logger  import JsonLogger


#  Temperature calculator 


def compute_temperature(
    events_per_sec:    float = 0.0,
    queue_size:        int   = 0,
    queue_max:         int   = 10000,
    active_incidents:  int   = 0,
    ssh_fails_per_min: float = 0.0,
) -> float:
    """
    Convert CNSL metrics into a HuddleCluster temperature score [0.0, 1.0].

    Temperature formula:
      0.40 × event_load   (events_per_sec / saturation point of 100 eps)
      0.35 × queue_load   (queue_size / queue_max)
      0.25 × incident_load (active_incidents / saturation of 50)

    A temperature above heat_threshold causes HuddleCluster to evict the
    node to the outer (resting) ring. A node in the outer ring with
    temperature below cool_threshold gets promoted back to inner ring.

    Examples:
      Idle CNSL          → ~0.00  (inner ring, serving)
      Moderate attack    → ~0.35  (inner ring, healthy)
      Heavy brute-force  → ~0.70  (inner ring, warm)
      DDoS / mass attack → ~0.90+ (evicted to outer ring, resting)
    """
    event_load    = min(1.0, events_per_sec / 100.0)
    queue_load    = min(1.0, queue_size / max(queue_max, 1))
    incident_load = min(1.0, active_incidents / 50.0)

    temp = (
        0.40 * event_load +
        0.35 * queue_load +
        0.25 * incident_load
    )
    return round(min(1.0, max(0.0, temp)), 4)


#  CNSLHuddleNode 


class CNSLHuddleNode:
    """
    Represents a single CNSL instance inside a HuddleCluster.

    Wraps a HuddleCluster Server object and periodically pushes
    CNSL metrics as temperature updates.

    Usage (single-node mode — report own temperature):
        node = CNSLHuddleNode(cluster, server_id="cnsl-01", metrics=metrics)
        await node.start()          # background task
        temp = node.current_temp    # read anytime
    """

    def __init__(
        self,
        cluster,                   # HuddleCluster instance
        server_id:  str,
        metrics:    Optional["Metrics"] = None,
        logger:     Optional["JsonLogger"] = None,
        queue_ref:  Any = None,    # asyncio.Queue reference for queue_size
        update_interval_sec: float = 5.0,
    ):
        self._cluster    = cluster
        self._server_id  = server_id
        self._metrics    = metrics
        self._logger     = logger
        self._queue      = queue_ref
        self._interval   = update_interval_sec
        self._task:      Optional[asyncio.Task] = None
        self.current_temp: float = 0.0

    async def start(self) -> None:
        """Start background temperature reporting loop."""
        self._task = asyncio.create_task(
            self._report_loop(), name="huddle_temp_reporter"
        )

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _report_loop(self) -> None:
        while True:
            try:
                temp = self._compute()
                self.current_temp = temp
                self._push_to_cluster(temp)
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(self._interval)

    def _compute(self) -> float:
        eps       = 0.0
        q_size    = 0
        incidents = 0

        if self._metrics:
            eps       = getattr(self._metrics, "events_per_sec", 0.0)
            incidents = getattr(self._metrics, "total_incidents", 0)

        if self._queue:
            try:
                q_size = self._queue.qsize()
            except Exception:
                pass

        return compute_temperature(
            events_per_sec   = eps,
            queue_size       = q_size,
            active_incidents = incidents,
        )

    def _push_to_cluster(self, temp: float) -> None:
        """Update the HuddleCluster server object with new temperature."""
        try:
            server = self._cluster.get_server_by_id(self._server_id)
            if server:
                server.temperature = temp
        except Exception:
            pass


#  HuddleManager 


class HuddleManager:
    """
    Top-level integration manager.

    Creates a HuddleCluster with all configured CNSL nodes,
    starts temperature reporting for the local node, and
    provides a proxy() method to route incoming requests
    to the currently active (inner-ring) CNSL node.

    Usage in engine.py:
        huddle = HuddleManager(cfg, metrics=metrics, logger=logger)
        await huddle.start()

        # In dashboard proxy:
        target = huddle.proxy(client_ip=req.remote)
        # → "http://10.0.0.2:8765"
    """

    def __init__(
        self,
        cfg:        Dict[str, Any],
        metrics:    Optional["Metrics"]    = None,
        logger:     Optional["JsonLogger"] = None,
        queue_ref:  Any = None,
    ):
        hc = cfg.get("huddle", {})
        self.enabled        = bool(hc.get("enabled", False))
        self._nodes_cfg     = hc.get("nodes", [])
        self._max_inner     = int(hc.get("max_inner_size", 2))
        self._heat_thresh   = float(hc.get("heat_threshold", 0.75))
        self._cool_thresh   = float(hc.get("cool_threshold", 0.35))
        self._gossip        = bool(hc.get("gossip", False))
        self._gossip_port   = int(hc.get("gossip_port", 7946))
        self._health_check  = bool(hc.get("health_check", True))
        self._hc_interval   = int(hc.get("health_check_interval_sec", 15))
        self._state_file    = hc.get("state_file")
        self._metrics       = metrics
        self._logger        = logger
        self._queue         = queue_ref
        self._cluster       = None
        self._node:         Optional[CNSLHuddleNode] = None
        self._local_id:     Optional[str] = None

    async def start(self) -> None:
        """Initialize HuddleCluster and start temperature reporting."""
        if not self.enabled:
            return

        try:
            from huddle_cluster import HuddleCluster, Server, GossipAgent
        except ImportError:
            if self._logger:
                await self._logger.log("huddle_warning", {
                    "msg": "HuddleCluster not installed. Run: pip install git+https://github.com/rahadbhuiya/HuddleCluster.git",
                })
            self.enabled = False
            return

        # Build GossipAgent if enabled
        gossip = None
        if self._gossip and self._nodes_cfg:
            import socket as _socket
            local_id = self._nodes_cfg[0].get("id", _socket.gethostname())
            gossip = GossipAgent(
                node_id     = local_id,
                gossip_port = self._gossip_port,
            )

        # Build cluster
        self._cluster = HuddleCluster(
            max_inner_size       = self._max_inner,
            heat_threshold       = self._heat_thresh,
            cool_threshold       = self._cool_thresh,
            gossip_agent         = gossip,
            health_check_path    = "/api/stats" if self._health_check else None,
            health_check_interval_sec = self._hc_interval,
            state_file           = self._state_file,
            alert_webhooks       = [],  # CNSL handles its own alerts
            on_rotation          = self._on_rotation,
        )

        # Register all CNSL nodes
        import socket as _socket
        local_host = _socket.gethostname()
        for i, node_cfg in enumerate(self._nodes_cfg):
            nid   = node_cfg.get("id", f"cnsl-{i:02d}")
            host  = node_cfg.get("host", "127.0.0.1")
            port  = int(node_cfg.get("port", 8765))
            weight= float(node_cfg.get("weight", 1.0))
            server = Server(
                id     = nid,
                host   = host,
                port   = port,
                weight = weight,
                tags   = {"role": "cnsl", "host": host},
            )
            self._cluster.add_server(server, force_inner=(i < self._max_inner))
            if host in (local_host, "127.0.0.1", "localhost"):
                self._local_id = nid

        self._cluster.start()

        if self._logger:
            await self._logger.log("huddle_started", {
                "nodes":     len(self._nodes_cfg),
                "inner_max": self._max_inner,
                "gossip":    self._gossip,
                "local_id":  self._local_id,
            })

        # Start temperature reporter for local node
        if self._local_id:
            self._node = CNSLHuddleNode(
                cluster    = self._cluster,
                server_id  = self._local_id,
                metrics    = self._metrics,
                logger     = self._logger,
                queue_ref  = self._queue,
            )
            await self._node.start()

    async def stop(self) -> None:
        if self._node:
            await self._node.stop()
        if self._cluster:
            try:
                self._cluster.stop()
            except Exception:
                pass

    #  Request routing 

    def proxy(self, client_ip: Optional[str] = None) -> Optional[str]:
        """
        Get the best CNSL node URL for routing a request.

        Uses HuddleCluster's affinity routing so the same client
        always hits the same CNSL node (important for JWT sessions).

        Returns "http://host:port" or None if no server available.
        """
        if not self.enabled or not self._cluster:
            return None
        try:
            server = self._cluster.get_server(affinity_key=client_ip)
            if server:
                return f"http://{server.host}:{server.port}"
        except Exception:
            pass
        return None

    #  Stats 

    def get_stats(self) -> Dict[str, Any]:
        """Return HuddleCluster health report for the dashboard API."""
        if not self.enabled or not self._cluster:
            return {"enabled": False}
        try:
            report = self._cluster.health_report()
            return {
                "enabled":       True,
                "local_id":      self._local_id,
                "local_temp":    self._node.current_temp if self._node else 0.0,
                "inner_servers": [
                    {
                        "id":   s.id,
                        "host": s.host,
                        "port": s.port,
                        "temp": round(s.temperature, 3),
                        "p95":  round(s.metrics.p95_latency(), 1),
                        "healthy": s.metrics.is_healthy,
                    }
                    for s in report.get("inner_ring", [])
                ],
                "outer_servers": [
                    {
                        "id":   s.id,
                        "host": s.host,
                        "port": s.port,
                        "temp": round(s.temperature, 3),
                    }
                    for s in report.get("outer_ring", [])
                ],
                "rotations":   report.get("total_rotations", 0),
                "fairness":    round(report.get("fairness_score", 1.0), 3),
            }
        except Exception as exc:
            return {"enabled": True, "error": str(exc)}

    #  Callbacks 

    def _on_rotation(self, event) -> None:
        """Called by HuddleCluster when a server rotates rings."""
        try:
            asyncio.get_event_loop().create_task(
                self._log_rotation(event)
            )
        except RuntimeError:
            pass

    async def _log_rotation(self, event) -> None:
        if self._logger:
            await self._logger.log("huddle_rotation", {
                "server_id": getattr(event, "server_id", "?"),
                "from_ring": getattr(event, "from_ring", "?"),
                "to_ring":   getattr(event, "to_ring", "?"),
                "reason":    getattr(event, "reason", "?"),
                "temp":      getattr(event, "temperature", 0.0),
            })