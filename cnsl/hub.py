"""
cnsl/hub.py — Multi-node hub view.

Federation (cnsl/federation.py) lets nodes share detection signals, and
RedisSync (cnsl/redis_sync.py) already gives every node a heartbeat key
in Redis. But before this module, there was no single place an operator
could see ALL nodes' health side by side -- each node's dashboard only
showed itself, plus a list of peer IDs and timestamps with no stats.

get_hub_view() combines:
  - RedisSync.get_cluster_nodes()   -- per-node heartbeat + stats
  - FederationBus.status()/get_cross_node_ips() -- this node's view of
    cross-node attacker activity

...into one aggregated response for a dashboard "Hub" panel: a table of
every known node (health, incidents, active blocks, uptime) plus the
IPs seen by 2+ nodes.

This node's own entry is included via `stats_provider` wired in
engine.py (see RedisSync.heartbeat_loop) -- it is not treated specially
here beyond an `is_self` flag for the UI to highlight it.

Failure mode: if Redis is unavailable, the hub view degrades to a
single-node view (just this node, no stats) -- it never raises.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


async def get_hub_view(
    redis_sync: Any,
    federation_bus: Optional[Any] = None,
    cross_node_limit: int = 50,
) -> Dict[str, Any]:
    """
    Build the aggregated multi-node view.

    Returns:
        {
          "this_node":  "<node_id>",
          "nodes": [
            {"node_id": ..., "is_self": bool, "last_seen": <iso>,
             "stats": {...}},
            ...
          ],
          "cross_node_ips": [...],   # from federation_bus, if given
          "federation": {...} | None # federation_bus.status(), if given
        }
    """
    this_node = getattr(redis_sync, "node_id", "local")

    try:
        cluster = await redis_sync.get_cluster_nodes()
    except Exception:
        cluster = {this_node: {"ts": None, "stats": {}}}

    nodes: List[Dict[str, Any]] = []
    for node_id, info in cluster.items():
        nodes.append({
            "node_id":   node_id,
            "is_self":   node_id == this_node,
            "last_seen": info.get("ts"),
            "stats":     info.get("stats", {}),
        })
    # Self first, then most-recently-seen peers.
    nodes.sort(key=lambda n: (not n["is_self"], n["node_id"]))

    cross_node_ips: List[Dict[str, Any]] = []
    federation_status: Optional[Dict[str, Any]] = None
    if federation_bus is not None:
        try:
            cross_node_ips = [
                r.to_dict() for r in federation_bus.get_cross_node_ips(limit=cross_node_limit)
            ]
            federation_status = federation_bus.status()
        except Exception:
            pass

    return {
        "this_node":      this_node,
        "node_count":     len(nodes),
        "nodes":          nodes,
        "cross_node_ips": cross_node_ips,
        "federation":     federation_status,
    }