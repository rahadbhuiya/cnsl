# Multi-Node Federation

CNSL nodes running on different servers can share detection signals in
real time, so an attack visible to one node becomes visible to all of them.
This closes the federation gap from the original CNSL research paper:

> "Future work includes multi-node federation, allowing CNSL instances
>  across different hosts to correlate attacker behavior collectively
>  rather than in isolation."


## Why federation?

Without federation, every CNSL node only sees its own logs. If an
attacker scans `web-01`'s nginx and then brute-forces `db-01`'s MySQL,
neither node alone has enough signal to recognize this as one coordinated
attack -- each just sees a single-source event that may be below its own
detection threshold.

Federation gives every node visibility into what every other node is
seeing for the same IP, without requiring a central correlator or any
new infrastructure -- it reuses the Redis connection that already exists
for blocklist sync (`redis_sync.py`).


## How it differs from existing distributed features

CNSL already has several Redis- and cluster-related features. Federation
is a distinct, additional layer:

| Feature | What it shares | Module |
|:---|:---|:---|
| Distributed blocklist | "This IP is blocked" | `redis_sync.py` |
| HuddleCluster | Node load/temperature for load balancing | `huddle_integration.py` |
| Agent forwarding | Raw log events, one-way (agent -> central server) | `agent.py` |
| **Federation** | **Detection signals, peer-to-peer, between full CNSL nodes** | `federation.py` |

Federation is the only one of these that lets two independently-running
CNSL instances build a *combined* picture of an attacker's behavior.


## How it works

1. **Shared connection, new channel.** `FederationBus` reuses the same
   Redis connection object as `RedisSync` -- no second connection, no new
   config block for host/port/password. It subscribes to a new pub/sub
   channel, `{prefix}:federation`, kept separate from the existing
   `{prefix}:events` blocklist channel.

2. **Publishing.** Every time a kill-chain-relevant event happens locally
   (SSH fail, web scan, sudo fail, etc.), the node publishes a compact
   `FederatedSignal`: `{node_id, ip, kind, severity, ts}`. A per-(ip, kind)
   dedup window (default 5 seconds) prevents flooding the channel with
   redundant publishes during a sustained attack.

3. **Receiving.** Every other connected node receives the signal and
   feeds it into its **own local** `kill_chain_tracker.update()` for that
   IP -- as if the event had happened on that node, but the kill chain
   record still only reflects stages, not which node saw what (that
   detail lives in the separate federation IP record, see below).

4. **Cross-node tracking.** Independently of the kill chain feed, the
   `FederationBus` keeps a `FederatedIPRecord` per IP showing exactly
   which nodes reported which event kinds. Once 2 or more distinct nodes
   have reported on the same IP, `is_cross_node` becomes `True` and the
   IP appears in the dashboard's "Cross-Node Attacks" table.

5. **Graceful degradation.** If Redis is unavailable or `federation.enabled`
   is `false`, every publish/receive call becomes a safe no-op. Local
   detection is never delayed or blocked by federation.


## Configuration

Federation reuses the existing `redis` config block for connection
details -- it does not introduce a second connection.

```json
{
  "redis": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 6379,
    "key_prefix": "cnsl"
  },
  "federation": {
    "enabled":           true,
    "min_severity":      "LOW",
    "dedupe_window_sec": 5,
    "max_remote_ips":    10000
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable federation. Requires `redis.enabled: true` to actually connect. |
| `min_severity` | `LOW` | Reserved for future severity-based publish filtering |
| `dedupe_window_sec` | `5` | Minimum seconds between re-publishing the same (ip, kind) pair |
| `max_remote_ips` | `10000` | Maximum number of IP federation records kept in memory. Oldest evicted when full. |

Every node in the cluster must point at the same Redis instance and use
the same `key_prefix` to see each other.


## REST API

### This node's federation status

```
GET /api/federation/status
```

```json
{
  "enabled":          true,
  "connected":        true,
  "node_id":          "a1b2c3d4",
  "channel":          "cnsl:federation",
  "signals_sent":     142,
  "signals_received": 87,
  "known_peer_count": 2,
  "ips_tracked":      34,
  "cross_node_ips":   3
}
```

### Known peer nodes

```
GET /api/federation/nodes
```

```json
{
  "nodes": [
    {"node_id": "web-01-a1b2", "last_seen": "2024-11-15T02:14:33Z"},
    {"node_id": "db-01-c3d4",  "last_seen": "2024-11-15T02:13:01Z"}
  ]
}
```

### Cross-node attacks

```
GET /api/federation/cross-node?limit=50
```

Returns IPs that have been reported by 2 or more distinct nodes, sorted
by most recently active:

```json
[
  {
    "ip":            "45.33.32.1",
    "first_seen":    "2024-11-15T01:50:02Z",
    "last_seen":     "2024-11-15T02:14:33Z",
    "node_count":    2,
    "is_cross_node": true,
    "nodes": {
      "web-01-a1b2": {
        "signal_count": 12,
        "kinds":        ["WEB_SCAN", "WEB_AUTH_FAIL"],
        "last_seen":    "2024-11-15T02:01:00Z"
      },
      "db-01-c3d4": {
        "signal_count": 8,
        "kinds":        ["DB_AUTH_FAIL"],
        "last_seen":    "2024-11-15T02:14:33Z"
      }
    }
  }
]
```

### Combined view for one IP

```
GET /api/federation/ip/{ip}
```

Returns the same shape as one entry above, scoped to a single IP.
Returns 404 if no federation record exists for that IP.


## Dashboard

The Federation panel appears in the Settings tab, above Module Status.

**Summary cards**: connection status, signals sent, signals received,
cross-node IP count (highlighted in red when greater than zero).

**Known Peer Nodes table**: every node ID this node has heard a signal
from, with last seen timestamp.

**Cross-Node Attacks table**: IPs seen by 2+ nodes, which node IDs
reported on them, which event kinds were observed by each, and when.

Click Refresh to reload, or open the Settings tab to load automatically.


## Interaction with Kill Chain Tracker

Federation does not replace or duplicate the kill chain tracker -- it
feeds it. When `engine.py` wires `federation.on_remote_signal`, every
remote signal calls `kill_chain_tracker.update(ip, kind)` on the
receiving node, exactly as if that event kind had been observed locally.

This means: if Node A sees `WEB_SCAN` and Node B sees `SSH_FAIL` for the
same IP, **both nodes'** kill chain for that IP will show both stages,
even though each node only logged one of the two events itself. The
kill chain's `complete` flag and `score` reflect the attacker's full
cross-node path on every node in the cluster.


## Interaction with redis_sync

Federation deliberately does not modify `redis_sync.py`. It only reads
`redis_sync._redis` (the underlying connection) and `redis_sync.prefix`
/ `redis_sync.node_id` for channel naming and node identity. This keeps
the two systems independent: disabling federation has zero effect on
blocklist synchronization, and vice versa.


## Origin

Federation is the direct implementation of the research paper's listed
future work item: *"multi-node federation, allowing CNSL instances
across different hosts to correlate attacker behavior collectively."*

The original research papers are available in the separate `cnsl-research` repository.