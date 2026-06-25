# HuddleCluster Integration

CNSL integrates with [HuddleCluster](https://github.com/rahadbhuiya/HuddleCluster)
to provide intelligent, self-organizing load balancing across multiple CNSL instances.
No central coordinator is needed -- nodes self-organize using temperature scores.

## How It Works

```
CNSL-01 (inner ring)  <--- attacks flooding in --->  temp 0.85 -> evicted
CNSL-02 (inner ring)  <--- normal traffic      --->  temp 0.30 -> stays
CNSL-03 (outer ring)  <--- resting             --->  temp 0.10 -> promoted
```

**Temperature score** = CNSL load converted to [0.0 - 1.0]:

| Metric | Weight |
|:---|:---:|
| Events per second (/ 100 saturation) | 40% |
| Queue fill (queue_size / max) | 35% |
| Active incidents (/ 50 saturation) | 25% |

| Temperature | Ring | Meaning |
|:---|:---|:---|
| 0.0 - 0.35 | Inner or outer | Idle -- coolest node gets promoted |
| 0.35 - 0.75 | Inner | Healthy, serving traffic |
| 0.75+ | Outer (evicted) | Overloaded -- resting, not serving |

---

## Installation

```bash
pip install git+https://github.com/rahadbhuiya/HuddleCluster.git
```

---

## Config

```json
"huddle": {
  "enabled":        true,
  "nodes": [
    {"id": "cnsl-01", "host": "10.0.0.1", "port": 8765, "weight": 1.0},
    {"id": "cnsl-02", "host": "10.0.0.2", "port": 8765, "weight": 1.0},
    {"id": "cnsl-03", "host": "10.0.0.3", "port": 8765, "weight": 1.0}
  ],
  "max_inner_size":             2,
  "heat_threshold":             0.75,
  "cool_threshold":             0.35,
  "gossip":                     true,
  "gossip_port":                7946,
  "health_check":               true,
  "health_check_interval_sec":  15,
  "state_file":                 "/var/lib/cnsl/huddle_state.json"
}
```

| Setting | Description |
|:---|:---|
| `nodes` | All CNSL instances in the cluster |
| `max_inner_size` | How many nodes actively serve traffic at once |
| `heat_threshold` | Temperature above this -> node evicted to outer ring |
| `cool_threshold` | Temperature below this -> node promoted back to inner ring |
| `gossip` | UDP multicast temperature sharing (no central coordinator) |
| `health_check` | Periodically GET `/api/stats` to verify nodes are alive |
| `state_file` | Persist cluster state across CNSL restarts |

---

## Dashboard

The **Settings** tab shows live HuddleCluster status:
- Inner ring nodes with temperature color (green/yellow/red) and p95 latency
- Outer ring nodes (resting)
- Total rotations and fairness score

```
GET /api/huddle
```

```json
{
  "enabled": true,
  "local_id": "cnsl-01",
  "local_temp": 0.42,
  "inner_servers": [
    {"id": "cnsl-01", "host": "10.0.0.1", "port": 8765, "temp": 0.42, "p95": 12.3, "healthy": true},
    {"id": "cnsl-02", "host": "10.0.0.2", "port": 8765, "temp": 0.18, "p95": 8.1,  "healthy": true}
  ],
  "outer_servers": [
    {"id": "cnsl-03", "host": "10.0.0.3", "port": 8765, "temp": 0.05}
  ],
  "rotations": 3,
  "fairness": 0.94
}
```

---

## Gossip Protocol

With `gossip: true`, all CNSL nodes share temperature scores over UDP multicast
(default port 7946). This means:
- No central broker needed
- Works even if one node goes down
- Nodes converge on correct ring membership within seconds

```bash
# Firewall rule needed on each node:
sudo ufw allow 7946/udp
```

---

## Deployment Example

```yaml
# docker-compose.yml (3-node cluster)
services:
  cnsl-01:
    image: cnsl:2.9.0
    environment:
      - CNSL_NODE_ID=cnsl-01
    ports: ["8765:8765"]
    volumes:
      - ./config/config-01.json:/etc/cnsl/config.json

  cnsl-02:
    image: cnsl:2.9.0
    environment:
      - CNSL_NODE_ID=cnsl-02
    ports: ["8766:8765"]
    volumes:
      - ./config/config-02.json:/etc/cnsl/config.json

  cnsl-03:
    image: cnsl:2.9.0
    environment:
      - CNSL_NODE_ID=cnsl-03
    ports: ["8767:8765"]
    volumes:
      - ./config/config-03.json:/etc/cnsl/config.json
```

Each node's config points to all three nodes:
```json
"huddle": {
  "enabled": true,
  "nodes": [
    {"id": "cnsl-01", "host": "cnsl-01", "port": 8765},
    {"id": "cnsl-02", "host": "cnsl-02", "port": 8765},
    {"id": "cnsl-03", "host": "cnsl-03", "port": 8765}
  ],
  "max_inner_size": 2,
  "gossip": true
}
```