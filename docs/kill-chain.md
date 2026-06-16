# Kill Chain Tracker

CNSL tracks the full attack progression of every source IP across seven kill chain stages.
This is the intent graph described in the original CNSL research paper:

> "CNSL: A Correlated Network Security Layer for
>  Intent-Based Incident Detection and Response"

Instead of counting events in isolation, the kill chain tracker builds a per-IP graph that
shows *how far* an attacker has progressed and *what path* they took to get there.


## Why kill chain tracking?

A brute-force counter tells you that an IP failed 100 SSH logins.
The kill chain tells you that the same IP first scanned your web server,
then brute-forced SSH, then succeeded, then tried to escalate privileges.
Those are four different stages of a coordinated attack -- and that context
changes how you should respond.


## Stages

The tracker uses a seven-stage model derived from the Unified Kill Chain
and MITRE ATT&CK, adapted for network-level log observability:

| Stage | Name | What triggers it |
|:---:|:---|:---|
| 0 | Reconnaissance | Web scans, port probes, honeypot port hits, firewall blocks |
| 1 | Weaponization | Exploit path hits, known-bad threat feed match |
| 2 | Delivery | SSH brute-force, web auth failures, database auth failures |
| 3 | Exploitation | SSH login success after repeated failures |
| 4 | Installation | sudo/su failure after an SSH login (privilege escalation attempt) |
| 5 | C2 | Persistent reconnection after block -- correlation rule match |
| 6 | Actions on Objectives | Post-compromise data access or lateral movement (future) |

A chain is marked **complete** when stages 0, 2, and 3 are all observed --
meaning the attacker moved from reconnaissance through delivery to a confirmed breach.


## Score

Each IP is assigned a score from 0.0 to 1.0:

```
score = (highest stage observed + 1) / 7
```

Examples:
- Only web scans seen (stage 0): score = 0.14
- Brute-force in progress (stage 2): score = 0.43
- Credential breach confirmed (stage 3): score = 0.57
- Privilege escalation attempted (stage 4): score = 0.71
- C2 behavior (stage 5): score = 0.86


## Configuration

```json
{
  "kill_chain": {
    "enabled":       true,
    "max_chains":    5000,
    "stage_ttl_sec": 86400,
    "persist":       true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable or disable the tracker entirely |
| `max_chains` | `5000` | Maximum number of IP chains to keep in memory. Oldest is evicted when full. |
| `stage_ttl_sec` | `86400` | Chains not updated for this many seconds are pruned (24 hours default) |
| `persist` | `true` | Persist chains to SQLite so they survive a restart |


## REST API

### List all chains

```
GET /api/kill-chain
```

Query parameters:

| Parameter | Default | Description |
|:---|:---|:---|
| `limit` | `100` | Maximum number of chains to return |
| `min_score` | `0.0` | Only return chains with score >= this value |
| `complete_only` | `false` | Only return chains where all three minimum stages are confirmed |

Response: array of chain objects (see schema below).

---

### Get chain for one IP

```
GET /api/kill-chain/{ip}
```

Returns the full chain detail for the given IP address, including per-stage
event kinds and counts. Returns 404 if the IP has not been seen.

---

### Aggregate statistics

```
GET /api/kill-chain/stats
```

Returns:

```json
{
  "total_chains":    142,
  "complete_chains": 3,
  "avg_score":       0.31,
  "stage_distribution": {
    "Reconnaissance": 142,
    "Delivery":       89,
    "Exploitation":   3,
    "Installation":   1
  }
}
```


## Chain object schema

```json
{
  "ip":            "45.33.32.1",
  "first_seen":    "2024-11-01T02:14:33Z",
  "last_seen":     "2024-11-01T03:22:11Z",
  "stage_mask":    7,
  "max_stage":     2,
  "max_stage_name":"Delivery",
  "score":         0.429,
  "complete":      false,
  "event_count":   87,
  "geo_country":   "US",
  "geo_city":      "Fremont",
  "stages": {
    "0": {
      "stage":       0,
      "name":        "Reconnaissance",
      "description": "Web scanning, port probing, honeypot port hits",
      "first_seen":  "2024-11-01T02:14:33Z",
      "last_seen":   "2024-11-01T02:18:01Z",
      "count":       12,
      "event_kinds": ["WEB_SCAN", "FW_HONEYPOT_PORT"]
    },
    "2": {
      "stage":       2,
      "name":        "Delivery",
      "description": "Brute-force credential attempts (SSH, web, DB)",
      "first_seen":  "2024-11-01T02:19:44Z",
      "last_seen":   "2024-11-01T03:22:11Z",
      "count":       75,
      "event_kinds": ["SSH_FAIL"]
    }
  }
}
```


## Dashboard

The Kill Chain tab in the dashboard shows:

- **Stats bar** -- total chains, complete chains, average score, stage distribution
- **Table** -- one row per IP, sorted by score descending. Columns: IP, max stage,
  score bar, complete badge, event count, last seen, location, detail button
- **Detail view** -- opens below the table. Shows a horizontal pipeline of all seven
  stages, color-coded by whether they were observed. Each observed stage shows
  event count and a sample of event kinds. First/last seen and location shown below.

Filter controls:
- **Complete only** checkbox -- hides partial chains
- **Score filter** dropdown -- 0 / 0.3 / 0.5 / 0.7 thresholds
- **Refresh** button -- reloads from the API


## Database schema

```sql
CREATE TABLE kc_chains (
    ip          TEXT PRIMARY KEY,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    stage_mask  INTEGER DEFAULT 0,
    max_stage   INTEGER DEFAULT 0,
    score       REAL DEFAULT 0.0,
    complete    INTEGER DEFAULT 0,
    event_count INTEGER DEFAULT 0,
    geo_country TEXT,
    geo_city    TEXT,
    stage_data  TEXT DEFAULT '{}'
);
```

`stage_data` is a JSON blob of all stage records for that IP.
`stage_mask` is a bitmask: bit N is set if stage N has been observed.


## Origin

The kill chain tracker is the implementation of the core research thesis from the
CNSL paper: *"intent-based detection"* -- tracking what an attacker is trying to
accomplish rather than just counting individual events. The paper called this the
*"cognitive layer"* -- the part of CNSL that reasons about attacker intent across
multiple log sources over time.

See `../old-research/paper/paper.md` for the original research paper.