# REST API Reference

All endpoints require the dashboard to be running (`--dashboard`, default port 8765).

All write endpoints (`POST`, `PATCH`, `DELETE`) require the `admin` or `analyst` role.
Read-only endpoints require at minimum the `viewer` role.

## Authentication

```bash
# Login
curl -s -X POST http://127.0.0.1:8765/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"cnsl-change-me"}' | jq .token

# Use token in all subsequent requests
export TOKEN="<jwt-token>"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/api/stats
```

Token lifetime is configurable via `dashboard.token_ttl_sec` (default 86400 = 24 hours).

---

## Stats & Overview

```
GET  /api/stats              Engine summary: events processed, blocks, incidents
GET  /api/system             Uptime, SSH fails, events processed, blocks total
GET  /api/events             Raw recent events (limit param)
GET  /api/debug              Module wiring status -- which modules are enabled/connected
```

`/api/debug` returns a JSON object with boolean fields like `kill_chain_enabled`, `federation_connected`, `pattern_learner_enabled`, `zero_trust_enabled`, `cloud_aws_enabled`, etc. Useful for verifying config.

---

## Incidents & Blocks

```
GET  /api/incidents          Recent incidents
GET  /api/incidents/export   Export incidents as NDJSON or CEF
GET  /api/attackers          Top attackers by incident count
GET  /api/blocks             Active IP blocks
POST /api/block              Manually block an IP
POST /api/unblock            Manually unblock an IP
```

**`GET /api/incidents`** query params:

| Param | Default | Description |
|:---|:---|:---|
| `limit` | `100` | Max incidents to return |
| `severity` | (all) | Filter: `LOW`, `MEDIUM`, `HIGH` |
| `src_ip` | (all) | Filter by source IP |
| `from` | (all) | ISO timestamp lower bound |
| `to` | (all) | ISO timestamp upper bound |

**`POST /api/block`** and **`POST /api/unblock`** require the `X-CNSL-Secret` header matching `api.secret_value` in config.

```bash
curl -X POST http://127.0.0.1:8765/api/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CNSL-Secret: your-secret" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "reason": "manual block", "duration_sec": 3600}'
```

---

## Audit Log

```
GET  /api/audit               Compliance audit trail -- who did what, when
```

Requires the `auditor` or `admin` role (`logs:read` permission). Records every
manual block/unblock and secret rotation with the acting user, source IP, and
timestamp -- separate from the general detection-event log, for SOC2/ISO27001-style
review.

| Param | Default | Description |
|:---|:---|:---|
| `actor` | (all) | Filter by username |
| `action` | (all) | Filter: `block`, `unblock`, `rotate_secret` |
| `target` | (all) | Filter by target (e.g. blocked IP) |
| `limit` | `100` | Max entries (capped at 1000) |
| `offset` | `0` | Pagination offset |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/audit?actor=admin&action=block&limit=20"
```

Response:

```json
{
  "entries": [
    {"id": 3, "time": "2026-07-19T10:15:00Z", "actor": "admin",
     "action": "block", "target": "1.2.3.4", "details": {"ok": true},
     "source_ip": "10.0.0.5"}
  ],
  "total": 3
}
```

---

## Kill Chain

```
GET  /api/kill-chain                 All tracked chains
GET  /api/kill-chain/stats           Aggregate stage distribution and average score
GET  /api/kill-chain/{ip}            Full chain detail for one IP
```

**`GET /api/kill-chain`** query params:

| Param | Default | Description |
|:---|:---|:---|
| `limit` | `100` | Max chains to return |
| `min_score` | `0.0` | Only return chains with score >= this value |
| `complete_only` | `false` | Only return chains where stages 0+2+3 are confirmed |

**Response example:**
```json
{
  "ip":            "45.33.32.1",
  "score":         0.57,
  "complete":      false,
  "max_stage":     3,
  "max_stage_name": "Exploitation",
  "event_count":   14,
  "stages": {
    "0": {"name": "Reconnaissance", "count": 3, "event_kinds": ["WEB_SCAN"]},
    "2": {"name": "Delivery",       "count": 10, "event_kinds": ["SSH_FAIL"]},
    "3": {"name": "Exploitation",   "count": 1,  "event_kinds": ["SSH_SUCCESS"]}
  }
}
```

### Predictive blocking

Config-only (no dedicated API endpoint) -- `cnsl/predictive_blocking.py` hooks into the same kill-chain update path every event already passes through. Every other block decision in CNSL fires when ONE rule's own threshold is crossed; predictive blocking instead looks at an IP's overall kill-chain *trajectory* -- its score and how many distinct stages it's touched -- and blocks early when that shape looks like a real attack in progress, even if the attacker spread their steps across different attack types (recon, then a web exploit attempt, then credential stuffing) none of which alone reached its own threshold. Opt-in and disabled by default, since it deliberately trades some precision for reacting sooner.

```json
"predictive_blocking": {
  "enabled": false,
  "score_threshold": 0.60,
  "min_stages": 2
}
```

Both `score_threshold` and `min_stages` must hold together, not score alone -- a single very-late-stage high-severity event can spike score without the IP having shown a real multi-step pattern. Manual blocks triggered this way appear in `/api/incidents`/logs with reason `"predictive: kill-chain score 0.XX across N stages (...)"`, and go through the same `Blocker.block_ip()` as every other block (respects the allowlist, is idempotent, honors dry_run).

---

## Attack Behavior Graph

```
GET  /api/graph              Pre-computed nodes + edges JSON
```

**`GET /api/graph`** query params:

| Param | Default | Description |
|:---|:---|:---|
| `limit` | `50` | Max nodes to include |
| `min_incidents` | `1` | Only include IPs with at least this many incidents |

**Response:**
```json
{
  "nodes": [
    {
      "ip": "45.33.32.1",
      "incident_count": 5,
      "max_severity": "HIGH",
      "kill_chain": {"score": 0.57, "max_stage_name": "Exploitation"},
      "trust":      {"score": 0.35, "label": "suspicious"}
    }
  ],
  "edges": [
    {"source": "45.33.32.1", "target": "192.168.1.5",
     "shared_rules": ["ssh.brute_force"]}
  ]
}
```

---

## ML Detector

```
GET   /api/ml-status          Status, training progress, current parameters
PATCH /api/ml/params          Live-update parameters (no restart needed)
POST  /api/ml/retrain         Force immediate retrain
GET   /api/ml/alerts          Recent ML anomaly alerts
GET   /api/ml/feature-stats   Feature importance counts from recent alerts
POST  /api/ml/alerts/{id}/false-positive   Mark an alert as a false positive
```

**`PATCH /api/ml/params`** body (all fields optional):
```json
{
  "contamination":        0.05,
  "threshold":            -0.1,
  "min_samples":          100,
  "retrain_interval_sec": 3600
}
```

Constraints: `contamination` clamped to [0.001, 0.5]; `min_samples` minimum 10; `retrain_interval_sec` minimum 60.

**`GET /api/ml/alerts`** query params: `limit` (default 50). Each alert now includes `id` and `false_positive`.

**`POST /api/ml/retrain`** response:
```json
{"ok": true,  "samples": 142}          // retrain scheduled
{"ok": false, "reason": "Not enough samples (42 < 100)"}
```

**`POST /api/ml/alerts/{id}/false-positive`** -- requires analyst+ role (`block:write`). The IsolationForest model is unsupervised, so there's no label to flip; instead, the alert's own feature vector is folded back into training data with extra weight (`ml.fp_reinforce_weight`, default 5 copies) so the next retrain treats that pattern -- and statistically similar ones -- as normal rather than an outlier. Idempotent: marking an already-marked alert returns success without double-reinforcing. Only alerts still in the last 200 (`recent_alert_count`) can be marked; older ones return 404.

```json
{"ok": true, "status": {"...": "...", "false_positives_marked": 3, "fp_reinforce_weight": 5}}
```

---

## Zero-Trust

```
GET  /api/zero-trust/stats                  Aggregate trust statistics
GET  /api/zero-trust/scores                 All scored entities, sorted by score ascending
GET  /api/zero-trust/scores/{entity}        Score detail with recent signal history
POST /api/zero-trust/scores/{entity}/reset  Reset entity to initial_score
```

**`GET /api/zero-trust/scores`** query params:

| Param | Default | Description |
|:---|:---|:---|
| `type` | (all) | Filter by entity type: `ip` or `user` |
| `max_score` | `1.0` | Return only entities with score <= this value |
| `limit` | `100` | Max rows to return |

For `/api/zero-trust/scores/{entity}` and the reset endpoint, add `?type=user` for user entities (default: `ip`).

**Stats response:**
```json
{
  "total_entities": 142, "trusted": 98, "moderate": 30,
  "suspicious": 12, "untrusted": 2, "avg_score": 0.71
}
```

---

## Pattern Learning

```
GET  /api/pattern-suggestions               Active suggestions
GET  /api/pattern-suggestions/stats         Aggregate learner statistics
POST /api/pattern-suggestions/{id}/promote  Promote to live rule
POST /api/pattern-suggestions/{id}/dismiss  Dismiss permanently
```

**`GET /api/pattern-suggestions`** query params: `dismissed=true`, `promoted=true` to include those.

**Suggestion response:**
```json
{
  "id":           "a3f9c1b2e8d4",
  "pattern_key":  "SSH_FAIL+WEB_SCAN",
  "event_kinds":  ["SSH_FAIL", "WEB_SCAN"],
  "occurrences":  11,
  "confidence":   1.0,
  "severity":     "MEDIUM",
  "threshold":    8,
  "window_sec":   300,
  "example_ips":  ["45.33.32.1"],
  "promoted":     false,
  "dismissed":    false
}
```

---

## SIEM Connectors

```
GET  /api/siem/status         Connector health + retry queue depth
POST /api/siem/test/{name}    Send test event to splunk|sentinel|webhook
POST /api/siem/flush          Force flush retry queue
```

`{name}` must be one of `splunk`, `sentinel`, or `webhook`. The connector must be enabled to test.

---

## Federation

```
GET  /api/federation/status      This node's federation health and stats
GET  /api/federation/nodes       All peer nodes with last-seen timestamp
GET  /api/federation/cross-node  IPs seen by 2+ distinct nodes
GET  /api/federation/ip/{ip}     Combined per-node view for one IP
GET  /api/federation/hub         Multi-node health/stats + cross-node view, one call
```

**`GET /api/federation/cross-node`** query params: `limit` (default 50).

**`GET /api/federation/hub`** -- the multi-node "hub" view: every known node's health (uptime, incidents, active blocks -- via each node's Redis heartbeat) plus this node's federation cross-node IP data, in one response. Requires Redis (`redis.enabled: true`); returns 400 if Redis isn't connected, since a hub view is meaningless for a single unclustered node. Query params: `limit` (default 50, passed through to the cross-node-IPs portion).

```json
{
  "this_node": "a1b2c3d4",
  "node_count": 3,
  "nodes": [
    {"node_id": "a1b2c3d4", "is_self": true, "last_seen": "2026-07-24T10:00:00Z",
     "stats": {"uptime_sec": 86400, "incidents_total": {"HIGH": 12, "MEDIUM": 40, "LOW": 8},
               "blocks_active": 5, "blocks_total": 91, "events_processed": 48213}},
    {"node_id": "e5f6a7b8", "is_self": false, "last_seen": "2026-07-24T10:00:03Z", "stats": {...}}
  ],
  "cross_node_ips": [{"ip": "45.33.32.1", "node_count": 2, "nodes": {...}}],
  "federation": {"enabled": true, "connected": true, "signals_sent": 340, ...}
}
```

A node running an older CNSL version that hasn't been upgraded shows up with `stats: {}` rather than being dropped from the list.

---

## Cloud Identity

```
GET  /api/cloud-identity/status  Connector health, poll counts, events fed
```

---

## Rules

```
GET   /api/rules                 All detection rules with current overrides
GET   /api/rules/{rule_id}       Single rule detail
PATCH /api/rules/{rule_id}       Override threshold, severity, window, enabled
POST  /api/rules/{rule_id}/enable
POST  /api/rules/{rule_id}/disable
POST  /api/rules/{rule_id}/reset  Reset to built-in defaults
```

**`PATCH /api/rules/{rule_id}`** body:
```json
{"threshold": 5, "severity": "HIGH", "window_sec": 120, "enabled": true}
```

All fields are optional. Only supplied fields are updated.

---

## Correlation Rules

Cross-source rules (`cnsl/correlator.py`) that fire on combinations of events across multiple log sources -- e.g. web recon followed by SSH brute-force, or a honeypot-port hit followed by an SSH attempt. Distinct from the single-source detection rules above (`/api/rules`).

```
GET   /api/correlation-rules              All correlation rules with current overrides
GET   /api/correlation-rules/{name}       Single rule detail
PATCH /api/correlation-rules/{name}       Tune enabled/window_sec/cooldown_sec/confidence
POST  /api/correlation-rules/{name}/enable
POST  /api/correlation-rules/{name}/disable
POST  /api/correlation-rules/{name}/reset  Reset to built-in defaults
```

Rule names: `multi_service_brute_force`, `web_recon_then_ssh`, `honeypot_then_ssh`, `web_auth_flood`, `privilege_escalation`, `persistent_recon`.

**`PATCH /api/correlation-rules/{name}`** body:
```json
{"enabled": true, "window_sec": 300, "cooldown_sec": 120, "confidence": 0.8}
```

All fields are optional. `window_sec` must be positive, `cooldown_sec` non-negative, `confidence` between 0.0 and 1.0. Only the rule's tunable knobs (enable/disable, sliding window, alert cooldown, confidence score) are adjustable this way -- each rule's trigger logic (e.g. "3 SSH fails") stays in code. Same config.json override path as detection rules, under a separate `correlation_rules` block:

```json
"correlation_rules": {
  "web_auth_flood": {"enabled": false},
  "persistent_recon": {"window_sec": 900, "confidence": 0.6}
}
```

---

## UEBA

```
GET  /api/ueba/anomalies              Recent UEBA anomalies
GET  /api/ueba/profiles               All user behavioral profiles
GET  /api/ueba/profiles/{username}    Profile detail for one user
```

**`GET /api/ueba/anomalies`** query params: `limit` (default 50).

---

## Cases

```
GET   /api/cases               All cases
POST  /api/cases               Create a new case
GET   /api/cases/{id}          Case detail with comments and linked incidents
PATCH /api/cases/{id}          Update case (status, assignee, title)
POST  /api/cases/{id}/comment  Add a comment
POST  /api/cases/{id}/link     Link an incident to the case
```

**`GET /api/cases`** query params: `status=open|closed|in_progress`.

**Create case body:**
```json
{"title": "SSH attack from 45.33.32.1", "assignee": "analyst1", "incident_id": 42}
```

---

## FIM

```
GET  /api/fim/alerts   Recent file integrity alerts (limit param)
GET  /api/fim/status   Watched paths and last baseline check time
```

---

## Honeypot

```
GET  /api/honeypot   Status, active redirects, recent session list
```

---

## Rate Limit

```
GET  /api/rate-limit/status      Current rate-limit state and top requesters
POST /api/rate-limit/reset/{ip}  Reset rate-limit block for an IP
```

---

## Reports

```
POST /api/report/generate   Generate a report
GET  /api/report/list       List generated reports
```

**Generate body:**
```json
{"format": "html", "period_days": 30}
```

`format` is `html`, `pdf`, or `json`.

---

## Threat Feed

```
GET  /api/threat-feed/status   Feed health and last update times
POST /api/threat-feed/refresh  Force refresh all feeds
```

---

## Search

```
GET  /api/search         Full-text search across events and incidents
GET  /api/search/status  Search engine availability and index stats
```

**`GET /api/search`** query params:

| Param | Default | Description |
|:---|:---|:---|
| `q` | | Search query (KQL-like syntax) |
| `limit` | `50` | Max results |
| `from` | | ISO timestamp lower bound |
| `to` | | ISO timestamp upper bound |

---

## Export

```
GET  /api/incidents/export   Export incidents (format=ndjson or format=cef)
GET  /api/export/cef         CEF export for ArcSight/Splunk
GET  /api/export/ecs         ECS JSON export for Elasticsearch
GET  /api/export/stix        STIX 2.1 bundle of detected attacker IPs (downloadable file)
POST /api/es-push/status     Elasticsearch push status
POST /api/es-push/push       Trigger manual Elasticsearch push
```

**`GET /api/export/stix`** query params: `limit` (default 200, max 1000). Returns a STIX 2.1 bundle: one `indicator` object per attacker IP (from `store.top_attackers()`, so already deduplicated) plus a `identity` object for CNSL as the producer. Downloads as `cnsl-iocs.stix2.json`.

---

## TAXII 2.1 Server

A minimal, read-only TAXII 2.1 server exposing the same data as `/api/export/stix`, so SOAR platforms, threat intel platforms (TIPs), and other SIEMs can pull CNSL's detected attacker IPs automatically instead of a human downloading a file. One API root (`cnsl`), one collection (`attacker-ips`) -- always read-only, there is no ingestion path.

```
GET /taxii2/                                        Discovery
GET /taxii2/cnsl/                                    API root info
GET /taxii2/cnsl/collections/                        List collections
GET /taxii2/cnsl/collections/attacker-ips/           Collection detail
GET /taxii2/cnsl/collections/attacker-ips/objects/   The STIX objects (query param: limit)
```

Auth: same Bearer/JWT token as the rest of the REST API (`POST /api/login`), not HTTP Basic Auth as some TAXII clients default to -- most TAXII client libraries let you configure a bearer token instead.

This is intentionally minimal: no `added_after` cursoring beyond a simple `limit`, and no write/ingestion endpoints. Fine for a single self-hosted node's outbound feed; if you need full TAXII pagination semantics, treat this as a starting point.

---

## Attacker Fingerprinting

Cross-IP actor clustering (`cnsl/fingerprint.py`): the same attacker often rotates through many IPs (VPN exits, botnet nodes, cloud churn) while their *behavior* stays recognizable -- the same mix of attack types, the same timing rhythm, the same TTP keywords in incident reasons. This builds a behavioral fingerprint per IP from its incident history and finds/clusters IPs whose fingerprints are similar enough to plausibly be the same actor. Not machine learning -- a similarity metric over hand-picked features, computed fresh each call; no training, no model file.

```
GET /api/fingerprint/clusters       Groups of IPs that look like the same actor
GET /api/fingerprint/similar/{ip}   IPs similar to one given IP
```

Both require at least 3 incidents for an IP to be fingerprinted reliably (`MIN_INCIDENTS_FOR_FINGERPRINT`); IPs below that are simply excluded, not errored.

**`GET /api/fingerprint/clusters`** query params: `threshold` (default 0.80, clamped 0.0-1.0), `incident_limit` (default 5000, max 20000 -- how many recent incidents to fingerprint over).

```json
{
  "clusters": [
    {"ips": ["45.33.32.1", "91.108.4.88"], "size": 2, "fingerprints": [...]}
  ],
  "total_clusters": 1,
  "total_fingerprinted_ips": 14,
  "threshold": 0.8
}
```

**`GET /api/fingerprint/similar/{ip}`** query params: `threshold` (default 0.75), `limit` (default 20, max 200), `incident_limit` (as above). Returns 404 if `{ip}` doesn't have enough incident history to fingerprint.

```json
{
  "ip": "45.33.32.1",
  "fingerprint": {"kind_ratios": {...}, "mean_interval_sec": 30.0, "interval_cv": 0.0,
                  "avg_severity": 0.6, "reason_keywords": ["brute_force"], ...},
  "similar": [{"ip": "91.108.4.88", "score": 0.97, "fingerprint": {...}}],
  "threshold": 0.75
}
```

Similarity combines cosine similarity of attack-type mix (40%), timing rhythm closeness (25%), Jaccard similarity of TTP keywords (25%), and severity closeness (10%) -- see `cnsl/fingerprint.py`'s `similarity()` docstring for the exact formula.

---

## Graph Correlation

While attacker fingerprinting (above) clusters IPs by *direct* pairwise behavioral similarity, `cnsl/graph_correlation.py` finds IPs correlated *transitively*, through the attack graph itself, even when no two of them look similar to each other. The graph is heterogeneous: `ip` nodes connect to `rule` nodes (the TTP keyword each incident's reason names) and `stage` nodes (kill-chain stages reached). Two IPs with nothing directly in common can still land in the same connected component -- e.g. IP A and IP C never interact, but both trigger `sql_injection` and both reach the `Delivery` stage, so the graph links them through those shared nodes. Classical connected-components, not a trained model -- no training, no model file.

```
GET /api/graph/campaigns             Groups of 3+ IPs transitively linked through the graph
GET /api/graph/explain/{ip_a}/{ip_b} What two specific IPs directly have in common
```

A rule/stage node triggered by only one IP is a dead end, not correlation -- a node must be shared by at least `min_shared_degree` (default 2) distinct IPs before it's allowed to bridge them into a campaign.

**`GET /api/graph/campaigns`** query params: `min_ips` (default 3, max 100), `min_shared_degree` (default 2, max 50), `incident_limit` (default 5000, max 20000).

```json
{
  "campaigns": [
    {"ips": ["1.1.1.1", "2.2.2.2", "3.3.3.3"], "size": 3,
     "shared_nodes": [{"id": "rule:sql_injection", "type": "rule", "label": "sql_injection"}]}
  ],
  "total_campaigns": 1,
  "graph_nodes": 4,
  "graph_edges": 3
}
```

**`GET /api/graph/explain/{ip_a}/{ip_b}`** -- only reports *direct* shared nodes; two IPs correlated transitively through a third IP (not directly) return `directly_connected: false` here even though they're in the same campaign in `/api/graph/campaigns`.

```json
{"ip_a": "1.1.1.1", "ip_b": "2.2.2.2",
 "shared_nodes": [{"id": "rule:sql_injection", "type": "rule", "label": "sql_injection"}],
 "directly_connected": true}
```

---

## System

```
GET  /api/attackers   Top attacker IPs by incident count (limit param)
GET  /api/assets      Discovered asset inventory
GET  /api/metrics     Prometheus metrics (text format)
GET  /ws/agent        WebSocket agent log ingestion endpoint
GET  /ws/live         WebSocket live event stream
```

**`GET /api/attackers`** query params: `limit` (default 20).