# REST API Reference

All endpoints are available when `--dashboard` is active (default port 8765).

## Authentication

```bash
# Login
curl -s -X POST http://127.0.0.1:8765/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"cnsl-change-me"}' | jq .token

# Use token
export TOKEN="<jwt-token>"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/api/stats
```

---

## Endpoints

### Stats & Overview

```
GET  /api/stats          Engine summary (events processed, blocks, incidents)
GET  /api/system         Uptime, SSH fails, events processed, blocks total
GET  /api/events         Raw recent events
GET  /api/debug          Module wiring status (which modules are enabled)
```

### Incidents & Attackers

```
GET  /api/incidents      Recent incidents (?limit=50, max 500)
GET  /api/top-attackers  Top attacker IPs with geo info
GET  /api/timeline       Incident counts per hour (last 24h)
```

### Blocks

```
GET  /api/blocks         Currently active blocks
POST /api/block          Manual block  { "ip": "1.2.3.4" }   — analyst+ only
POST /api/unblock        Manual unblock { "ip": "1.2.3.4" }  — analyst+ only
```

### Search & Query

```
GET  /api/search         Full-text KQL-like search
GET  /api/aggregate      Aggregations: by_severity, top_ips, top_countries, hourly
```

**Search query syntax:**
```
GET /api/search?q=severity:HIGH
GET /api/search?q=1.2.3.4
GET /api/search?q=country:China
GET /api/search?q=reasons:brute_force
GET /api/search?q=severity:HIGH&since=1700000000&until=1800000000
GET /api/search?q=severity:HIGH&limit=100
```

### Export

```
GET  /api/events/normalized    ECS-normalized incident documents
GET  /api/export/ecs           Elasticsearch bulk NDJSON download
GET  /api/export/cef           CEF text download (ArcSight/Splunk)
POST /api/search/es-push       Push incidents to Elasticsearch
GET  /api/search/es-status     Elasticsearch cluster health
```

### ML

```
GET  /api/ml-status      ML detector status, training progress, samples collected
```

### Honeypot

```
GET  /api/honeypot       Honeypot status and recent sessions
```

### FIM

```
GET  /api/fim            FIM alerts and watched paths
```

### Assets

```
GET  /api/assets         Passive network asset inventory
```

### Monitoring

```
GET  /api/metrics        Prometheus metrics (auth required)
```

### Reports

```
POST /api/report         Generate report { "format": "html", "days": 30 }
```

### Auth

```
POST /api/login          { "username": "...", "password": "..." }
POST /api/logout
```

---

## Example: Fetch HIGH incidents

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/search?q=severity:HIGH&limit=20" | jq .
```

## Example: Manual block

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4"}' \
  http://127.0.0.1:8765/api/block
```

## Example: Push to Elasticsearch

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/search/es-push | jq .
```

## Example: Export NDJSON

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/export/ecs -o events.ndjson

# Push to Elasticsearch directly
curl -X POST http://localhost:9200/_bulk \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @events.ndjson
```

---

## Response Format

All endpoints return JSON. Common envelope:
```json
{
  "ok":   true,
  "data": { ... }
}
```

Errors return HTTP 4xx/5xx with:
```json
{
  "ok":    false,
  "error": "description"
}
```

---

## Rate Limiting

No built-in rate limiting on the API — run behind a reverse proxy (nginx, Caddy)
with rate limiting if exposing beyond localhost.

For remote access, use an SSH tunnel:
```bash
ssh -L 8765:127.0.0.1:8765 user@yourserver
```