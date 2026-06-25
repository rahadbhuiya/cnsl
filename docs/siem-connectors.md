# SIEM / SOAR Native Push Connectors

CNSL can push incidents and detections to external SIEM and SOAR platforms
in real time as they happen, without requiring any manual export step.

Three connectors are built in:

| Connector | Platform |
|:---|:---|
| Splunk HEC | Splunk Enterprise, Splunk Cloud |
| Microsoft Sentinel | Azure Monitor Logs / Log Analytics |
| Webhook | Palo Alto XSOAR, IBM QRadar, custom SOC tooling |


## How it works

Every time a detection alert fires in `detector.py`, the result is pushed
asynchronously to all enabled connectors. The push is fire-and-forget --
it does not delay detection or block the event loop.

If a push fails, the event is queued for retry (up to `max_retries` attempts
with exponential backoff). The retry queue holds up to 1000 events in memory.
Operators can also force a flush from the dashboard Settings tab.


## Splunk HEC

The Splunk HTTP Event Collector (HEC) connector pushes events to:

```
POST {hec_url}/services/collector/event
Authorization: Splunk {token}
Content-Type: application/json
```

Payload format:
```json
{
  "time":       1699999999.0,
  "host":       "my-server",
  "sourcetype": "cnsl:incident",
  "index":      "cnsl",
  "event": {
    "ip":             "45.33.32.1",
    "severity":       "HIGH",
    "reasons":        ["ssh_brute_force: 120 failures"],
    "_cnsl_version":  "2.9.0",
    "_push_time":     "2024-11-15T02:14:33Z"
  }
}
```

### Config

```json
{
  "siem": {
    "splunk": {
      "enabled":      true,
      "hec_url":      "https://splunk.example.com:8088",
      "token":        "your-hec-token",
      "index":        "cnsl",
      "sourcetype":   "cnsl:incident",
      "host":         "my-cnsl-server",
      "verify_ssl":   true,
      "timeout_sec":  5,
      "max_retries":  3,
      "min_severity": "MEDIUM"
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable Splunk push |
| `hec_url` | | Full URL to HEC endpoint, including port |
| `token` | | HEC token from Splunk Settings > Data Inputs > HTTP Event Collector |
| `index` | `cnsl` | Splunk index to write to |
| `sourcetype` | `cnsl:incident` | Splunk sourcetype |
| `host` | `` | Optional host field override |
| `verify_ssl` | `true` | Verify Splunk TLS certificate |
| `timeout_sec` | `5` | HTTP request timeout |
| `max_retries` | `3` | Max retry attempts for failed pushes |
| `min_severity` | `MEDIUM` | Only push alerts at or above this severity |


## Microsoft Sentinel

The Sentinel connector pushes to the Log Analytics Data Collector REST API
using HMAC-SHA256 request signing:

```
POST https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01
Authorization: SharedKey {workspace_id}:{signature}
Log-Type: CNSLIncident
Content-Type: application/json
```

Events appear in the Log Analytics workspace as a custom table named
`{log_type}_CL` (e.g. `CNSLIncident_CL`).

### Config

```json
{
  "siem": {
    "sentinel": {
      "enabled":      true,
      "workspace_id": "your-workspace-id",
      "shared_key":   "your-shared-key",
      "log_type":     "CNSLIncident",
      "api_version":  "2016-04-01",
      "timeout_sec":  5,
      "max_retries":  3,
      "min_severity": "MEDIUM"
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable Sentinel push |
| `workspace_id` | | Log Analytics workspace ID (Settings > Agents) |
| `shared_key` | | Primary or secondary key (Settings > Agents) |
| `log_type` | `CNSLIncident` | Custom table prefix (becomes `{log_type}_CL` in Sentinel) |
| `api_version` | `2016-04-01` | API version -- do not change unless Microsoft deprecates it |
| `timeout_sec` | `5` | HTTP request timeout |
| `max_retries` | `3` | Max retry attempts |
| `min_severity` | `MEDIUM` | Min severity to push |

### Finding workspace_id and shared_key

1. Azure Portal > Log Analytics workspaces > your workspace
2. Settings > Agents
3. Copy "Workspace ID" and "Primary key"


## Generic Webhook

The webhook connector sends a JSON POST to any HTTPS endpoint. This works
with Palo Alto XSOAR, IBM QRadar (REST API ingest), PagerDuty Events v2,
and any custom SOC ingest pipeline.

Payload format:
```json
{
  "cnsl_version": "2.9.0",
  "push_time":    "2024-11-15T02:14:33Z",
  "event": {
    "ip":       "45.33.32.1",
    "severity": "HIGH",
    "reasons":  ["ssh_brute_force: 120 failures"]
  }
}
```

### Config

```json
{
  "siem": {
    "webhook": {
      "enabled":      true,
      "url":          "https://your-soar.example.com/api/ingest",
      "method":       "POST",
      "headers":      {
        "X-API-Key": "your-api-key"
      },
      "bearer_token": "",
      "verify_ssl":   true,
      "timeout_sec":  5,
      "max_retries":  3,
      "min_severity": "MEDIUM"
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable webhook push |
| `url` | | Full HTTPS URL for the ingest endpoint |
| `method` | `POST` | HTTP method (POST or PUT) |
| `headers` | `{}` | Extra headers to add to every request |
| `bearer_token` | `` | If set, adds `Authorization: Bearer {token}` |
| `verify_ssl` | `true` | Verify TLS certificate |
| `timeout_sec` | `5` | HTTP request timeout |
| `max_retries` | `3` | Max retry attempts |
| `min_severity` | `MEDIUM` | Min severity to push |


## REST API

### Connector status

```
GET /api/siem/status
```

Returns health, push counts, and error information for all connectors, plus
the current retry queue depth.

```json
{
  "any_enabled": true,
  "queue_depth": 0,
  "connectors": {
    "splunk": {
      "enabled":     true,
      "healthy":     true,
      "status":      200,
      "push_count":  42,
      "error_count": 0,
      "last_error":  null
    },
    "sentinel": { "enabled": false },
    "webhook":  { "enabled": false }
  }
}
```

### Send test event

```
POST /api/siem/test/{name}
```

Where `{name}` is `splunk`, `sentinel`, or `webhook`. Sends a synthetic
LOW severity test event to verify the connector is working.

Returns `{"ok": true, "connector": "splunk"}` on success.

### Flush retry queue

```
POST /api/siem/flush
```

Forces an immediate retry of all queued events. Returns counts by connector:

```json
{"flushed": {"splunk": 3}}
```


## Dashboard

The SIEM / SOAR Connectors section appears at the top of the Settings tab.

Each enabled connector shows:
- Status (Healthy / Error / Disabled)
- Push count and error count
- Last error message (if any)
- Send Test button

The retry queue line shows how many events are pending retry,
with a Flush Now button to force immediate retry.


## aiohttp dependency

All three connectors require `aiohttp` for async HTTP. CNSL already lists
this as a dependency. If it is not installed, connectors degrade gracefully
(push returns False, events are queued but never sent).

```
pip install aiohttp
```