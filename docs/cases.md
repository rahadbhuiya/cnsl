# Case Management

Track security incidents as actionable cases with status, analyst assignment,
and timestamped notes. Cases give your SOC team a structured workflow for
investigating and resolving alerts.

## Overview

Cases are created automatically from every HIGH severity detection, or manually
from the dashboard for any incident. Each case has:

- **Status** -- open -> investigating -> closed / false_positive
- **Severity** -- LOW / MEDIUM / HIGH (inherited from detection)
- **Assigned to** -- any dashboard username
- **Notes** -- append-only timestamped analyst notes with full audit trail
- **Linked incident** -- traceability back to the original detection

## Case Lifecycle

```
         open
          |
          v
    investigating  <---- (reassign, add notes anytime)
          |
    +-----+------+
    v            v
  closed   false_positive
```

Status transitions are logged as system notes automatically.

---

## Auto-Creation

Cases are created automatically for every **HIGH** severity incident:
- SSH credential breach
- Country-blocked IP
- Honeypot trigger
- Web exploit attempt
- Cross-source correlation hits

MEDIUM and LOW incidents do not auto-create cases -- create them manually
from the dashboard if needed.

---

## RBAC

| Role | Permissions |
|:---|:---|
| viewer | Read cases and notes |
| analyst+ | Create cases, update status, assign, add notes |
| admin | All of the above + delete cases |

---

## API Reference

All endpoints require a valid JWT token (`Authorization: Bearer <token>`).

### List Cases

```
GET /api/cases
```

Query parameters:

| Parameter | Description |
|:---|:---|
| `status` | Filter by status: `open`, `investigating`, `closed`, `false_positive` |
| `assigned_to` | Filter by assignee username. Use `__unassigned__` for unassigned cases |
| `severity` | Filter by severity: `LOW`, `MEDIUM`, `HIGH` |
| `limit` | Max results (default 50, max 200) |
| `offset` | Pagination offset |

```bash
# All open cases
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/cases?status=open"

# Cases assigned to alice
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/cases?assigned_to=alice"

# Unassigned HIGH cases
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/cases?assigned_to=__unassigned__&severity=HIGH"
```

Response:
```json
{
  "cases": [
    {
      "id": 1,
      "title": "SSH Brute-Force -- 45.33.32.156",
      "status": "open",
      "severity": "HIGH",
      "src_ip": "45.33.32.156",
      "assigned_to": null,
      "created_by": "system",
      "created_at": 1748685600.0,
      "updated_at": 1748685600.0,
      "country": "United States",
      "isp": "Linode",
      "reasons": ["brute_force: 9 fails in 60s"]
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Case Stats

```
GET /api/cases/stats
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/cases/stats
```

```json
{
  "total": 42,
  "open": 12,
  "investigating": 5,
  "closed": 22,
  "false_positive": 3,
  "high": 30,
  "medium": 10,
  "low": 2
}
```

### Get Single Case

```
GET /api/cases/{id}
```

Returns the case plus all notes:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/cases/1
```

```json
{
  "id": 1,
  "title": "SSH Brute-Force -- 45.33.32.156",
  "status": "investigating",
  "severity": "HIGH",
  "src_ip": "45.33.32.156",
  "assigned_to": "alice",
  "notes": [
    {
      "id": 1,
      "case_id": 1,
      "author": "system (alice)",
      "body": "Status changed: open -> investigating",
      "ts": 1748685700.0,
      "time": "2026-05-31T10:01:40Z"
    },
    {
      "id": 2,
      "case_id": 1,
      "author": "alice",
      "body": "Confirmed attacker. Same subnet as last week's campaign.",
      "ts": 1748685800.0,
      "time": "2026-05-31T10:03:20Z"
    }
  ]
}
```

### Create Case Manually

```
POST /api/cases
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious access from VPN exit node",
    "severity": "MEDIUM",
    "src_ip": "1.2.3.4",
    "assigned_to": "alice",
    "reasons": ["manual: analyst flagged for review"]
  }' \
  http://127.0.0.1:8765/api/cases
```

```json
{ "ok": true, "case_id": 7 }
```

### Update Status

```
PATCH /api/cases/{id}/status
```

```bash
# Start investigating
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "investigating"}' \
  http://127.0.0.1:8765/api/cases/1/status

# Close
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "closed"}' \
  http://127.0.0.1:8765/api/cases/1/status

# Mark false positive
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status": "false_positive"}' \
  http://127.0.0.1:8765/api/cases/1/status
```

Valid statuses: `open`, `investigating`, `closed`, `false_positive`

### Assign Case

```
PATCH /api/cases/{id}/assign
```

```bash
# Assign to alice
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assigned_to": "alice"}' \
  http://127.0.0.1:8765/api/cases/1/assign

# Unassign
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"assigned_to": null}' \
  http://127.0.0.1:8765/api/cases/1/assign
```

### Add Note

```
POST /api/cases/{id}/notes
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"body": "Checked threat intel -- IP confirmed malicious. Blocking permanently."}' \
  http://127.0.0.1:8765/api/cases/1/notes
```

Notes are append-only. Status changes and assignments also generate system notes automatically.

### Delete Case (admin only)

```
DELETE /api/cases/{id}
```

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/cases/1
```

Deletes the case and all its notes permanently.

---

## Database Schema

Cases are stored in the same SQLite database as incidents (`store.db_path`).

```sql
-- cases table
id, incident_id, title, status, severity, src_ip,
assigned_to, created_at, updated_at, created_by,
country, isp, reasons (JSON)

-- case_notes table
id, case_id, author, body, ts, time
```

The schema is created automatically on startup via `Store.init()`.
Existing databases are migrated safely with `CREATE TABLE IF NOT EXISTS`.