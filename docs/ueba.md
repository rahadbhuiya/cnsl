# User and Entity Behavior Analytics (UEBA)

CNSL builds behavioral profiles for every user observed making successful
SSH logins, and flags activity that deviates from their established baseline.

## Detection Capabilities

| Anomaly | Description |
|:---|:---|
| **Unusual login hour** | Login outside the user's normal hours |
| **New source IP** | Login from an IP this user has never used |
| **Lateral movement** | Same user active on N+ IPs within a short time window |
| **Login after absence** | Login after more than N days of inactivity |
| **Frequency spike** | Today's logins significantly above the 7-day average |

Multiple anomalies can fire simultaneously and are reported together.

---

## Config

```json
"ueba": {
  "enabled":               true,
  "min_observations":      10,
  "lateral_window_sec":    600,
  "lateral_ip_threshold":  3,
  "absence_days":          7,
  "frequency_spike_factor": 3.0,
  "persist":               true
}
```

| Setting | Description |
|:---|:---|
| `enabled` | Enable UEBA engine |
| `min_observations` | Successful logins before anomaly detection starts (default: 10) |
| `lateral_window_sec` | Time window for lateral movement detection in seconds (default: 600) |
| `lateral_ip_threshold` | Distinct source IPs in window before lateral movement fires (default: 3) |
| `absence_days` | Days since last login before "login after absence" fires (default: 7) |
| `frequency_spike_factor` | Multiplier vs 7-day average before frequency spike fires (default: 3.0) |
| `persist` | Persist profiles to SQLite (survives restarts) |

---

## How It Works

### Profile Building

CNSL observes every successful SSH login. For each username it tracks:
- Hour-of-day distribution (0–23)
- Set of known source IPs with last-seen timestamps
- Rolling 7-day daily login counts
- Recent IPs in the lateral movement window
- First seen / last seen timestamps

Anomaly detection does not start until `min_observations` logins have been seen
for a user. This prevents false positives during the learning phase.

### Lateral Movement

If the same username logs in from N+ distinct source IPs within
`lateral_window_sec` seconds, a lateral movement anomaly is raised.
This catches credential sharing, compromised accounts pivoting between hosts,
or attackers who have stolen credentials and are testing them across systems.

### Persistence

When `persist: true`, profiles are saved to the CNSL SQLite database
(`store.db_path`). Profiles survive restarts and accumulate over time,
making the baselines more accurate with each passing day.

---

## API Reference

All endpoints require a valid JWT token.

### UEBA Stats

```
GET /api/ueba
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/ueba
```

```json
{
  "enabled":           true,
  "total_profiles":    42,
  "anomalous_users":   3,
  "total_logins_seen": 1834
}
```

### List User Profiles

```
GET /api/ueba/profiles
```

Query parameters:

| Parameter | Description |
|:---|:---|
| `limit` | Max results (default 50, max 200) |
| `offset` | Pagination offset |
| `sort_by` | Sort field: `anomaly_count` (default), `total_logins`, `last_seen` |

```bash
# Most anomalous users first
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/ueba/profiles?sort_by=anomaly_count&limit=10"
```

```json
{
  "profiles": [
    {
      "username":        "alice",
      "total_logins":    127,
      "anomaly_count":   3,
      "first_seen":      "2026-01-01T00:00:00Z",
      "last_seen":       "2026-05-31T10:00:00Z",
      "known_ip_count":  4,
      "known_ips":       ["1.2.3.4", "5.6.7.8"],
      "login_hours":     {"9": 45, "10": 38, "11": 22},
      "recent_anomalies": []
    }
  ],
  "total": 42
}
```

### Get Single User Profile

```
GET /api/ueba/profiles/{username}
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/ueba/profiles/alice
```

### Recent Anomalies

```
GET /api/ueba/anomalies
```

Query parameters:

| Parameter | Description |
|:---|:---|
| `limit` | Max results (default 50, max 200) |
| `username` | Filter by username |

```bash
# All recent anomalies
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/ueba/anomalies?limit=20"

# Anomalies for alice only
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/ueba/anomalies?username=alice"
```

```json
{
  "anomalies": [
    {
      "username":      "alice",
      "src_ip":        "203.0.113.5",
      "reason":        "new source IP 203.0.113.5 (known IPs: 2); login at unusual hour 03:xx",
      "anomaly_types": ["new_source_ip", "unusual_hour"],
      "ts":            1748685600.0,
      "time":          "2026-05-31T10:00:00Z"
    }
  ],
  "total": 1
}
```

---

## Integration with Detections

When a UEBA anomaly is detected on a successful SSH login, it is included
as an additional reason in the detection incident. If no other rule fired
(e.g. the login was successful without preceding failures), a `MEDIUM`
severity incident is raised so the anomaly appears in the dashboard
Incidents tab and triggers notifications.

This means UEBA anomalies:
- Appear in `GET /api/incidents`
- Trigger configured notifications (Telegram, email, etc.)
- Auto-create a case if the incident is HIGH severity
- Are searchable via `GET /api/search?q=ueba`

---

## Database Schema

```sql
-- User profiles (one row per username)
ueba_profiles:
  username, total_logins, anomaly_count, first_seen, last_seen,
  login_hours (JSON), known_ips (JSON)

-- Anomaly log (append-only)
ueba_anomalies:
  id, ts, time, username, src_ip, reason, anomaly_type
```