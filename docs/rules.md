# Alert Rule Engine

Every detection in CNSL is driven by a named rule with an id, severity,
threshold, and window. Rules can be enabled/disabled and threshold-tuned
at runtime via the dashboard API -- no restart required.

## Built-in Rules

| Rule ID | Name | Default Severity | Default Threshold | Window |
|:---|:---|:---|:---|:---|
| `ssh.brute_force` | SSH Brute Force | MEDIUM | 8 fails | 60s |
| `ssh.credential_stuffing` | SSH Credential Stuffing | MEDIUM | 4 usernames | 60s |
| `ssh.credential_breach` | SSH Credential Breach | HIGH | 5 fails before success | 60s |
| `web.scan_flood` | Web Scan Flood | MEDIUM | 20 scan events | 60s |
| `web.auth_flood` | Web Auth Flood | MEDIUM | 15 auth failures | 60s |
| `web.exploit` | Web Exploit Attempt | HIGH | 1 exploit hit | instant |
| `db.brute_force` | Database Brute Force | MEDIUM | 5 DB failures | 60s |
| `fw.honeypot_port` | Honeypot Port Hit | HIGH | 1 connection | instant |
| `net.repeat_offender` | Repeat Offender Escalation | HIGH | 3 incidents | 3600s |
| `cloud.signin_brute_force` | Cloud Sign-in Brute Force | MEDIUM | 5 failures | 300s |
| `cloud.mfa_failure` | Cloud MFA Failure / Bypass | HIGH | 1 failure | instant |
| `cloud.risky_signin` | Cloud Risky Sign-in | HIGH | 1 flag | instant |
| `cloud.signin_breach` | Cloud Sign-in Breach | HIGH | 3 prior failures | 300s |
| `cloud.impossible_travel` | Cloud Impossible Travel | HIGH | 1 event | instant |

Cloud rules (added in v2.6.0) apply to AWS CloudTrail and Azure AD events.
All 14 rules can be adjusted or disabled from the dashboard Rules tab or via `PATCH /api/rules/{rule_id}`.

---

## Config Overrides

Override any rule in `config.json` under the `"rules"` key.
Unknown rule ids are silently ignored.

```json
"rules": {
  "ssh.brute_force": {
    "enabled":   true,
    "threshold": 5,
    "severity":  "HIGH",
    "window_sec": 30
  },
  "web.scan_flood": {
    "enabled": false
  }
}
```

All four fields are optional -- only specify what you want to change.

---

## API Reference

All endpoints require a valid JWT. Write operations require `analyst` role or above.

### List All Rules

```
GET /api/rules
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rules | jq .
```

```json
{
  "rules": [
    {
      "id":                 "db.brute_force",
      "name":               "Database Brute Force",
      "description":        "Fires when an IP generates many database authentication failures.",
      "default_severity":   "MEDIUM",
      "default_threshold":  5,
      "default_window_sec": 60,
      "effective_severity":  "MEDIUM",
      "effective_threshold": 5,
      "effective_window":    60,
      "enabled":            true,
      "tags":               ["database", "brute-force"],
      "overridden":         false
    }
  ],
  "total": 9
}
```

### Get Single Rule

```
GET /api/rules/{rule_id}
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rules/ssh.brute_force
```

### Update Rule (analyst+)

```
PATCH /api/rules/{rule_id}
```

Send any combination of fields:

```bash
# Lower SSH brute-force threshold and escalate to HIGH
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"threshold": 5, "severity": "HIGH"}' \
  http://127.0.0.1:8765/api/rules/ssh.brute_force

# Tighten the window
curl -s -X PATCH \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"window_sec": 30}' \
  http://127.0.0.1:8765/api/rules/ssh.brute_force
```

### Enable / Disable (analyst+)

```bash
# Disable web scan flood (too noisy for your environment)
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rules/web.scan_flood/disable

# Re-enable it
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rules/web.scan_flood/enable
```

### Reset to Defaults (admin only)

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rules/ssh.brute_force/reset
```

---

## Runtime Behaviour

- Changes take effect **immediately** -- the next event processed will use the new threshold/severity
- Overrides survive for the lifetime of the process; they are not persisted to the database
- To make changes permanent, add them to `config.json` under `"rules"`
- Disabling a rule means its events are still counted in state, but no alert is raised

---

## Common Tuning Examples

**Tighten SSH brute-force for high-security servers:**
```json
"ssh.brute_force": { "threshold": 3, "severity": "HIGH" }
```

**Disable web scan flood for a high-traffic public site:**
```json
"web.scan_flood": { "enabled": false }
```

**Make repeat offenders escalate faster:**
```json
"net.repeat_offender": { "threshold": 2, "window_sec": 1800 }
```

**Make DB brute-force fire sooner:**
```json
"db.brute_force": { "threshold": 3 }
```