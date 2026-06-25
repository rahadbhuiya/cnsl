# Multi-Tenant Support

A single CNSL instance can serve multiple isolated organizations (tenants).
Each tenant has independent users, rules, notifications, and allowlists,
while sharing the underlying detection engine and infrastructure.

## When to Use Multi-Tenant

- **MSSPs** -- manage multiple customer environments from one CNSL instance
- **Large organizations** -- isolate departments (IT, Finance, HR) with different rules
- **SaaS deployments** -- offer CNSL as a service to multiple customers

Single-tenant mode (default) is unchanged -- existing configs work without modification.

---

## Config

```json
"tenants": {
  "enabled":        true,
  "default_tenant": "acme",
  "list": {
    "acme": {
      "display_name": "Acme Corp",
      "users": {
        "alice": { "password_hash": "$2b$12$...", "role": "admin" },
        "bob":   { "password_hash": "$2b$12$...", "role": "analyst" }
      },
      "notifications": {
        "telegram": { "enabled": true, "bot_token": "...", "chat_id": "..." }
      },
      "allowlist": ["10.0.0.0/8", "192.168.1.0/24"],
      "country_block": {
        "enabled": true,
        "countries": ["CN", "RU"]
      },
      "rules": {
        "ssh.brute_force": { "threshold": 3, "severity": "HIGH" },
        "web.scan_flood":  { "enabled": false }
      }
    },
    "globex": {
      "display_name": "Globex Inc",
      "users": {
        "charlie": { "password_hash": "$2b$12$...", "role": "admin" }
      },
      "rules": {
        "ssh.brute_force": { "threshold": 10 }
      }
    }
  }
}
```

### Per-Tenant Settings

| Setting | Description |
|:---|:---|
| `display_name` | Human-readable tenant name shown in dashboard |
| `users` | Tenant-specific user accounts (isolated from other tenants) |
| `notifications` | Per-tenant alert channels (Telegram, email, etc.) |
| `allowlist` | IPs never blocked for this tenant |
| `country_block` | Country blocking config for this tenant |
| `rules` | Rule threshold/severity overrides for this tenant |

---

## Isolation Model

| Resource | Isolated per tenant | Shared |
|:---|:---:|:---:|
| User accounts | yes | |
| JWT tokens | yes (tenant_id claim) | |
| Alert rules (overrides) | yes | |
| Notifications | yes | |
| Allowlist | yes | |
| Country block config | yes | |
| Incidents (DB rows) | yes (tenant_id column) | |
| Cases | yes | |
| Detection engine | | yes |
| GeoIP | | yes |
| Threat feed | | yes |
| Log sources | | yes |
| Blocker (iptables) | | yes |

---

## API Reference

All endpoints require admin role.

### List Tenants

```
GET /api/tenants
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/tenants | jq .
```

```json
{
  "enabled":        true,
  "tenant_count":   2,
  "default_tenant": "acme",
  "tenants": [
    {
      "id":           "acme",
      "display_name": "Acme Corp",
      "user_count":   2,
      "has_custom_rules": true,
      "country_block_enabled": true
    }
  ]
}
```

### Create Tenant (admin only)

```
POST /api/tenants
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "initech",
    "display_name": "Initech",
    "users": {
      "peter": { "password_hash": "...", "role": "admin" }
    }
  }' \
  http://127.0.0.1:8765/api/tenants
```

### Delete Tenant (admin only)

```
DELETE /api/tenants/{tenant_id}
```

```bash
curl -s -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/tenants/initech
```

Cannot delete the default tenant.

---

## Per-Tenant Rule Tuning

Each tenant gets its own `RuleEngine` with overrides applied on top of
global defaults. Changes are cached until `update_tenant_rules()` is called.

Example: Acme wants SSH brute-force to fire sooner and at HIGH severity:

```json
"acme": {
  "rules": {
    "ssh.brute_force": { "threshold": 3, "severity": "HIGH" }
  }
}
```

Globex keeps the default threshold but disables web scan flood:

```json
"globex": {
  "rules": {
    "web.scan_flood": { "enabled": false }
  }
}
```

---

## Single-Tenant Migration

To enable multi-tenant mode on an existing single-tenant deployment:

1. Move existing users from `auth.users` into `tenants.list.myorg.users`
2. Set `tenants.enabled: true` and `tenants.default_tenant: myorg`
3. Restart CNSL

Existing tokens will need to be re-issued (they don't have `tenant_id` claims).