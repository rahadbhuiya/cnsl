# Country-Based Blocking

Block all traffic from specific countries **before** detection thresholds are reached.
The first event from any IP in a blocked country immediately triggers a `HIGH` severity
block -- no need to accumulate fails.

## Requirements

- GeoIP must be enabled (MaxMind offline or ip-api.com fallback)
- Requires CNSL 1.2.0 or later

## Configuration

```json
"country_block": {
  "enabled":   true,
  "countries": ["CN", "RU", "KP", "IR"],
  "allowlist": []
}
```

| Key | Type | Description |
|:---|:---|:---|
| `enabled` | bool | Enable/disable country blocking |
| `countries` | list | ISO 3166-1 alpha-2 codes (uppercase) |
| `allowlist` | list | IPs exempt from country blocking even if their country is blocked |

## Country Codes

Use two-letter uppercase [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) codes.

Common examples:
| Country | Code |
|:---|:---|
| China | CN |
| Russia | RU |
| North Korea | KP |
| Iran | IR |
| Belarus | BY |
| Venezuela | VE |

## Allowlisting Specific IPs

If you have trusted partners, vendors, or employees in a blocked country,
exempt their IPs:

```json
"country_block": {
  "enabled":   true,
  "countries": ["CN"],
  "allowlist": ["203.0.113.10", "203.0.113.11"]
}
```

The `country_block.allowlist` is separate from the top-level `allowlist`.
The top-level `allowlist` is always checked first by the blocker (those IPs
are never blocked by any rule).

## How It Works

1. On the first event from an unknown IP, CNSL does a GeoIP lookup (async)
2. If the IP's `countryCode` is in the blocked list, a `HIGH` detection is raised immediately
3. The IP is blocked, a notification is sent, and the incident is saved to the database
4. Subsequent events from the same IP are silently dropped (already blocked)

The check runs once per IP per session -- if the block expires and the same IP
reconnects, it will be checked again.

## Log Format

Country block events are logged as:
```json
{
  "ts": 1748685600.0,
  "type": "country_block_triggered",
  "payload": {
    "ip":          "1.2.3.4",
    "country":     "China",
    "countryCode": "CN",
    "event_kind":  "SSH_FAIL"
  }
}
```

## Dashboard

Country-blocked IPs appear in the Incidents and Blocks tabs with reason:
```
country_block: China (CN) is in the blocked-countries list
```

## Safety Note

Country blocking is a coarse tool. Use it when:
- You have no legitimate users or services in those countries
- You are seeing sustained attack volume from specific regions
- Combined with `--execute` mode for real blocking

In dry-run mode (the default), blocks are logged but not applied -- safe to test.

Always add your own management IP to the top-level `allowlist` before enabling
live blocking (`dry_run: false`).