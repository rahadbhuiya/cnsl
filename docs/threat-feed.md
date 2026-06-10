# Community Threat Feed

CNSL downloads known-bad IP lists from multiple public threat intelligence
feeds and checks every incoming IP against them. Hits are flagged or blocked
immediately — before detection thresholds are reached.

## Built-in Feeds

| Feed | Key | Default | Type |
|:---|:---|:---:|:---|
| Emerging Threats Compromised IPs | `emerging_threats` | ✓ | Plain IPs |
| Feodo Tracker Botnet C2 | `feodo_tracker` | ✓ | Plain IPs |
| CINS Army Score | `cins_army` | ✓ | Plain IPs |
| abuse.ch SSL Blacklist | `abuse_ch_sslbl` | ✓ | Plain IPs |
| Spamhaus DROP | `spamhaus_drop` | — | CIDR |
| Spamhaus EDROP | `spamhaus_edrop` | — | CIDR |

All feeds are free and require no API key.

---

## Config

```json
"threat_feed": {
  "enabled":              true,
  "auto_block":           false,
  "severity":             "HIGH",
  "refresh_interval_sec": 3600,
  "local_file":           null,
  "feeds": {
    "emerging_threats": true,
    "feodo_tracker":    true,
    "cins_army":        true,
    "abuse_ch_sslbl":   true,
    "spamhaus_drop":    false,
    "spamhaus_edrop":   false
  }
}
```

| Setting | Description |
|:---|:---|
| `enabled` | Enable/disable the entire threat feed system |
| `auto_block` | `true` = block immediately on hit; `false` = flag and alert only |
| `severity` | Severity for threat feed hits (default: `HIGH`) |
| `refresh_interval_sec` | How often feeds are re-downloaded (default: 3600 = 1 hour) |
| `local_file` | Path to a custom file with one IP or CIDR per line |
| `feeds` | Per-feed enable/disable toggles |

---

## How It Works

1. On startup CNSL downloads all enabled feeds (async, non-blocking)
2. A background task re-downloads feeds every `refresh_interval_sec`
3. On every incoming event, the source IP is checked:
   - Plain IP: O(1) set lookup
   - CIDR ranges: linear scan (only if plain lookup misses)
4. On a hit:
   - Incident is logged and saved
   - Case is auto-created (HIGH severity)
   - Notification is sent
   - If `auto_block: true` — IP is immediately blocked via iptables/ipset

---

## Local Custom Blocklist

Add your own IPs or CIDR blocks:

```bash
# /etc/cnsl/custom_blocklist.txt
# One IP or CIDR per line, # for comments

1.2.3.4
10.20.30.0/24
# VPN exit nodes
185.220.101.0/24
```

```json
"threat_feed": {
  "enabled":    true,
  "local_file": "/etc/cnsl/custom_blocklist.txt"
}
```

---

## API Reference

### Feed Status

```
GET /api/threat-feed
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/threat-feed | jq .
```

```json
{
  "enabled":        true,
  "auto_block":     false,
  "severity":       "HIGH",
  "total_ips":      42350,
  "total_cidrs":    0,
  "last_refresh":   "2026-05-31T10:00:00Z",
  "refresh_interval_sec": 3600,
  "feeds": [
    {
      "key":          "emerging_threats",
      "name":         "Emerging Threats Compromised IPs",
      "enabled":      true,
      "ip_count":     15234,
      "cidr_count":   0,
      "last_updated": "2026-05-31T10:00:00Z",
      "last_error":   null,
      "ok":           true
    }
  ]
}
```

### Manual Refresh (analyst+)

```
POST /api/threat-feed/refresh
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/threat-feed/refresh | jq .
```

### Check a Specific IP

```
POST /api/threat-feed/check
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}' \
  http://127.0.0.1:8765/api/threat-feed/check
```

```json
{
  "ip":     "1.2.3.4",
  "listed": true,
  "hit": {
    "ip":         "1.2.3.4",
    "match_type": "exact",
    "source":     "threat_feed"
  }
}
```