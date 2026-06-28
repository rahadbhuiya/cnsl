# Configuration Reference

## Config File Location

CNSL auto-discovers config in this order:
1. `--config FILE` (explicit CLI path)
2. `/etc/cnsl/config.json`
3. `/etc/cnsl/config.yaml`
4. `./config.json` (current directory)
5. Built-in defaults only

Copy the example and edit:
```bash
sudo mkdir -p /etc/cnsl
sudo cp config/config.example.json /etc/cnsl/config.json
sudo nano /etc/cnsl/config.json
```

---

## Minimum Required Changes

```json
{
  "authlog_path": "/var/log/auth.log",

  "allowlist": [
    "127.0.0.1",
    "YOUR_OWN_IP_HERE"
  ],

  "actions": {
    "dry_run": false,
    "block_duration_sec": 900
  },

  "store": {
    "db_path": "/var/lib/cnsl/cnsl_state.db"
  }
}
```

> **Always** add your own IP to `allowlist` before setting `dry_run: false`.
> Use absolute paths for `db_path` -- relative paths reset the baseline on restart.

---

## Detection Thresholds

```json
"thresholds": {
  "fails_window_sec":              60,   // sliding window for fail counting
  "fails_threshold":               8,    // SSH fails before MEDIUM alert
  "unique_users_threshold":        4,    // distinct usernames before stuffing alert
  "success_after_fails_threshold": 5,   // breach: success after N fails
  "incident_cooldown_sec":         120, // suppress duplicate alerts per IP
  "web_scan_threshold":            20,  // 404/scan events before alert
  "web_auth_fail_threshold":       15,  // 401/403 events before alert
  "db_fail_threshold":             5    // DB auth fails before alert
}
```

---

## Blocking

```json
"actions": {
  "dry_run":                   true,        // SAFE DEFAULT -- change to false to enable
  "block_duration_sec":        900,         // 15-minute block
  "block_backend":             "iptables",  // "iptables" | "ipset"
  "ipset_name":                "cnsl_blocklist",
  "chain":                     "INPUT",
  "repeat_offender_threshold": 3,           // escalate block if IP hits N incidents
  "repeat_offender_window_sec":3600
}
```

---

## Country-Based Blocking

Block all traffic from specific countries before detection thresholds are reached.
Requires GeoIP to be enabled. Uses ISO 3166-1 alpha-2 codes.

```json
"country_block": {
  "enabled":   true,
  "countries": ["CN", "RU", "KP", "IR"],
  "allowlist": ["203.0.113.5"]
}
```

The first event from any IP in a blocked country immediately triggers a `HIGH`
severity block. The `allowlist` inside `country_block` exempts specific IPs
even if their country is blocked (useful for trusted partners in those countries).

---

## Log Sources

```json
"log_sources": {
  "nginx":  "/var/log/nginx/access.log",
  "apache": "/var/log/apache2/access.log",
  "mysql":  "/var/log/mysql/error.log",
  "ufw":    "/var/log/ufw.log",
  "syslog": "/var/log/syslog"
}
```

Set any value to `null` to disable that source.

---

## GeoIP

MaxMind GeoLite2 (offline, fast, no rate limit):
```json
"geoip": {
  "mmdb_path": "/etc/cnsl/GeoLite2-City.mmdb"
}
```

Download free at https://www.maxmind.com/en/geolite2/signup

If `mmdb_path` is not set, CNSL falls back to ip-api.com (online, 45 req/min).

---

## Dashboard Auth

```json
"auth": {
  "enabled":   true,
  "secret_key": "REPLACE_WITH_RANDOM_SECRET",
  "access_token_expire_hours": 8,
  "users": {
    "admin": {
      "password_hash": "<bcrypt hash>",
      "role": "admin"
    }
  }
}
```

Generate a secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Generate a password hash:
```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

### Roles

| Role | Permissions |
|:---|:---|
| `viewer` | Read stats, incidents, blocks, metrics |
| `analyst` | viewer + manual block / unblock |
| `auditor` | analyst + generate reports + view asset inventory |
| `admin` | Full access |

---

## Notifications

### Telegram

```json
"notifications": {
  "min_severity": "MEDIUM",
  "telegram": {
    "enabled":   true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id":   "YOUR_CHAT_ID"
  }
}
```

Get a bot token from `@BotFather`. Get your chat ID from `@userinfobot`.

### Discord / Slack

```json
"discord": { "enabled": true, "webhook_url": "https://discord.com/api/webhooks/..." },
"slack":   { "enabled": true, "webhook_url": "https://hooks.slack.com/services/..." }
```

### Email (SMTP)

```json
"email": {
  "enabled":        true,
  "smtp_host":      "smtp.gmail.com",
  "smtp_port":      587,
  "use_tls":        true,
  "use_ssl":        false,
  "username":       "alerts@example.com",
  "password":       "your-app-password",
  "from":           "CNSL Alerts <alerts@example.com>",
  "to":             ["soc@example.com", "admin@example.com"],
  "subject_prefix": "[CNSL]"
}
```

| Setting | Description |
|:---|:---|
| `smtp_host` | SMTP server hostname |
| `smtp_port` | 587 for STARTTLS (default), 465 for SSL, 25 for plain |
| `use_tls` | STARTTLS on port 587 -- recommended |
| `use_ssl` | Implicit SSL on port 465 |
| `username` / `password` | SMTP credentials (use app passwords for Gmail) |
| `from` | Sender address shown in the email |
| `to` | List of recipient addresses |
| `subject_prefix` | Prepended to every alert subject |

For Gmail: enable 2FA, then create an App Password at https://myaccount.google.com/apppasswords

### Generic Webhook

```json
"webhook": {
  "enabled":       true,
  "url":           "https://your-server.com/cnsl-hook",
  "secret_header": "X-CNSL-Secret",
  "secret_value":  "mysecret"
}
```

---

## File Integrity Monitoring

```json
"fim": {
  "enabled":          true,
  "db_path":          "/var/lib/cnsl/cnsl_fim.db",
  "watch_paths":      ["/etc/passwd", "/etc/ssh/", "/var/www/"],
  "scan_interval_sec": 60
}
```

Directories are scanned recursively. Any file created, modified, deleted,
or permission-changed fires an alert.

---

## ML Anomaly Detection

```json
"ml": {
  "enabled":                  true,
  "min_samples":              100,
  "retrain_interval_sec":     3600,
  "contamination":            0.05,
  "anomaly_score_threshold": -0.1
}
```

Uses IsolationForest (scikit-learn). Trains automatically on your own traffic
after `min_samples` events. No pre-trained model needed.

Check status: `GET /api/ml-status`

---

## Remote Syslog Ingestion

```json
"syslog_receiver": {
  "enabled":     true,
  "host":        "0.0.0.0",
  "udp_port":    5514,
  "tcp_port":    5514,
  "udp_enabled": true,
  "tcp_enabled": true
}
```

Use port 5514 (not 514) to avoid needing root. Configure remote devices:
```bash
# Linux rsyslog
echo "*.* @CNSL_IP:5514" >> /etc/rsyslog.conf
systemctl restart rsyslog

# Cisco IOS
logging host CNSL_IP transport udp port 5514
```

---

## Redis Distributed Blocklist

```json
"redis": {
  "enabled":     true,
  "host":        "127.0.0.1",
  "port":        6379,
  "password":    null,
  "db":          0,
  "key_prefix":  "cnsl",
  "sync_blocks": true
}
```

Blocks and unblocks are published to all CNSL nodes in the cluster automatically.

---

## Honeypot

```json
"honeypot": {
  "enabled":                true,
  "mode":                   "redirect",
  "honeypot_host":          "127.0.0.1",
  "honeypot_port":          2222,
  "fake_hostname":          "ubuntu-server",
  "fake_version":           "Ubuntu 22.04.3 LTS",
  "log_commands":           true,
  "auto_redirect_severity": "HIGH"
}
```

Modes: `redirect` (fake shell), `drop` (silent drop), `tarpit` (slow connection), `log_only`.

---

## Elasticsearch / OpenSearch

```json
"search": {
  "elasticsearch": {
    "enabled":  true,
    "url":      "http://localhost:9200",
    "index":    "cnsl-events",
    "username": "",
    "password": "",
    "timeout_sec": 5
  }
}
```

Push events: `POST /api/search/es-push`

---

## Prometheus + Grafana

Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: cnsl
    static_configs:
      - targets: ['localhost:8765']
    metrics_path: /api/metrics
    authorization:
      credentials: YOUR_JWT_TOKEN_HERE
```

Export Grafana template:
```bash
python -m cnsl --grafana-export
```

Import in Grafana: Dashboards -> Import -> Upload `cnsl_grafana_dashboard.json`

---

## Kill Chain Tracker

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
| `enabled` | `true` | Enable kill chain tracking |
| `max_chains` | `5000` | Max IP chains in memory (oldest evicted) |
| `stage_ttl_sec` | `86400` | Chains not updated for this long are pruned |
| `persist` | `true` | Save to SQLite on shutdown |

---

## Automated Pattern Learning

```json
{
  "pattern_learning": {
    "enabled":          true,
    "lookback_sec":     300,
    "min_occurrences":  5,
    "max_suggestions":  50,
    "persist":          true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable pattern discovery |
| `lookback_sec` | `300` | Event window to look back on each alert |
| `min_occurrences` | `5` | Times a pattern must repeat to generate a suggestion |
| `max_suggestions` | `50` | Max suggestions in memory (weakest evicted) |

---

## SIEM / SOAR Connectors

```json
{
  "siem": {
    "splunk": {
      "enabled":      false,
      "hec_url":      "https://splunk.example.com:8088",
      "token":        "your-hec-token",
      "index":        "cnsl",
      "sourcetype":   "cnsl:incident",
      "verify_ssl":   true,
      "timeout_sec":  5,
      "max_retries":  3,
      "min_severity": "MEDIUM"
    },
    "sentinel": {
      "enabled":      false,
      "workspace_id": "your-workspace-id",
      "shared_key":   "your-shared-key",
      "log_type":     "CNSLIncident",
      "min_severity": "MEDIUM"
    },
    "webhook": {
      "enabled":      false,
      "url":          "https://your-soar.example.com/api/ingest",
      "bearer_token": "",
      "verify_ssl":   true,
      "min_severity": "MEDIUM"
    }
  }
}
```

See `docs/siem-connectors.md` for full per-connector documentation.

---

## Multi-Node Federation

Federation reuses the `redis` config block for connection details.

```json
{
  "federation": {
    "enabled":           true,
    "min_severity":      "LOW",
    "dedupe_window_sec": 5,
    "max_remote_ips":    10000
  }
}
```

Requires `redis.enabled: true`. All nodes must share the same Redis instance and `key_prefix`.

---

## Cloud Identity Connectors

```json
{
  "cloud_identity": {
    "enabled":           true,
    "poll_interval_sec": 60,
    "aws": {
      "enabled":           false,
      "access_key_id":     "",
      "secret_access_key": "",
      "region":            "us-east-1",
      "lookback_sec":      300
    },
    "azure_ad": {
      "enabled":       false,
      "tenant_id":     "",
      "client_id":     "",
      "client_secret": "",
      "lookback_sec":  300
    }
  }
}
```

See `docs/cloud-identity.md` for required IAM permissions and setup steps.

---

## Zero-Trust Trust Score Engine

```json
{
  "zero_trust": {
    "enabled":            true,
    "initial_score":      0.8,
    "min_score":          0.05,
    "recovery_per_day":   0.05,
    "persist":            true,
    "max_entities":       50000,
    "apply_to_threshold": true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable zero-trust scoring |
| `initial_score` | `0.8` | Starting score for new entities |
| `min_score` | `0.05` | Floor -- score never drops below this |
| `recovery_per_day` | `0.05` | Trust improvement per day of quiet |
| `apply_to_threshold` | `true` | Whether to scale detection thresholds by trust score |

See `docs/zero-trust.md` for full documentation.

---

## Reporting

```json
{
  "reporting": {
    "enabled":    true,
    "output_dir": "/var/lib/cnsl/reports",
    "format":     "html"
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable report generation |
| `output_dir` | `./reports` | Directory where reports are saved |
| `format` | `html` | Default format: `html`, `pdf`, or `json` |

Trigger a report via `POST /api/report/generate` or the Reports tab.

---

## Kafka Log Ingestion

```json
{
  "kafka": {
    "enabled":          false,
    "bootstrap_servers": "localhost:9092",
    "topic":            "cnsl-logs",
    "group_id":         "cnsl",
    "auto_offset_reset": "latest"
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable Kafka consumer |
| `bootstrap_servers` | | Comma-separated list of broker addresses |
| `topic` | `cnsl-logs` | Kafka topic to consume |
| `group_id` | `cnsl` | Consumer group ID |
| `auto_offset_reset` | `latest` | `latest` or `earliest` |

Requires `kafka-python` installed: `pip install kafka-python`.

---

## Multi-Tenant

```json
{
  "tenants": {
    "enabled": false,
    "tenants": [
      {
        "id":   "tenant-a",
        "name": "Tenant A",
        "ip_ranges": ["10.0.0.0/8"],
        "overrides": {
          "thresholds": {"fails_threshold": 5}
        }
      }
    ]
  }
}
```

When tenants are enabled, each detected IP is matched against `ip_ranges`
and the matching tenant's `overrides` are applied on top of the base config.


---

## OT/IoT Log Sources

```json
{
  "ot": {
    "enabled": false,
    "log_sources": {
      "modbus": "/var/log/modbus-gateway.log",
      "dnp3":   "/var/log/dnp3-gateway.log",
      "scada":  "/var/log/scada-hmi.log"
    },
    "trusted_ips":        [],
    "alert_on_any_write": true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable OT log ingestion |
| `log_sources.modbus` | `""` | Path to Modbus gateway log |
| `log_sources.dnp3` | `""` | Path to DNP3 gateway log |
| `log_sources.scada` | `""` | Path to SCADA/HMI syslog |
| `trusted_ips` | `[]` | IPs allowed to read from PLCs without triggering scan alert |
| `alert_on_any_write` | `true` | Fire HIGH alert on any Modbus write FC, even from trusted IPs |

See `docs/ot-iot.md` for full documentation including log format compatibility.