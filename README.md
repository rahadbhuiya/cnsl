<div align="center">


# CNSL — Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/rahadbhuiya/cnsl"><img src="https://codecov.io/gh/rahadbhuiya/cnsl/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://pypi.org/project/cnsl"><img src="https://img.shields.io/pypi/v/cnsl" alt="PyPI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
</p>

**A self-hosted SIEM for Linux — correlation, ML, honeypot, and search.**

Correlates SSH, web, database, and firewall signals to detect attacks  
that no single log source can see alone — then blocks them automatically.

[Quick Start](#quick-start) · [Features](#features) · [Dashboard](#dashboard) · [API](#rest-api) · [Docs](docs/) · [Changelog](#changelog)

</div>

---

## Why CNSL?

Most security tools watch **one log** and count failures. That is not enough.

A real attacker does not just hammer SSH — they scan your web server, probe your database, then log in with stolen credentials. **CNSL sees the full picture.**

```
Web scan      from 45.33.32.1  --+
SSH brute     from 45.33.32.1  --+--->  HIGH alert + auto-block
DB auth fail  from 45.33.32.1  --+
```

---

## CNSL vs Fail2ban vs SSHGuard

Fail2ban and SSHGuard are proven, widely-deployed tools. If single-service blocking is all you need, either one will serve you well. CNSL solves a different problem: **multi-source correlation** — detecting attackers that move across SSH, web, and database simultaneously.

| Feature | Fail2ban | SSHGuard | CNSL |
|:---|:---:|:---:|:---:|
| Multi-source log correlation | No | No | Yes |
| Credential breach detection | No | No | Yes |
| ML anomaly detection | No | No | Yes |
| Honeypot (fake SSH shell) | No | No | Yes |
| Live web dashboard | No | No | Yes |
| GeoIP + threat intelligence | No | No | Yes |
| File integrity monitoring | No | No | Yes |
| Telegram / Discord / Slack / Email | No | No | Yes |
| Redis distributed blocklist | No | No | Yes |
| Prometheus + Grafana | No | No | Yes |
| SOC2 / PCI-DSS compliance reports | No | No | Yes |
| Privilege escalation detection | No | No | Yes |
| PDF export from dashboard | No | No | Yes |
| Remote syslog ingestion (UDP/TCP) | No | No | Yes |
| ECS / CEF event normalization | No | No | Yes |
| Full-text search + KQL queries | No | No | Yes |
| Elasticsearch / OpenSearch export | No | No | Yes |
| Auto-unblock timer | Yes | Yes | Yes |
| Language | Python | C | Python |

---

## What CNSL Detects

| Threat | How |
|:---|:---|
| SSH brute-force | Threshold-based failure counting per IP |
| Credential breach | SSH success after repeated failures (stolen password) |
| Credential stuffing | Many different usernames tried from one IP |
| Web scanner | Nikto, sqlmap, gobuster User-Agent and path detection |
| Web exploit attempts | `/.env`, `/wp-admin`, `/phpmyadmin`, path traversal |
| Database brute-force | MySQL auth failure spikes |
| Honeypot port probe | Any connection to port 23 / 3389 / 6379 — instant block |
| Privilege escalation | sudo/su failure after successful SSH login |
| File tampering | `/etc/passwd`, `authorized_keys`, `sshd_config`, any watched directory |
| Behavioral anomaly | Unusual login hour, new username, frequency spike (ML) |
| Coordinated attack | Same IP across SSH + web + DB simultaneously |
| Remote device events | Syslog from routers, switches, firewalls (RFC 3164 / RFC 5424) |

---

## Features

| Category | Capability |
|:---|:---|
| Detection | SSH brute-force, credential stuffing, credential breach |
| Detection | Web scanner + exploit paths (false positive resistant) |
| Detection | Database brute-force (MySQL), firewall honeypot ports |
| Detection | Privilege escalation (sudo/su after login) |
| Correlation | 6 cross-source rules — web+SSH, multi-service, kill chain |
| Response | iptables / ipset auto-block with configurable auto-unblock timer |
| Response | Country-based blocking — block entire countries before thresholds fire |
| Response | Honeypot redirect — attacker lands on a fake Ubuntu shell (40+ commands) |
| Response | Redis distributed blocklist — sync blocks across a server cluster |
| Intelligence | GeoIP enrichment (MaxMind offline or ip-api.com fallback) |
| Intelligence | AbuseIPDB threat score lookup |
| Intelligence | Behavioral baseline + ML anomaly detection (IsolationForest) |
| Ingestion | Remote syslog receiver — UDP/TCP 514 or 5514 (RFC 3164 / RFC 5424) |
| Normalization | ECS-compatible event schema, CEF export for ArcSight/Splunk |
| Search | KQL-like full-text search, time-range filters, aggregations |
| Export | Elasticsearch/OpenSearch bulk push, NDJSON and CEF file export |
| Monitoring | File Integrity Monitoring — watches files and directories recursively |
| Monitoring | Passive asset inventory via network events |
| Visibility | Live web dashboard with tabbed UI and real-time SSE feed |
| Visibility | Prometheus metrics + Grafana dashboard template |
| Reporting | PDF export from dashboard (no extra tools needed) |
| Reporting | PDF / HTML compliance reports (SOC2, ISO27001, PCI-DSS) |
| Access | JWT authentication + Role-Based Access Control (4 roles) |
| Notifications | Telegram, Discord, Slack, custom webhook (plain text, no emoji) |
| Persistence | SQLite incident history, FIM baseline, block records |
| Ops | Dry-run safe by default, systemd ready, Docker ready |

---

## Quick Start

```bash
# Option A — pip install (recommended)
pip install cnsl[full]
sudo python -m cnsl --no-tcpdump

# Update (Option A)
pip install --upgrade cnsl

# Option B — from source
# 1. Clone
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl

# 2. Install (use a virtualenv)
python3 -m venv venv
source venv/bin/activate
pip install -e ".[full]"

# Update (Option B)
git pull origin main
pip install -e ".[full]"

# 3. Run in safe dry-run mode (no real blocks)
sudo venv/bin/python -m cnsl --no-tcpdump

# 4. Run with live dashboard
sudo venv/bin/python -m cnsl --dashboard --no-tcpdump
# Open http://127.0.0.1:8765
# Default login: admin / cnsl-change-me

# 5. Enable real blocking when ready
sudo venv/bin/python -m cnsl --execute --dashboard
```

> Always use the virtualenv Python (`venv/bin/python`) with `sudo`.
> Running `sudo python` uses the system Python which may not have all packages (e.g. scikit-learn).

---

## Installation

```bash
pip install -e .            # core only
pip install -e ".[full]"    # everything recommended
pip install -e ".[dev]"     # + testing tools
```

| Extra | Packages | Required for |
|:---|:---|:---|
| `full` | aiohttp, aiosqlite, pyyaml, bcrypt, PyJWT, pyotp, scikit-learn, numpy, reportlab | Dashboard, DB, auth, 2FA, ML, PDF reports |
| `auth` | bcrypt, PyJWT | Dashboard login |
| `2fa` | pyotp | Two-factor authentication |
| `db` | aiosqlite | SQLite persistence |
| `geoip` | geoip2 | MaxMind offline GeoIP |
| `ml` | scikit-learn, numpy | ML anomaly detection |
| `reports` | reportlab | PDF compliance reports |
| `redis` | redis | Distributed blocklist |
| `kafka` | aiokafka | Kafka log ingestion |
| `dev` | pytest + all above | Running tests |

---

## Usage

```
sudo venv/bin/python -m cnsl [options]

Core:
  --config FILE        Config file (.json or .yaml)
  --authlog PATH       Auth log path  (default: /var/log/auth.log)
  --iface IFACE        Network interface for tcpdump  (default: any)
  --execute            Enable real blocking  (default: dry-run)
  --backend BACKEND    Blocking backend: iptables or ipset  (default: iptables)

Features:
  --dashboard          Enable web dashboard on http://127.0.0.1:8765
  --no-tcpdump         Auth.log only, lower CPU
  --no-geoip           Disable GeoIP enrichment
  --no-db              Disable SQLite persistence

Ops:
  --init               Interactive setup wizard — create /etc/cnsl/config.json
  --status             Show event count, blocked IPs, and config summary, then exit
  --check-update       Check if a newer version is available on PyPI

Reports:
  --report FORMAT      Generate report and exit  (html | pdf | json)
  --report-days N      Report period in days  (default: 30)
  --grafana-export     Export Grafana dashboard JSON and exit
```

### Auth log paths by OS

| OS | Default path |
|:---|:---|
| Ubuntu / Debian | `/var/log/auth.log` |
| CentOS / RHEL / Fedora | `/var/log/secure` |
| OpenSUSE | `/var/log/messages` |

---

## Documentation

Detailed guides live in [`docs/`](docs/):

| Guide | Contents |
|:---|:---|
| [Installation](docs/installation.md) | Install, Docker, systemd service, OS-specific paths |
| [Configuration](docs/configuration.md) | Full config reference for every setting |
| [API](docs/api.md) | REST endpoint list, auth, examples |
| [Notifications](docs/notifications.md) | Telegram, Discord, Slack, Email, webhook setup |
| [Country Blocking](docs/country-blocking.md) | Country-based blocking, ISO codes, allowlist |
| [2FA](docs/2fa.md) | Two-factor authentication setup, backup codes, API |
| [Cases](docs/cases.md) | Case management — tickets, assignment, notes, API |
| [Rules](docs/rules.md) | Alert rule engine — built-in rules, tuning, API |
| [Threat Feed](docs/threat-feed.md) | Community threat feed — setup, feeds, API |
| [Zeek](docs/zeek.md) | Zeek log ingestion — conn, ssh, http, dns, notice, weird |
| [UEBA](docs/ueba.md) | User behavior analytics — profiles, lateral movement, anomalies |
| [Agent](docs/agent.md) | Remote log forwarding agent — setup, systemd, WebSocket |
| [Kafka](docs/kafka.md) | Kafka log ingestion — topics, parsers, high-volume tips |
| [Tenants](docs/tenants.md) | Multi-tenant support — isolation model, config, API |
| [Rate Limiting](docs/rate-limiting.md) | Rate limiting + DDoS protection — config, middleware, API |
| [HuddleCluster](docs/huddle.md) | Self-organizing load balancing across CNSL nodes |
| [Architecture](docs/architecture.md) | Module map, event flow, concurrency model |

---

## How to Run (Step by Step)

### Step 1 — Minimal run (dry-run, no config needed)

```bash
sudo venv/bin/python -m cnsl --no-tcpdump
```

### Step 2 — With dashboard

```bash
sudo venv/bin/python -m cnsl --dashboard --no-tcpdump
```

Open `http://127.0.0.1:8765` — Login: `admin` / `cnsl-change-me`

---

### Step 3 — Create a config file

```bash
sudo mkdir -p /etc/cnsl
sudo cp config/config.example.json /etc/cnsl/config.json
sudo nano /etc/cnsl/config.json
```

Minimum required changes:

```json
{
  "authlog_path": "/var/log/auth.log",

  "allowlist": [
    "127.0.0.1",
    "YOUR_OWN_IP_HERE"
  ],

  "country_block": {
    "enabled":   false,
    "countries": [],
    "allowlist": []
  },

  "actions": {
    "dry_run": false,
    "block_duration_sec": 900
  },

  "store": {
    "db_path": "/var/lib/cnsl/cnsl_state.db"
  },

  "fim": {
    "db_path": "/var/lib/cnsl/cnsl_fim.db"
  }
}
```

> **Important:** Always add your own IP to `allowlist` before setting `dry_run: false`.  
> Use absolute paths for `db_path` — relative paths cause baselines to reset on restart.

---

### Step 4 — Enable live blocking

```bash
sudo venv/bin/python -m cnsl \
  --config /etc/cnsl/config.json \
  --execute \
  --dashboard
```

---

### Step 5 — Add more log sources (optional)

```json
"log_sources": {
  "nginx":  "/var/log/nginx/access.log",
  "apache": "/var/log/apache2/access.log",
  "mysql":  "/var/log/mysql/error.log",
  "ufw":    "/var/log/ufw.log",
  "syslog": "/var/log/syslog"
}
```

---

### Step 6 — Enable File Integrity Monitoring (optional)

```json
"fim": {
  "enabled": true,
  "db_path": "/var/lib/cnsl/cnsl_fim.db",
  "watch_paths": [
    "/etc/passwd",
    "/etc/ssh/",
    "/var/www/"
  ],
  "scan_interval_sec": 60
}
```

FIM watches both individual files and entire directories recursively. Any file created, modified, deleted, or permission-changed fires an alert.

Test FIM:
```bash
sudo touch /etc/ssh/test_cnsl.txt
# wait 60 seconds
grep "fim_alert" /var/log/cnsl.jsonl | tail -3
sudo rm /etc/ssh/test_cnsl.txt
```

---

### Step 7 — Enable ML anomaly detection (optional)

```json
"ml": {
  "enabled": true,
  "min_samples": 100,
  "retrain_interval_sec": 3600,
  "contamination": 0.05,
  "anomaly_score_threshold": -0.1
}
```

ML uses IsolationForest from scikit-learn — no pre-trained model needed. CNSL trains on your own traffic automatically after collecting `min_samples` events.

Check training status: `http://127.0.0.1:8765/api/ml-status`

---

### Step 8 — Enable remote syslog ingestion (optional)

Receive logs from routers, switches, firewalls, and other Linux servers:

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

> Use port 5514 (not 514) to avoid needing root. Configure remote devices to send to `CNSL_IP:5514`.

Configure remote devices:
```bash
# Linux rsyslog
echo "*.* @CNSL_IP:5514" >> /etc/rsyslog.conf
systemctl restart rsyslog

# Cisco IOS
logging host CNSL_IP transport udp port 5514
```

Test:
```bash
echo "<38>Jan  1 00:00:00 router sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2" \
  | nc -u 127.0.0.1 5514
```

---

### Step 9 — Enable Telegram alerts (optional)

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

Get a bot token from `@BotFather` on Telegram. Get your chat ID from `@userinfobot`.

---

### Step 10 — Run as a systemd service

```bash
sudo nano /etc/systemd/system/cnsl.service
```

```ini
[Unit]
Description=CNSL — Correlated Network Security Layer
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=root
ExecStart=/opt/cnsl/venv/bin/python -m cnsl \
  --config /etc/cnsl/config.json \
  --execute \
  --dashboard
WorkingDirectory=/opt/cnsl
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cnsl/service.log
StandardError=append:/var/log/cnsl/service.log

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cnsl
sudo journalctl -u cnsl -f
```

---

## Test Without a Real Server

```bash
# Run all scenarios
python simulate.py

# Run a specific scenario
python simulate.py brute        # SSH brute-force
python simulate.py breach       # credential breach (HIGH severity)
python simulate.py stuffing     # credential stuffing
python simulate.py web          # web scanner + exploit attempt
python simulate.py db           # database brute-force
python simulate.py priv         # privilege escalation (SSH to sudo)
python simulate.py honeypot     # honeypot port probe
python simulate.py correlation  # multi-source coordinated attack
python simulate.py unblock      # auto-unblock + Prometheus verify
python simulate.py allowlist    # allowlist protection test
python simulate.py metrics      # metrics and DB stats
python simulate.py notify       # notification pipeline test

# Interactive mode
python simulate.py live
```

---

## Dashboard

Enable with `--dashboard`. Access at `http://127.0.0.1:8765`

| Tab | What it shows |
|:---|:---|
| Overview | Stat cards, timeline chart (last 24h), severity doughnut, top attackers |
| Incidents | Full incident table with time, IP, location, severity, fail count, reasons |
| Blocks | Active blocks with unblock button, manual block form |
| Honeypot | Status, active redirects, session table (IP, duration, auth attempts, commands typed) |
| FIM | Watched paths list, file integrity alerts |
| ML | Enabled/trained status, training progress bar, samples collected, last trained time |
| Live Feed | Every event streamed in real time via SSE |

Export PDF button in the header generates a full security report from live data — uses browser print, no extra tools needed.

> Dashboard binds to `127.0.0.1` only. For remote access use an SSH tunnel:
> ```bash
> ssh -L 8765:127.0.0.1:8765 user@yourserver
> ```

---

## Dashboard Authentication

```json
"auth": {
  "enabled": true,
  "secret_key": "REPLACE_WITH_RANDOM_SECRET",
  "session_timeout_minutes": 60
}
```

Generate a secure key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

**Change the default credentials before deploying.** Default is `admin` / `cnsl-change-me`.

### Roles

| Role | Permissions |
|:---|:---|
| `viewer` | Read stats, incidents, blocks, metrics |
| `analyst` | viewer + manual block / unblock |
| `auditor` | analyst + generate reports + view asset inventory |
| `admin` | Full access |

---

## Honeypot Mode

Instead of blocking attackers, redirect them to a fake SSH server:

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

The built-in fake shell simulates a real Ubuntu system:

| What the attacker can do | What actually happens |
|:---|:---|
| `ls`, `cd`, `pwd`, `cat` | Full fake filesystem — `/etc`, `/root`, `/var`, `/proc`, `/home` |
| `touch`, `mkdir`, `rm`, `cp`, `mv` | Works in a session-local virtual filesystem |
| `echo "x" > file` | Writes to virtual filesystem (`>>` append also works) |
| `cat /etc/passwd`, `/etc/shadow`, `/etc/sudoers` | Returns realistic fake content |
| `ps`, `top`, `df`, `free`, `netstat` | Returns realistic fake system info |
| `wget`, `curl` | Simulates DNS timeout after a delay |
| `python3`, `perl` | Interactive prompt or silent run |
| `sudo`, `passwd` | Password prompts — logs what the attacker types |
| `systemctl status` | Returns fake service status |

> Use `honeypot_port` (not `ports`). Make sure port 2222 is free before starting.

---

## Event Normalization

Every CNSL event is automatically normalized to an ECS-compatible schema:

```json
{
  "@timestamp": "2026-05-04T07:33:34Z",
  "event": {
    "kind": "event",
    "category": ["authentication", "network"],
    "outcome": "failure",
    "severity": 40
  },
  "source": { "ip": "1.2.3.4" },
  "cnsl": {
    "kind": "SSH_FAIL",
    "threat_score": 3,
    "reasons": ["brute_force: 5 fails in 60s"]
  }
}
```

Export formats:
```bash
# Elasticsearch bulk NDJSON
curl http://127.0.0.1:8765/api/export/ecs -H "Authorization: Bearer $TOKEN" -o events.ndjson

# CEF (ArcSight / Splunk)
curl http://127.0.0.1:8765/api/export/cef -H "Authorization: Bearer $TOKEN"
```

Push to Elasticsearch:
```bash
curl -X POST http://localhost:9200/_bulk \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @events.ndjson
```

---

## Search and Query

Full-text search over incidents using a KQL-like syntax:

```bash
# Search by severity
GET /api/search?q=severity:HIGH

# Search by IP
GET /api/search?q=1.2.3.4

# Search by country
GET /api/search?q=country:China

# Search by reason
GET /api/search?q=reasons:brute_force

# Time range
GET /api/search?q=severity:HIGH&since=1700000000&until=1800000000

# Aggregations — top IPs, countries, hourly buckets
GET /api/aggregate
```

---

## Notifications

```json
"notifications": {
  "min_severity": "MEDIUM",
  "dedup_window_sec": 300,
  "daily_digest": {
    "enabled": true,
    "hour": 8
  },
  "telegram": { "enabled": true, "bot_token": "...", "chat_id": "..." },
  "discord":  { "enabled": true, "webhook_url": "..." },
  "slack":    { "enabled": true, "webhook_url": "..." },
  "email": {
    "enabled":   true,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "use_tls":   true,
    "username":  "alerts@example.com",
    "password":  "your-app-password",
    "from":      "CNSL Alerts <alerts@example.com>",
    "to":        ["admin@example.com"]
  }
}
```

- `dedup_window_sec` — suppress duplicate alerts from the same IP+event type within this window (default: 300s)
- `daily_digest` — send a summary of all alerts at the configured hour via Telegram/Slack

Messages use clean plain text — no emoji. ISP names and detection reasons with special characters are automatically escaped so Telegram formatting never breaks.

---

## Reports

From the dashboard — click Export PDF in the header to generate a full security report from live data.

From the CLI:

```bash
python -m cnsl --report html --report-days 30
python -m cnsl --report pdf
python -m cnsl --report json
python -m cnsl --grafana-export
```

Reports include: executive summary, top attackers, recent incidents, FIM alerts, honeypot sessions, ML status, and SOC2 / ISO27001 / PCI-DSS compliance mapping.

---

## Grafana

```bash
python -m cnsl --grafana-export
```

Import in Grafana: `Dashboards > Import > Upload cnsl_grafana_dashboard.json`

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

---

## REST API

All endpoints available when `--dashboard` is active.

```
GET  /api/stats                  Engine summary
GET  /api/incidents              Recent incidents (?limit=50, max 500)
GET  /api/events                 Raw recent events
GET  /api/blocks                 Currently active blocks
GET  /api/top-attackers          Top attacker IPs with geo info
GET  /api/timeline               Incident counts per hour (last 24h)
GET  /api/search                 Full-text search (?q=severity:HIGH&limit=50)
GET  /api/aggregate              Aggregations: by_severity, top_ips, top_countries, hourly
GET  /api/events/normalized      ECS-normalized incident documents
GET  /api/export/ecs             Elasticsearch bulk NDJSON download
GET  /api/export/cef             CEF text download (ArcSight/Splunk)
GET  /api/ml-status              ML detector status and training progress
GET  /api/honeypot               Honeypot status and recent sessions
GET  /api/fim                    FIM alerts and watched paths
GET  /api/system                 Uptime, SSH fails, events processed, blocks total
GET  /api/assets                 Passive network asset inventory
GET  /api/metrics                Prometheus metrics (auth required)
GET  /api/debug                  Module wiring status
GET  /api/search/es-status       Elasticsearch cluster health

POST /api/login                  {"username": "...", "password": "..."}
POST /api/logout
POST /api/block                  {"ip": "1.2.3.4"}  analyst+ only
POST /api/unblock                {"ip": "1.2.3.4"}  analyst+ only
POST /api/report                 {"format": "html", "days": 30}
POST /api/search/es-push         Push incidents to Elasticsearch
POST /api/notify/test            Test all enabled notification channels  admin only
POST /api/auth/rotate-secret     Rotate JWT secret, invalidate all sessions  admin only
```

---

## JSON Log Format

Every event is a newline-delimited JSON record in `cnsl.jsonl`:

```json
{
  "ts": 1713260000.0,
  "time": "2024-04-16T10:00:00Z",
  "type": "incident",
  "payload": {
    "src_ip": "1.2.3.4",
    "severity": "HIGH",
    "reasons": ["credential_breach: success after 6 fails (threshold=5)"],
    "fail_count": 6,
    "geo": { "country": "China", "city": "Beijing" }
  }
}
```

```bash
# Stream all events live
tail -f /var/log/cnsl.jsonl | jq .

# HIGH severity incidents only
tail -f /var/log/cnsl.jsonl | jq 'select(.type=="incident" and .payload.severity=="HIGH")'

# ML training events
grep "ml_retrained\|ml_error" /var/log/cnsl.jsonl | tail -5

# FIM alerts
grep "fim_alert" /var/log/cnsl.jsonl | tail -10
```

Compatible with: Grafana Loki, Elasticsearch, Splunk, Vector, Fluentd, Datadog

---

## Docker

```bash
docker build -t cnsl .

docker run --rm \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --network host \
  -v /var/log:/var/log:ro \
  -v /etc/cnsl:/etc/cnsl:ro \
  cnsl --config /etc/cnsl/config.json --execute --dashboard
```

---

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v --timeout=60
# 250 passed
```

---

## Project Structure

```
cnsl/
├── cnsl/
│   ├── __init__.py              package version (2.1.0)
│   ├── __main__.py              python -m cnsl entrypoint
│   │
│   ├── models.py                Event, Detection dataclasses
│   ├── config.py                config loading and all defaults
│   ├── validator.py             startup config validation
│   ├── logger.py                async JSON logger (text prefixes, no emoji)
│   │
│   ├── parsers.py               auth.log + tcpdump parsers (sshd + sshd-session)
│   ├── log_sources.py           nginx, apache, mysql, ufw, syslog parsers
│   ├── sources.py               async log file tailers
│   ├── syslog_receiver.py       UDP/TCP syslog server (RFC 3164/5424)
│   ├── zeek_parser.py           Zeek TSV/JSON log parser (6 log types)
│   ├── kafka_consumer.py        async Kafka consumer (aiokafka + confluent fallback)
│   │
│   ├── normalizer.py            ECS/CEF event normalization
│   ├── search_engine.py         KQL search, aggregations, Elasticsearch push
│   │
│   ├── detector.py              stateful per-IP detection engine + country blocking
│   ├── correlator.py            cross-source correlation rules (6 rules)
│   ├── rules.py                 alert rule engine (9 built-in rules, runtime tuning)
│   ├── ml_detector.py           ML anomaly detection (IsolationForest, auto-trains)
│   ├── threat_intel.py          AbuseIPDB + behavioral baseline
│   ├── threat_feed.py           community threat feeds (6 feeds, CIDR matching)
│   ├── ueba.py                  user/entity behavior analytics (5 anomaly types)
│   │
│   ├── blocker.py               iptables / ipset blocking backend
│   ├── honeypot.py              fake SSH server (40+ commands, virtual filesystem)
│   ├── redis_sync.py            distributed blocklist via Redis pub/sub
│   │
│   ├── geoip.py                 GeoIP (MaxMind offline + ip-api.com)
│   ├── assets.py                passive asset inventory
│   ├── fim.py                   file integrity monitoring (files + directories)
│   │
│   ├── auth.py                  JWT authentication + 2FA (TOTP)
│   ├── rbac.py                  role-based access control (4 roles)
│   ├── dashboard.py             web dashboard + REST API + SSE/WebSocket feed
│   ├── metrics.py               Prometheus metrics
│   ├── grafana.py               Grafana dashboard template generator
│   ├── reporter.py              PDF / HTML compliance reports
│   ├── notify.py                Telegram, Discord, Slack, Email, webhook
│   ├── store.py                 SQLite persistence (aiosqlite)
│   │
│   ├── cases.py                 case management (tickets, notes, RBAC)
│   ├── tenants.py               multi-tenant registry with per-tenant isolation
│   ├── rate_limiter.py          sliding window rate limiting + DDoS detection
│   ├── agent.py                 remote log forwarding agent (WebSocket, reconnect)
│   ├── huddle_integration.py    self-organizing load balancing across nodes
│   │
│   └── engine.py                main async loop + CLI argument parser
│
├── tests/
│   └── test_cnsl.py             250 unit tests
│
├── config/
│   ├── config.example.json      annotated example config
│   └── filebeat.yml             Filebeat config for Elasticsearch ingestion
│
├── docs/
│   ├── installation.md          install, Docker, systemd
│   ├── configuration.md         full config reference
│   ├── api.md                   REST API endpoints + examples
│   ├── notifications.md         Telegram, Discord, Slack, Email, webhook
│   ├── country-blocking.md      country-based blocking guide
│   ├── 2fa.md                   two-factor authentication setup
│   ├── cases.md                 case management guide
│   ├── rules.md                 alert rule engine guide
│   ├── threat-feed.md           community threat feed guide
│   ├── zeek.md                  Zeek log ingestion guide
│   ├── ueba.md                  UEBA guide
│   ├── agent.md                 remote agent setup guide
│   ├── kafka.md                 Kafka ingestion guide
│   ├── tenants.md               multi-tenant support guide
│   ├── rate-limiting.md         rate limiting + DDoS protection
│   ├── huddle.md                HuddleCluster load balancing
│   └── architecture.md          module map, event flow, concurrency model
│
├── .github/
│   └── workflows/ci.yml
├── simulate.py                  local test simulator (12 scenarios)
├── Dockerfile
├── docker-compose.yml
├── setup.py
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Roadmap

- [x] Alert deduplication + daily digest — added in v2.1.0
- [x] Session timeout + secret rotation — added in v2.1.0
- [x] `cnsl --init` setup wizard — added in v2.1.0
- [x] `cnsl --status` + `--check-update` — added in v2.1.0
- [x] Alert Rule Engine — added in v1.5.0 (9 built-in rules, runtime enable/disable/tune, API)
- [x] Case Management — added in v1.4.0 (tickets, assignment, notes, RBAC)
- [x] Full UEBA — added in v1.8.0 (per-user profiles, lateral movement, 5 anomaly types)
- [x] Country-based blocking — added in v1.2.0 (`country_block.countries: ["CN", "RU"]`)
- [x] Email notifications (SMTP) — added in v1.2.0
- [x] 2FA for dashboard login — added in v1.3.0 (TOTP, backup codes, partial token flow)
- [x] Community threat feed — added in v1.6.0 (6 feeds, auto-block, local file, API)
- [x] Kafka support — added in v2.0.0 (aiokafka + confluent-kafka, all parsers)
- [x] Zeek log ingestion — added in v1.7.0 (conn, ssh, http, dns, notice, weird; TSV+JSON)
- [x] Multi-tenant support — added in v2.0.0 (tenant isolation, per-tenant rules)
- [x] Agent system — added in v1.9.0 (WebSocket forwarding, reconnect, systemd)
- [x] WebSocket — added in v1.9.0 (/ws bidirectional, /ws/agent ingestion, SSE kept)
- [x] HuddleCluster integration — added in v2.0.0 (self-organizing load balancing, gossip, temperature scoring)

---

## Safety

> `--execute` flag modifies live firewall rules.

Before enabling real blocking:

1. Add your management IP to `allowlist` in config
2. Test in dry-run mode first (this is the default)
3. Ensure you have console or out-of-band access to the server
4. The authors are not responsible for accidental self-lockouts

---

## Contributing

1. Fork and create a feature branch
2. Add or update tests in `tests/test_cnsl.py`
3. Run `pytest tests/ -v --timeout=60` — all 250 must pass
4. Submit a pull request

Code style: type hints on all public functions, docstrings on all public methods, no external dependencies in `cnsl/` core modules.

---

## Changelog

### v2.1.0 — Security, Monitoring, Ops improvements

**`cnsl/auth.py`** — Security
- `session_timeout_minutes` config — sessions expire after inactivity (0 = disabled)
- `rotate_secret()` — invalidates all active tokens and generates a new JWT signing secret

**`cnsl/notify.py`** — Monitoring
- Alert deduplication — `dedup_window_sec` suppresses repeat alerts from the same IP+event type (default: 300s)
- Daily digest — sends a summary of all alerts at a configured hour via Telegram/Slack (`daily_digest.enabled`, `daily_digest.hour`)
- `test_channels()` — sends a test message to all enabled channels and returns per-channel results

**`cnsl/engine.py`** — Usability + Ops
- `--init` — interactive setup wizard, creates `/etc/cnsl/config.json` with guided prompts (Telegram + email/SMTP)
- `--status` — shows event count, blocked IP count, and dry-run state from the database, then exits
- `--check-update` — checks PyPI for a newer version and prints upgrade instructions if available

**`cnsl/dashboard.py`** — API
- `POST /api/notify/test` — sends a test message to all enabled notification channels, returns per-channel results (`admin` only)
- `POST /api/auth/rotate-secret` — rotates JWT signing secret and invalidates all active sessions (`admin` only)

**`cnsl/validator.py`** — Usability
- Root permission check — clear error message when `dry_run=false` but CNSL is not run as root
- Validation for `dedup_window_sec`, `daily_digest.hour`, `session_timeout_minutes`

---

### v2.0.0 — Kafka, Multi-tenant, Rate Limiting, Enhanced Reports, HuddleCluster

**New module: `cnsl/kafka_consumer.py`**
- `KafkaConsumer` — async Kafka consumer using aiokafka (with confluent-kafka fallback)
- Per-topic parser assignment: auth, nginx, apache, mysql, ufw, syslog, json, zeek_*
- Exponential backoff reconnect, periodic offset commit
- `GET /api/kafka` — stats endpoint

**New module: `cnsl/tenants.py`**
- `TenantManager` — multi-tenant registry with per-tenant isolation
- `Tenant` — display name, users, notifications, allowlist, country_block, rule overrides
- Per-tenant `RuleEngine` with lazy init and cache invalidation
- Single-tenant mode: transparent wrapper, zero breaking changes
- `GET /api/tenants`, `POST /api/tenants`, `DELETE /api/tenants/{id}`

**New module: `cnsl/rate_limiter.py`**
- `RateLimiter` — sliding window per-IP rate limiting + DDoS detection
- Per-endpoint config (stricter limits for `/api/login`)
- Auto-block via Blocker on DDoS threshold
- aiohttp middleware: `make_rate_limit_middleware()`
- `GET /api/rate-limit`, `GET /api/rate-limit/top`, `POST /api/rate-limit/reset/{ip}`

**`cnsl/reporter.py`** — Enhanced compliance reports
- Now includes: UEBA anomaly summary, case stats, rule engine state, rate limit stats
- `Reporter.__init__()` accepts `ueba`, `case_manager`, `rule_engine`, `rate_limiter`

**Tests** — 30 new tests: `TestRateLimiter` (10), `TestTenantManager` (12),
`TestKafkaConsumer` (6), `TestReporterEnhanced` (2)
— total **250 passing** (was 240)

**Version** — bumped to `2.0.0`

---

### v1.9.0 — Agent System + WebSocket

**New module: `cnsl/agent.py`**
- `AgentQueue` — bounded event queue with drop-oldest overflow and dropped-count tracking
- `tail_file()` — async log file tailer with rotation detection
- `ws_sender()` — WebSocket sender with exponential backoff reconnect
- `run_agent()` — wires tailers + sender, prints queue/dropped stats every 60s
- `load_agent_config()` — loads from `~/.cnsl-agent.json`, `/etc/cnsl/agent.json`, or `--config`
- `main()` — CLI entrypoint: `python -m cnsl.agent --server wss://... --token ... --hostname web-01`
- Supports: auth, nginx, apache, mysql, ufw, syslog log sources

**`cnsl/dashboard.py`** — 2 new WebSocket endpoints
- `GET /ws` — bidirectional WebSocket for dashboard browser
  - Auth: first message `{"type":"auth","token":"..."}`
  - Server→client: live detection events, pings
  - Client→server: `{"type":"block","ip":"..."}`, `{"type":"unblock","ip":"..."}`, ping/pong
  - RBAC enforced server-side; SSE (`/stream`) kept for backward compat
- `GET /ws/agent` — agent ingestion endpoint
  - Auth: `Authorization: Bearer TOKEN` header
  - Agent→server: `{"type":"agent_events","host":"...","events":[...]}`
  - Events processed through full detection pipeline (threat feed, UEBA, rules)

**Tests** — 14 new tests — total **210 passing** (was 196)

**Version** — bumped to `1.9.0`

---

### v1.8.0 — Full UEBA (User and Entity Behavior Analytics)

**New module: `cnsl/ueba.py`**
- `UEBAEngine` — per-user behavioral profile engine with SQLite persistence
- `UserProfile` — tracks login hours, known IPs, daily counts, recent IPs, anomaly log
- `UEBAAnomaly` — typed anomaly result with reason string and anomaly_types list
- 5 detection capabilities:
  - **Unusual login hour** — login outside normal hours for this user
  - **New source IP** — login from an IP this user has never used
  - **Lateral movement** — same user active on N+ IPs in a short window
  - **Login after absence** — login after >N days of inactivity
  - **Frequency spike** — today's logins >> 7-day rolling average
- `min_observations` learning period — no false positives during warmup
- Async SQLite persistence (`ueba_profiles`, `ueba_anomalies` tables)

**Tests** — 19 new tests — total **196 passing** (was 177)

**Version** — bumped to `1.8.0`

---

### v1.7.0 — Zeek Log Ingestion

**New module: `cnsl/zeek_parser.py`**
- `ZeekLogParser` — stateful line-by-line parser for Zeek TSV and JSON output
- `_TSVState` — tracks `#fields` header per file, handles log rotation correctly
- Parsers for 6 log types: `conn`, `ssh`, `http`, `dns`, `notice`, `weird`
- `_shannon_entropy()` — DNS tunneling detection via high-entropy subdomain names
- Both TSV (default Zeek) and JSON (`@load policy/tuning/json-logs`) formats supported

**Tests** — 32 new tests — total **177 passing** (was 145)

**Version** — bumped to `1.7.0`

---

### v1.6.0 — Community Threat Feed

**New module: `cnsl/threat_feed.py`**
- `ThreatFeed` — downloads and caches known-bad IPs from 6 public feeds
- Built-in feeds: Emerging Threats, Feodo Tracker, CINS Army, abuse.ch SSLBL,
  Spamhaus DROP, Spamhaus EDROP (first 4 enabled by default)
- Local custom blocklist file support (IPs and CIDRs)
- Periodic background refresh (default: every hour)
- O(1) plain-IP lookup, CIDR range matching via `ipaddress`
- `auto_block` mode — blocks on first hit before thresholds fire

**Tests** — 20 new tests — total **145 passing** (was 125)

**Version** — bumped to `1.6.0`

---

### v1.5.0 — Alert Rule Engine

**New module: `cnsl/rules.py`**
- `Rule` dataclass — id, name, description, severity, threshold, window_sec, enabled, tags
- `RuleEngine` — manages all 9 built-in rules with config override and runtime mutation
- Built-in rules: `ssh.brute_force`, `ssh.credential_stuffing`, `ssh.credential_breach`,
  `web.scan_flood`, `web.auth_flood`, `web.exploit`, `db.brute_force`,
  `fw.honeypot_port`, `net.repeat_offender`
- Runtime API: `enable()`, `disable()`, `update()`, `reset()` — no restart required
- Immutable built-in defaults — `reset()` always restores original values

**Tests** — 22 new tests — total **125 passing** (was 103)

**Version** — bumped to `1.5.0`

---

### v1.4.0 — Case Management

**New module: `cnsl/cases.py`**
- `CaseManager` — full async SQLite-backed case lifecycle
- Auto-create cases from every HIGH severity detection
- Status transitions: `open` → `investigating` → `closed` / `false_positive`
- Every status change and assignment logged as append-only system note (full audit trail)
- Analyst notes — timestamped, append-only, author tracked

**Tests** — 23 new tests — total **103 passing** (was 80)

**Version** — bumped to `1.4.0`

---

### v1.3.0 — Two-Factor Authentication (TOTP)

- `auth.py` — TOTP 2FA (Google Authenticator / Authy compatible)
  - Per-user enable/disable — existing accounts unaffected until opted in
  - Two-step login: password → 6-digit OTP (partial token, 5 min expiry)
  - 8 single-use backup codes generated on activation (SHA-256 hashed in storage)
  - TOTP allows ±1 window (30s drift tolerance)
  - Graceful degradation if `pyotp` not installed

- `pyotp>=2.9.0` added to `requirements.txt` and `setup.py` extras

**Tests** — 22 new tests — total **80 passing** (was 58)

**Version** — bumped to `1.3.0`

---

### v1.2.0 — Country blocking, Email notifications, Docs

- Country-based blocking via `country_block.countries: ["CN", "RU"]`
- Email (SMTP) notifications — STARTTLS, implicit SSL, and plain SMTP
- Standalone `docs/` folder with 6 guides

**Version** — bumped to `1.2.0`

---

### v1.1.0 — Remote ingestion, ECS normalization, search engine

**New modules:** `syslog_receiver.py`, `normalizer.py`, `search_engine.py`

**Bug fixes:**
- IPv6-mapped IPv4 addresses (`::ffff:1.2.3.4`) stripped to plain IPv4
- Web log parser rewritten — bare 404 on normal paths no longer flagged as `WEB_SCAN`
- File write errors handled gracefully instead of crashing the engine
- `kind` column added to incidents table with automatic migration

**Tests** — total **48 passing** (was 26)

**Version** — bumped to `1.1.0`

---

### v1.0.4 — Honeypot overhaul, FIM fix, emoji removed

- `honeypot.py` — Full shell simulation rewrite. 40+ commands, persistent virtual filesystem
- `fim.py` — Directories in `watch_paths` now scanned recursively with `os.walk()`
- `notify.py` — All emoji removed, plain text messages, Telegram escaping fixed
- `logger.py` — Emoji prefixes replaced with aligned text labels

---

### v1.0.3 — Critical runtime fixes

- `parsers.py` — `sshd-session[PID]` regex added for modern OpenSSH
- `config.py` — `/etc/cnsl/config.json` now auto-discovered on startup
- Default `allowlist` — `::1` removed, `fails_threshold` lowered to 5

---

### v1.0.2 — Dashboard overhaul

- Tabbed UI with 7 tabs, 8 stat cards, timeline chart, PDF export, SVG icons
- New endpoints: `/api/timeline`, `/api/ml-status`, `/api/honeypot`, `/api/fim`, `/api/system`, `/api/debug`

---

### v1.0.1 — Bug fixes

- `engine_loop()` — `NameError` crash on first event fixed
- RBAC enforced on block/unblock endpoints
- Prometheus gauge decrements on unblock
- Redis unblock propagation fixed

---

### v1.0.0 — Initial release

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Thank You!

</div>