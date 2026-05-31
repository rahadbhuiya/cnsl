<div align="center">

# CNSL — Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/tests-58%20passing-brightgreen" alt="58 Tests Passing">
  <img src="https://img.shields.io/badge/version-1.2.0-blue" alt="Version 1.2.0">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey" alt="Linux">
</p>

**A lightweight SIEM for Linux — correlation, ML, honeypot, and search.**

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
# 1. Clone
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl

# 2. Install (use a virtualenv)
python3 -m venv venv
source venv/bin/activate
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
| `full` | aiohttp, aiosqlite, pyyaml, bcrypt, sklearn, numpy, reportlab | Dashboard, DB, auth, ML, PDF reports |
| `auth` | bcrypt, PyJWT | Dashboard login |
| `db` | aiosqlite | SQLite persistence |
| `geoip` | geoip2 | MaxMind offline GeoIP |
| `ml` | scikit-learn, numpy | ML anomaly detection |
| `reports` | reportlab | PDF compliance reports |
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

> Always add your own IP to `allowlist` before setting `dry_run: false`.
> Remove `::1` from `allowlist` if you want to detect attacks from localhost.
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
  "secret_key": "REPLACE_WITH_RANDOM_SECRET"
}
```

Generate a secure key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Default credentials: `admin` / `cnsl-change-me` — change before deploying to production.

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
# 58 passed
```

---

## Project Structure

```
cnsl/
├── cnsl/
│   ├── __init__.py          package version (1.2.0)
│   ├── __main__.py          python -m cnsl entrypoint
│   │
│   ├── models.py            Event, Detection dataclasses
│   ├── config.py            config loading and all defaults
│   ├── validator.py         startup config validation
│   ├── logger.py            async JSON logger (text prefixes, no emoji)
│   │
│   ├── parsers.py           auth.log + tcpdump parsers (sshd + sshd-session)
│   ├── log_sources.py       nginx, apache, mysql, ufw, syslog parsers
│   ├── sources.py           async log file tailers
│   ├── syslog_receiver.py   UDP/TCP syslog server (RFC 3164/5424)
│   │
│   ├── normalizer.py        ECS/CEF event normalization
│   ├── search_engine.py     KQL search, aggregations, Elasticsearch push
│   │
│   ├── detector.py          stateful per-IP detection engine + country blocking
│   ├── correlator.py        cross-source correlation rules (6 rules)
│   ├── ml_detector.py       ML anomaly detection (IsolationForest, auto-trains)
│   ├── threat_intel.py      AbuseIPDB + behavioral baseline
│   │
│   ├── blocker.py           iptables / ipset blocking backend
│   ├── honeypot.py          fake SSH server (40+ commands, virtual filesystem)
│   ├── redis_sync.py        distributed blocklist via Redis pub/sub
│   │
│   ├── geoip.py             GeoIP (MaxMind offline + ip-api.com)
│   ├── assets.py            passive asset inventory
│   ├── fim.py               file integrity monitoring (files + directories)
│   │
│   ├── auth.py              JWT authentication
│   ├── rbac.py              role-based access control (4 roles)
│   ├── dashboard.py         web dashboard + REST API + SSE feed
│   ├── metrics.py           Prometheus metrics
│   ├── grafana.py           Grafana dashboard template generator
│   ├── reporter.py          PDF / HTML compliance reports
│   ├── notify.py            Telegram, Discord, Slack, Email, webhook
│   ├── store.py             SQLite persistence (aiosqlite)
│   └── engine.py            main async loop + CLI argument parser
│
├── tests/
│   └── test_cnsl.py         48 unit tests
│
├── config/
│   └── config.example.json  annotated example config
│
├── docs/
│   ├── installation.md      install, Docker, systemd
│   ├── configuration.md     full config reference
│   ├── api.md               REST API endpoints + examples
│   ├── notifications.md     Telegram, Discord, Slack, Email, webhook
│   ├── country-blocking.md  country-based blocking guide
│   └── architecture.md      module map, event flow, concurrency model
│
├── .github/workflows/ci.yml
├── simulate.py              local test simulator (12 scenarios)
├── Dockerfile
├── setup.py
├── requirements.txt
└── README.md
```

---

## Roadmap

- [ ] Alert Rule Engine — Sigma rule support, custom thresholds, enable/disable toggle
- [ ] Case Management — incident tickets, assign to analyst, status tracking
- [ ] Full UEBA — per-user behavior profiles, lateral movement detection
- [x] Country-based blocking — added in v1.2.0 (`country_block.countries: ["CN", "RU"]`)
- [x] Email notifications (SMTP) — added in v1.2.0
- [ ] 2FA for dashboard login
- [ ] Community threat feed — opt-in shared blocklist
- [ ] Kafka support for high-volume environments
- [ ] Zeek log ingestion
- [ ] Multi-tenant support
- [ ] Agent system for multi-server log collection
- [ ] WebSocket instead of SSE for bidirectional dashboard control

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
3. Run `pytest tests/ -v --timeout=60` — all 48 must pass
4. Submit a pull request

Code style: type hints on all public functions, docstrings on all public methods, no external dependencies in `cnsl/` core modules.

---

## Changelog

### v1.2.0 — Country blocking, Email notifications, Docs

**New features**

- `config.py` / `detector.py` — Country-based blocking. Set `country_block.enabled: true` and
  `country_block.countries: ["CN", "RU"]` to block all traffic from specific countries before
  detection thresholds fire. The first event from a blocked-country IP raises a `HIGH` severity
  incident immediately. A per-rule `allowlist` lets you exempt specific trusted IPs.
  Requires GeoIP to be enabled (MaxMind offline or ip-api.com fallback).

- `notify.py` — Email (SMTP) notifications. Sends HTML + plaintext multipart alerts.
  Supports STARTTLS (port 587), implicit SSL (port 465), and plain SMTP.
  Configurable sender, multiple recipients, and subject prefix.
  All SMTP I/O runs in a thread executor — the detection engine is never blocked.
  Works with Gmail (App Password), Outlook, SendGrid, Postmark, and self-hosted mail servers.

- `docs/` — Standalone documentation folder.
  `installation.md`, `configuration.md`, `api.md`, `notifications.md`,
  `country-blocking.md`, `architecture.md`.

**Bug fixes**

- `engine.py` — `--version` flag was reporting `CNSL 1.0.0` instead of the current version.
  Now correctly reads from `__version__` in `__init__.py`.

**Version**

- `__init__.py`, `setup.py`, `engine.py` — bumped to `1.2.0`.

---

### v1.1.0 — Remote ingestion, ECS normalization, search engine

**New modules**

- `syslog_receiver.py` — UDP/TCP syslog server (RFC 3164 and RFC 5424). Routers, switches, firewalls, and remote Linux servers can ship logs directly to CNSL without a file agent. Parsed events go through the same detection pipeline as local logs. Configure with `syslog_receiver.enabled: true` and `udp_port: 5514` (no root required for ports above 1024).

- `normalizer.py` — ECS-compatible event normalization. Every CNSL event is automatically normalized to a consistent schema regardless of source (SSH, web, MySQL, UFW, syslog, remote syslog). Supports ECS JSON export for Elasticsearch and CEF format for ArcSight/Splunk. CEF `rt=` field uses the event's actual timestamp.

- `search_engine.py` — KQL-like full-text search, time-range filtering, and aggregations over the SQLite incident store. Optional Elasticsearch/OpenSearch push. New endpoints: `/api/search`, `/api/aggregate`, `/api/events`, `/api/export/ecs`, `/api/export/cef`, `/api/search/es-push`, `/api/search/es-status`.

**Bug fixes**

- `parsers.py` — IPv6-mapped IPv4 addresses (`::ffff:1.2.3.4`) are now stripped to plain IPv4 (`1.2.3.4`). Zone IDs (`fe80::1%eth0`) and brackets (`[::1]`) are also cleaned. The word `invalid` is no longer mistakenly extracted as a username from "Failed password for invalid user admin" lines.

- `log_sources.py` — Web log parser completely rewritten. A bare 404 on a normal path is no longer flagged as `WEB_SCAN` — only scanner user-agents or exploit paths trigger alerts. Googlebot, Bingbot, and other known legitimate crawlers are whitelisted. Duplicate `parse_web_access` function removed.

- `logger.py` — File write errors (disk full, file removed) are now handled gracefully instead of crashing the engine. Parent directories are created automatically if missing.

- `store.py` — Added `kind` column to the incidents table. Automatic migration for existing databases (`ALTER TABLE ADD COLUMN` on startup). `save_incident()` now infers the event kind from reasons — `credential_breach` incidents correctly store `SSH_SUCCESS`, not `SSH_FAIL`. Old databases can be fixed manually: `UPDATE incidents SET kind='SSH_SUCCESS' WHERE reasons LIKE '%credential_breach%'`.

- `search_engine.py` — Hourly aggregation now defaults to the last 30 days instead of last 24 hours, so data is visible even when there are no recent incidents.

- `dashboard.py` — `kind` field is now read from the database column instead of being hardcoded as `SSH_FAIL` in normalized event endpoints. Added `search_engine` and `es_pusher` parameters to `start_dashboard()`.

**Tests**

- 48 tests total (was 26 in v1.0.0).
- Added `TestSshdSessionParser` — 5 tests covering modern OpenSSH sshd-session format and IPv6.
- Added `TestTelegramEscape` — 6 tests covering Markdown v1 special character escaping.
- Added `TestStoreLowCount` — 2 tests verifying LOW severity is counted correctly in SQL.
- Added `TestFIMDirectoryScanning` — 3 tests verifying directories in `watch_paths` are scanned recursively.
- Added `TestMLRetrain` — 2 tests verifying ML timer logic (no training without data).
- Added `TestDashboardSignature` — 2 tests verifying `ml_detector` and `fim` parameters are present.
- `TestConfig` updated — tests `DEFAULT_CONFIG` directly instead of `load_config(None)` which now auto-discovers `/etc/cnsl/config.json`.
- `TestParseAuthEvent.test_ipv6_address` updated — `::ffff:1.2.3.4` correctly strips to `1.2.3.4`.
- sklearn pre-imported at module level so ML tests do not timeout on first import.

---

### v1.0.4 — Honeypot overhaul, FIM fix, emoji removed

- `honeypot.py` — Full shell simulation rewrite. 40+ commands, persistent virtual filesystem, dynamic prompt, realistic file contents.
- `fim.py` — Directories in `watch_paths` now scanned recursively with `os.walk()`.
- `notify.py` — All emoji removed, plain text messages, Telegram escaping fixed.
- `logger.py` — Emoji prefixes replaced with aligned text labels.
- `reporter.py` — HTML uses inline SVG, PDF uses plain text.

---

### v1.0.3 — Critical runtime fixes

- `parsers.py` — `sshd-session[PID]` regex added for modern OpenSSH.
- `config.py` — `/etc/cnsl/config.json` now auto-discovered on startup.
- Default `allowlist` — `::1` removed, `fails_threshold` lowered to 5.

---

### v1.0.2 — Dashboard overhaul

- Tabbed UI with 7 tabs, 8 stat cards, timeline chart, PDF export, SVG icons.
- ML tab, Honeypot tab, FIM tab, manual block form, live feed improvements.
- New endpoints: `/api/timeline`, `/api/ml-status`, `/api/honeypot`, `/api/fim`, `/api/system`, `/api/debug`.
- `engine.py` — `ml_detector` and `fim` parameters added to `start_dashboard()`.
- `store.py` — LOW severity now counted correctly.

---

### v1.0.1 — Bug fixes

- `engine_loop()` — `NameError` crash on first event fixed.
- `start_dashboard()` — missing parameters fixed.
- RBAC enforced on block/unblock endpoints.
- Prometheus gauge decrements on unblock.
- Redis unblock propagation fixed.
- Subprocess resource leaks fixed.

---

### v1.0.0 — Initial release

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Made with by <a href="https://github.com/rahadbhuiya">Rahad Bhuiya</a>

</div>