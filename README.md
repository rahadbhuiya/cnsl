<div align="center">

# 🛡️ CNSL — Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/tests-26%20passing-brightgreen" alt="26 Tests Passing">
  <img src="https://img.shields.io/badge/version-1.0.1-blue" alt="Version 1.0.1">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey" alt="Linux">
</p>

**A pre-SIEM, intent-aware security layer for Linux servers.**

Correlates SSH, web, database, and firewall signals to detect attacks  
that no single log source can see alone — then blocks them automatically.

[Quick Start](#quick-start) · [Features](#features) · [Dashboard](#dashboard) · [API](#rest-api) · [Docs](#how-to-run-step-by-step) · [Changelog](#changelog)

</div>

---

## Why CNSL?

Most security tools watch **one log** and count failures. That's not enough.

A real attacker doesn't just hammer SSH — they scan your web server, probe your database, then log in with stolen credentials. **CNSL sees the full picture.**

```
Web scan      from 45.33.32.1  ──┐
SSH brute     from 45.33.32.1  ──┼──▶  HIGH alert + auto-block
DB auth fail  from 45.33.32.1  ──┘
```

---

## CNSL vs Fail2ban vs SSHGuard

| Feature | Fail2ban | SSHGuard | **CNSL** |
|:---|:---:|:---:|:---:|
| Multi-source log correlation | ❌ | ❌ | ✅ |
| Credential breach detection | ❌ | ❌ | ✅ |
| ML anomaly detection | ❌ | ❌ | ✅ |
| Honeypot (fake SSH shell) | ❌ | ❌ | ✅ |
| Live web dashboard | ❌ | ❌ | ✅ |
| GeoIP + threat intelligence | ❌ | ❌ | ✅ |
| File integrity monitoring | ❌ | ❌ | ✅ |
| Telegram / Discord / Slack | ❌ | ❌ | ✅ |
| Redis distributed blocklist | ❌ | ❌ | ✅ |
| Prometheus + Grafana | ❌ | ❌ | ✅ |
| SOC2 / PCI-DSS compliance reports | ❌ | ❌ | ✅ |
| Privilege escalation detection | ❌ | ❌ | ✅ |
| Auto-unblock timer | ✅ | ✅ | ✅ |
| Language | Python | C | Python |

---

## What CNSL Detects

| Threat | How |
|:---|:---|
| **SSH brute-force** | Threshold-based failure counting per IP |
| **Credential breach** | SSH success after repeated failures (stolen password) |
| **Credential stuffing** | Many different usernames tried from one IP |
| **Web scanner** | Nikto, sqlmap, gobuster User-Agent & path detection |
| **Web exploit attempts** | `/wp-admin`, `/.env`, `/phpmyadmin`, path traversal |
| **Database brute-force** | MySQL auth failure spikes |
| **Honeypot port probe** | Any connection to port 23 / 3389 / 6379 → instant block |
| **Privilege escalation** | `sudo`/`su` failure after successful SSH login |
| **File tampering** | `/etc/passwd`, `authorized_keys`, `sshd_config`, crontab |
| **Behavioral anomaly** | Unusual login hour, new username, frequency spike (ML) |
| **Coordinated attack** | Same IP across SSH + web + DB simultaneously |

---

## Features

| Category | Capability |
|:---|:---|
| **Detection** | SSH brute-force, credential stuffing, credential breach |
| **Detection** | Web scanner (nikto, sqlmap, gobuster UA) + exploit paths |
| **Detection** | Database brute-force (MySQL), firewall honeypot ports |
| **Detection** | Privilege escalation (sudo/su after login) |
| **Correlation** | 6 cross-source rules — web+SSH, multi-service, kill chain, etc. |
| **Response** | iptables / ipset auto-block with configurable auto-unblock timer |
| **Response** | Honeypot redirect — attacker lands on a fake Ubuntu shell |
| **Response** | Redis distributed blocklist — sync blocks across a server cluster |
| **Intelligence** | GeoIP enrichment (MaxMind offline or ip-api.com fallback) |
| **Intelligence** | AbuseIPDB threat score lookup |
| **Intelligence** | Behavioral baseline + ML anomaly detection (IsolationForest) |
| **Monitoring** | File Integrity Monitoring (FIM) with SQLite baseline |
| **Monitoring** | Passive asset inventory via network events |
| **Visibility** | Live web dashboard with Server-Sent Events real-time feed |
| **Visibility** | Prometheus metrics + Grafana dashboard template |
| **Reporting** | PDF / HTML compliance reports (SOC2, ISO27001, PCI-DSS) |
| **Access** | JWT authentication + Role-Based Access Control (4 roles) |
| **Notifications** | Telegram, Discord, Slack, custom webhook |
| **Persistence** | SQLite incident history, FIM baseline, block records |
| **Ops** | Dry-run safe by default · systemd ready · Docker ready |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl

# 2. Install
pip install -e ".[full]"

# 3. Run in safe dry-run mode (no real blocks)
sudo python -m cnsl --no-tcpdump

# 4. Run with live dashboard
sudo python -m cnsl --dashboard --no-tcpdump
# → Open http://127.0.0.1:8765
# → Default login: admin / cnsl-change-me

# 5. Enable real blocking when ready
sudo python -m cnsl --execute --dashboard
```

> **Note:** `sudo` is required for `/var/log/auth.log`, `iptables`, and `tcpdump`.

---

## Installation

```bash
pip install -e .            # core only (pure stdlib — no external deps)
pip install -e ".[full]"    # everything recommended
pip install -e ".[dev]"     # + testing tools
```

| Extra | Packages | Required for |
|:---|:---|:---|
| `full` | aiohttp, aiosqlite, pyyaml, bcrypt, sklearn, numpy, reportlab | Dashboard, DB, YAML config, auth, ML, PDF reports |
| `auth` | bcrypt, PyJWT | Dashboard login |
| `db` | aiosqlite | SQLite persistence |
| `geoip` | geoip2 | MaxMind offline GeoIP |
| `ml` | scikit-learn, numpy | ML anomaly detection |
| `reports` | reportlab | PDF compliance reports |
| `dev` | pytest + all above | Running tests |

---

## Usage

```
sudo python -m cnsl [options]

Core:
  --config FILE        Config file (.json or .yaml)
  --authlog PATH       Auth log path  (default: /var/log/auth.log)
  --iface IFACE        Network interface for tcpdump  (default: any)
  --execute            Enable real blocking  (default: dry-run)
  --backend BACKEND    Blocking backend: iptables or ipset  (default: iptables)

Features:
  --dashboard          Enable web dashboard on http://127.0.0.1:8765
  --no-tcpdump         Auth.log only — lower CPU
  --no-geoip           Disable GeoIP enrichment
  --no-db              Disable SQLite persistence

Reports:
  --report FORMAT      Generate report and exit  (html | pdf | json)
  --report-days N      Report period in days  (default: 30)
  --grafana-export     Export Grafana dashboard JSON and exit
```

### Auth log paths by OS

| OS | Default path | Override flag |
|:---|:---|:---|
| Ubuntu / Debian | `/var/log/auth.log` | *(default)* |
| CentOS / RHEL / Fedora | `/var/log/secure` | `--authlog /var/log/secure` |
| OpenSUSE | `/var/log/messages` | `--authlog /var/log/messages` |

---

## How to Run (Step by Step)

### Step 1 — Minimal run (dry-run, auth.log only)

No config needed. Completely safe:

```bash
sudo python -m cnsl --no-tcpdump
```

Every SSH event appears in the console in real time.

---

### Step 2 — With dashboard

```bash
sudo python -m cnsl --dashboard --no-tcpdump
```

Open `http://127.0.0.1:8765` · Login: `admin` / `cnsl-change-me`

---

### Step 3 — Create a config file

```bash
sudo mkdir -p /etc/cnsl
sudo cp config/config.example.json /etc/cnsl/config.json
sudo nano /etc/cnsl/config.json
```

**Minimum required changes:**

```json
{
  "authlog_path": "/var/log/auth.log",

  "allowlist": [
    "127.0.0.1",
    "::1",
    "YOUR_OWN_IP_HERE"
  ],

  "actions": {
    "dry_run": false,
    "block_duration_sec": 900
  }
}
```

> ⚠️ **Always add your own IP to `allowlist` before setting `dry_run: false`.**  
> Forgetting this will lock you out of your own server.

---

### Step 4 — Enable live blocking

```bash
sudo python -m cnsl \
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
  "scan_interval_sec": 300
}
```

Watches `/etc/passwd`, `authorized_keys`, `sshd_config`, crontab, and more.

---

### Step 7 — Enable ML anomaly detection (optional)

```json
"ml": {
  "enabled": true,
  "min_samples": 100
}
```

Collects a baseline for a while, then starts flagging statistical outliers automatically.

---

### Step 8 — Enable Telegram alerts (optional)

```json
"notifications": {
  "min_severity": "MEDIUM",
  "telegram": {
    "enabled": true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "YOUR_CHAT_ID"
  }
}
```

Get a bot token from `@BotFather` on Telegram. Get your chat ID from `@userinfobot`.

---

### Step 9 — Run as a systemd service

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
ExecStart=/usr/bin/python3 -m cnsl \
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
# Run all 11 scenarios
python simulate.py

# Run a specific scenario
python simulate.py brute        # SSH brute-force
python simulate.py breach       # credential breach (HIGH severity)
python simulate.py stuffing     # credential stuffing
python simulate.py web          # web scanner + exploit attempt
python simulate.py db           # database brute-force
python simulate.py priv         # privilege escalation (SSH → sudo)
python simulate.py honeypot     # honeypot port probe + instant block
python simulate.py correlation  # multi-source coordinated attack (HIGH)
python simulate.py unblock      # auto-unblock + Prometheus gauge verify
python simulate.py allowlist    # allowlist protection test

# Interactive mode — type events manually
python simulate.py live
```

```
# SSH events
cnsl> fail 1.2.3.4 root      # SSH failure
cnsl> ok   1.2.3.4 root      # SSH success → HIGH breach alert

# Other attack types
cnsl> web     1.2.3.4         # web scanner
cnsl> exploit 1.2.3.4 /.env  # web exploit attempt
cnsl> db      1.2.3.4 root   # database auth failure
cnsl> sudo    1.2.3.4        # sudo failure (privilege escalation)
cnsl> hp      1.2.3.4 23     # honeypot port probe

# Management
cnsl> unblock 1.2.3.4        # manually unblock IP
cnsl> blocks                  # show active blocks
cnsl> status                  # show all tracked IPs
cnsl> metrics                 # show Prometheus counters
```

---

## Dashboard

Enable with `--dashboard`. Access at `http://127.0.0.1:8765`

| Section | What it shows |
|:---|:---|
| **Stat cards** | Total incidents, HIGH severity count, active blocks, unique attackers |
| **Charts** | Incidents over time, severity breakdown |
| **Active blocks** | Currently blocked IPs with one-click unblock |
| **Top attackers** | IP, country, ISP, incident count |
| **Recent incidents** | Time, IP, location, severity, detection reason |
| **Live feed** | Every event streamed in real time (SSE) |

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

Default credentials: `admin` / `cnsl-change-me` — **change this before deploying to production.**

### Roles

| Role | Permissions |
|:---|:---|
| `viewer` | Read stats, incidents, blocks, metrics |
| `analyst` | viewer + manual block / unblock *(enforced — viewer cannot block)* |
| `auditor` | analyst + generate reports + view asset inventory |
| `admin` | Full access including config and honeypot management |

> RBAC is enforced on all write endpoints. Block and unblock operations require `analyst` role or above. IP format is validated before any block action is taken.

---

## Honeypot Mode

Instead of simply blocking, redirect attackers to a fake Ubuntu SSH server:

```json
"honeypot": {
  "enabled": true,
  "mode": "redirect",
  "honeypot_port": 2222,
  "listen_ports": [23, 3306, 6379, 27017]
}
```

The attacker connects to what looks like a real server, types commands, and everything is logged. They never touch anything real.

---

## Notifications

```json
"notifications": {
  "min_severity": "MEDIUM",
  "telegram": { "enabled": true, "bot_token": "...", "chat_id": "..." },
  "discord":  { "enabled": true, "webhook_url": "..." },
  "slack":    { "enabled": true, "webhook_url": "..." }
}
```

---

## Reports

```bash
# HTML report — last 30 days
python -m cnsl --report html --report-days 30

# PDF report
python -m cnsl --report pdf

# Export Grafana dashboard JSON
python -m cnsl --grafana-export
```

Reports include: incident summary, top attackers, FIM alerts, and a SOC2 / ISO27001 / PCI-DSS compliance mapping.

---

## Grafana

```bash
python -m cnsl --grafana-export
```

Import in Grafana: `Dashboards → Import → Upload cnsl_grafana_dashboard.json`

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

> Get a JWT token via `POST /api/login`. If auth is disabled in config, no token is needed.

---

## REST API

All endpoints are available when `--dashboard` is active.

```
GET  /api/stats             Engine summary — incidents, blocks, uptime
GET  /api/incidents         Recent incidents  (?limit=50, max 500)
GET  /api/blocks            Currently active blocks
GET  /api/top-attackers     Top attacker IPs with geo + ISP info
GET  /api/assets            Passive network asset inventory
GET  /api/assets/summary    Trust level breakdown
GET  /api/metrics           Prometheus metrics  (auth required)
GET  /api/rbac/roles        Role and permission definitions
GET  /api/honeypot/status   Honeypot listener status

POST /api/login             {"username": "...", "password": "..."}
POST /api/logout
POST /api/block             {"ip": "1.2.3.4"}   — analyst+ only, IP validated
POST /api/unblock           {"ip": "1.2.3.4"}   — analyst+ only
POST /api/report            {"format": "html", "days": 30}
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
    "geo": { "country": "China", "city": "Beijing", "flag": "🇨🇳" }
  }
}
```

```bash
# Stream all events live
tail -f cnsl.jsonl | jq .

# HIGH severity incidents only
tail -f cnsl.jsonl | jq 'select(.type=="incident" and .payload.severity=="HIGH")'
```

Compatible with: **Grafana Loki · Elasticsearch · Splunk · Vector · Fluentd · Datadog**

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
pytest tests/ -v
# 26 passed
```

---

## Project Structure

```
cnsl/
├── cnsl/
│   ├── __init__.py          package version info
│   ├── __main__.py          python -m cnsl entrypoint
│   │
│   ├── models.py            Event, Detection dataclasses
│   ├── config.py            config loading + all defaults
│   ├── validator.py         startup config validation
│   ├── logger.py            async structured JSON logger
│   │
│   ├── parsers.py           auth.log + tcpdump line parsers
│   ├── log_sources.py       nginx, apache, mysql, ufw, syslog parsers
│   ├── sources.py           async log file tailers (tail -F)
│   │
│   ├── detector.py          stateful per-IP detection engine
│   ├── correlator.py        cross-source correlation rules (6 rules)
│   ├── ml_detector.py       ML anomaly detection (IsolationForest)
│   ├── threat_intel.py      AbuseIPDB + behavioral baseline
│   │
│   ├── blocker.py           iptables / ipset blocking backend
│   ├── honeypot.py          fake SSH server + active response
│   ├── redis_sync.py        distributed blocklist via Redis pub/sub
│   │
│   ├── geoip.py             GeoIP (MaxMind offline + ip-api.com)
│   ├── assets.py            passive asset inventory
│   ├── fim.py               file integrity monitoring
│   │
│   ├── auth.py              JWT authentication (PyJWT or fallback)
│   ├── rbac.py              role-based access control (4 roles)
│   ├── dashboard.py         web dashboard + REST API + SSE feed
│   ├── metrics.py           Prometheus metrics
│   ├── grafana.py           Grafana dashboard template generator
│   ├── reporter.py          PDF / HTML compliance reports
│   ├── notify.py            Telegram, Discord, Slack, webhook
│   ├── store.py             SQLite persistence (aiosqlite)
│   └── engine.py            main async loop + CLI argument parser
│
├── tests/
│   └── test_cnsl.py         26 unit tests
│
├── config/
│   └── config.example.json  annotated example config
│
├── .github/workflows/ci.yml
├── simulate.py              local test simulator (11 scenarios)
├── Dockerfile
├── setup.py
├── requirements.txt
└── README.md
```

---

## Roadmap

- [ ] Country-based blocking (`block_countries: ["CN", "RU"]`)
- [ ] Community threat feed — opt-in shared blocklist across CNSL instances
- [ ] Email notifications (SMTP)
- [ ] 2FA for dashboard login
- [ ] Kafka support for high-volume environments
- [ ] Multi-tenant support
- [ ] Zeek log ingestion (richer network signals)
- [ ] Grafana alerting rules template
- [ ] Agent system for multi-server log collection
- [ ] Sigma rule support (import industry-standard detection rules)

---

## Safety

> ⚠️ `--execute` flag modifies live firewall rules.

Before enabling real blocking:

1. Add your management IP to `allowlist` in config
2. Test in dry-run mode first — this is the default
3. Ensure you have console or out-of-band access to the server
4. The authors are not responsible for accidental self-lockouts

---

## Contributing

1. Fork and create a feature branch
2. Add or update tests in `tests/test_cnsl.py`
3. Run `pytest tests/ -v` — all 26 must pass
4. Submit a pull request

Code style: type hints on all public functions, docstrings on all public methods, no external dependencies in `cnsl/` core modules.

---

## Changelog

### v1.0.1 — Bug Fixes

**Critical**
- `engine_loop()` — `ml_detector` was used but never passed as a parameter — `NameError` crash on the very first event
- `start_dashboard()` — missing `rbac`, `assets`, `honeypot` parameters caused a `TypeError` at startup; dashboard never launched
- `engine.py` — `blocker.store` assigned before `store` was initialised — `UnboundLocalError` on startup

**Security**
- `/api/metrics` — now requires authentication (was publicly accessible to anyone)
- `/api/block` and `/api/unblock` — RBAC now enforced; `viewer` role can no longer perform write actions
- `/api/block` — IP address format is now validated before any iptables action
- `/api/incidents` — `?limit` parameter safely parsed and clamped to 1–500 (was an unguarded `int()` crash)

**Logic**
- `metrics.dec_block()` — Prometheus `cnsl_blocks_active` gauge now decrements correctly on unblock (was only ever incremented)
- `store.remove_block()` — unblock now removes the entry from SQLite; dashboard block count was previously stale
- Redis cluster sync — `publish_unblock()` was defined but never called; unblock events now propagate to all cluster nodes
- Redis `subscribe_loop()` — `action == "unblock"` messages were silently dropped; now handled via `on_remote_unblock` callback
- `--no-geoip` / `--no-db` — config-file path (`cfg["_no_geoip"]`) was ignored; only the CLI flag worked

**Performance**
- `ml_detector._retrain()` — `_last_train` was only updated on successful training; if below `min_samples`, retrain was attempted on every single event
- `fim._scan()` — all SQLite calls now run via `loop.run_in_executor()` to avoid blocking the async event loop

**Resource Leaks**
- `sources.py` and `log_sources.py` — `tail`/`tcpdump` subprocesses were never killed on EOF or exception; each reconnect spawned a new zombie process. Now always killed in a `finally` block.

**Concurrency**
- `AbuseIPDB.check()` — concurrent calls could both slip through the rate-limit window and fire duplicate HTTP requests. Now serialized with `asyncio.Lock` and a double-checked cache pattern.

**Simulator**
- `simulate.py` — added 7 new scenarios: web scanner, DB brute-force, privilege escalation, honeypot probe, multi-source correlation, auto-unblock/metrics verify, allowlist
- Wired `metrics`, `store`, and `correlator` into simulator setup so all bug fixes are exercised by tests
- Added interactive commands: `web`, `exploit`, `db`, `sudo`, `hp`, `unblock`, `metrics`

### v1.0.0 — Initial Release

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Made with by <a href="https://github.com/rahadbhuiya">Rahad Bhuiya</a>

</div>