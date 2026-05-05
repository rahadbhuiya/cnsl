<div align="center">

# 🛡️ CNSL — Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/tests-26%20passing-brightgreen" alt="26 Tests Passing">
  <img src="https://img.shields.io/badge/version-1.0.4-blue" alt="Version 1.0.4">
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
| PDF export from dashboard | ❌ | ❌ | ✅ |
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
| **File tampering** | `/etc/passwd`, `authorized_keys`, `sshd_config`, crontab, any watched directory |
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
| **Monitoring** | File Integrity Monitoring (FIM) — watches files AND directories recursively |
| **Monitoring** | Passive asset inventory via network events |
| **Visibility** | Live web dashboard with tabbed UI and Server-Sent Events real-time feed |
| **Visibility** | Prometheus metrics + Grafana dashboard template |
| **Reporting** | PDF export directly from dashboard (no extra tools needed) |
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

# 2. Install (use a virtualenv)
python3 -m venv venv
source venv/bin/activate
pip install -e ".[full]"

# 3. Run in safe dry-run mode (no real blocks)
sudo venv/bin/python -m cnsl --no-tcpdump

# 4. Run with live dashboard
sudo venv/bin/python -m cnsl --dashboard --no-tcpdump
# → Open http://127.0.0.1:8765
# → Default login: admin / cnsl-change-me

# 5. Enable real blocking when ready
sudo venv/bin/python -m cnsl --execute --dashboard
```

> **Important:** Always use the virtualenv's Python (`venv/bin/python`) with `sudo`.  
> Running `sudo python` uses the system Python which may not have all packages (e.g. `scikit-learn`).

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
    "YOUR_OWN_IP_HERE"
  ],

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

> **Important notes:**
> - Always add your own IP to `allowlist` before setting `dry_run: false` — forgetting this will lock you out.
> - Remove `::1` from `allowlist` if you want to detect attacks from localhost (e.g. for testing with `ssh localhost`).
> - Use absolute paths for `db_path` fields — relative paths cause baselines to reset on every restart.

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

FIM watches both individual files and entire directories (recursively). Any file created, modified, deleted, or permission-changed inside a watched directory fires an alert.

> Use absolute `db_path` — relative paths cause the baseline to reset on every restart.

**Test FIM:**
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

ML uses **IsolationForest** from scikit-learn — no pre-trained model needed. CNSL trains on your own traffic automatically.

- Collects `min_samples` events first, then trains
- Retrains every `retrain_interval_sec` seconds with fresh data
- Check training status: `http://127.0.0.1:8765/api/ml-status`

> **Important:** Use the virtualenv Python. `scikit-learn` installed in a venv won't be available to `sudo python` (system Python). Always run: `sudo venv/bin/python -m cnsl ...`

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
python simulate.py priv         # privilege escalation (SSH → sudo)
python simulate.py honeypot     # honeypot port probe + instant block
python simulate.py correlation  # multi-source coordinated attack (HIGH)
python simulate.py unblock      # auto-unblock + Prometheus gauge verify
python simulate.py allowlist    # allowlist protection test
python simulate.py metrics      # metrics & DB stats
python simulate.py notify       # notification pipeline + Telegram escaping test

# Interactive mode — type events manually
python simulate.py live
```

```
cnsl> fail 1.2.3.4 root      # SSH failure
cnsl> ok   1.2.3.4 root      # SSH success → HIGH breach alert
cnsl> web     1.2.3.4         # web scanner
cnsl> exploit 1.2.3.4 /.env  # web exploit attempt
cnsl> db      1.2.3.4 root   # database auth failure
cnsl> sudo    1.2.3.4        # sudo failure (privilege escalation)
cnsl> hp      1.2.3.4 23     # honeypot port probe
cnsl> unblock 1.2.3.4        # manually unblock IP
cnsl> blocks                  # show active blocks
cnsl> status                  # show all tracked IPs
cnsl> metrics                 # show Prometheus counters
```

---

## Dashboard

Enable with `--dashboard`. Access at `http://127.0.0.1:8765`

The dashboard has a **tabbed interface** — each tab shows a different area:

| Tab | What it shows |
|:---|:---|
| **Overview** | Stat cards (total incidents, HIGH, active blocks, unique attackers, uptime, SSH fails, events processed, all-time blocks) · Timeline chart (last 24h) · Severity doughnut · Top attackers table |
| **Incidents** | Full incident table with time, IP, location, severity, fail count, detection reasons |
| **Blocks** | Active blocks with unblock button · Manual block form (type IP + Enter) |
| **Honeypot** | Status, mode, active redirects · Session table (IP, duration, auth attempts, commands typed) |
| **FIM** | Watched paths list · File integrity alerts (created / modified / deleted / permission) |
| **ML** | Enabled/trained status · Training progress bar · Samples collected · Last trained time |
| **Live Feed** | Every event streamed in real time via SSE · Clear button |

**Export PDF** button in the header generates a full security report from all current data — no extra tools needed, uses browser print.

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

Default credentials: `admin` / `cnsl-change-me` — **change before deploying to production.**

### Roles

| Role | Permissions |
|:---|:---|
| `viewer` | Read stats, incidents, blocks, metrics |
| `analyst` | viewer + manual block / unblock |
| `auditor` | analyst + generate reports + view asset inventory |
| `admin` | Full access |

---

## Honeypot Mode

Instead of blocking attackers, redirect them to a fake SSH server. The attacker thinks they got in — while every command they type is logged.

```json
"honeypot": {
  "enabled": true,
  "mode": "redirect",
  "honeypot_host": "127.0.0.1",
  "honeypot_port": 2222,
  "fake_hostname": "ubuntu-server",
  "fake_version": "Ubuntu 22.04.3 LTS",
  "log_commands": true,
  "auto_redirect_severity": "HIGH"
}
```

> Use `honeypot_port` (not `ports`). Make sure port 2222 is free before starting.

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
| `sudo`, `passwd` | Password prompts (logs what they type) |
| `systemctl status` | Returns fake service status |

Everything the attacker types is logged to `cnsl.jsonl` as `honeypot_command` events and visible in the **Honeypot tab** of the dashboard.

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

Messages use clean plain text. ISP names, city names, and detection reasons with special characters (`_`, `*`) are automatically escaped so Telegram formatting never breaks.

---

## Reports

**From the dashboard** — click **Export PDF** in the header. Generates a full security report from live data including incidents, blocks, FIM alerts, honeypot sessions, and ML status. No extra tools needed — uses browser print.

**From the CLI:**

```bash
# HTML report — last 30 days
python -m cnsl --report html --report-days 30

# PDF report (requires reportlab: pip install reportlab)
python -m cnsl --report pdf

# JSON — machine-readable, for integration
python -m cnsl --report json

# Export Grafana dashboard JSON
python -m cnsl --grafana-export
```

Reports include: executive summary, top attackers, recent incidents, FIM alerts, honeypot sessions, ML status, and SOC2 / ISO27001 / PCI-DSS compliance mapping.

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

---

## REST API

All endpoints available when `--dashboard` is active.

```
GET  /api/stats             Engine summary — incidents, blocks, uptime
GET  /api/incidents         Recent incidents  (?limit=50, max 500)
GET  /api/blocks            Currently active blocks
GET  /api/top-attackers     Top attacker IPs with geo + ISP info
GET  /api/timeline          Incident counts per hour for last 24h (for charts)
GET  /api/ml-status         ML detector status + training progress
GET  /api/honeypot          Honeypot status + recent sessions
GET  /api/fim               FIM alerts + watched paths
GET  /api/system            Uptime, SSH fails total, events processed, blocks total
GET  /api/assets            Passive network asset inventory
GET  /api/metrics           Prometheus metrics  (auth required)
GET  /api/debug             Module wiring status (ml, fim, honeypot, assets)

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
│   ├── api.py               Lightweight REST API
│   ├── models.py            Event, Detection dataclasses
│   ├── config.py            config loading + all defaults
│   ├── validator.py         startup config validation
│   ├── logger.py            async structured JSON logger (text prefixes)
│   │
│   ├── parsers.py           auth.log + tcpdump line parsers (sshd + sshd-session)
│   ├── log_sources.py       nginx, apache, mysql, ufw, syslog parsers
│   ├── sources.py           async log file tailers (tail -F)
│   │
│   ├── detector.py          stateful per-IP detection engine
│   ├── correlator.py        cross-source correlation rules (6 rules)
│   ├── ml_detector.py       ML anomaly detection (IsolationForest, auto-trains)
│   ├── threat_intel.py      AbuseIPDB + behavioral baseline
│   │
│   ├── blocker.py           iptables / ipset blocking backend
│   ├── honeypot.py          fake SSH server + 40-command shell simulation
│   ├── redis_sync.py        distributed blocklist via Redis pub/sub
│   │
│   ├── geoip.py             GeoIP (MaxMind offline + ip-api.com)
│   ├── assets.py            passive asset inventory
│   ├── fim.py               file integrity monitoring (files + directories)
│   │
│   ├── auth.py              JWT authentication (PyJWT or fallback)
│   ├── rbac.py              role-based access control (4 roles)
│   ├── dashboard.py         web dashboard + REST API + SSE feed (tabbed UI, SVG icons)
│   ├── metrics.py           Prometheus metrics
│   ├── grafana.py           Grafana dashboard template generator
│   ├── reporter.py          PDF / HTML compliance reports (SVG)
│   ├── notify.py            Telegram, Discord, Slack, webhook (plain text)
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
├── simulate.py              local test simulator (12 scenarios)
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
- [ ] WebSocket instead of SSE for bidirectional dashboard control
- [ ] `MarkdownV2` Telegram formatting for richer alerts
- [ ] Dashboard dark/light mode toggle

---

## Safety

> `--execute` flag modifies live firewall rules.

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

### v1.0.4 — Honeypot overhaul, FIM fix

**`honeypot.py` — Full shell simulation rewrite**
- Previous shell had ~12 hardcoded responses in a dict lookup. New implementation handles 40+ commands with real logic.
- Full fake Linux filesystem tree — `/etc`, `/root`, `/home`, `/var/log`, `/proc`, `/tmp` with realistic structure.
- 20+ fake file contents — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/hosts`, `/root/.bashrc`, `/root/.bash_history`, `/proc/cpuinfo`, `/var/log/auth.log` and more.
- Session-persistent virtual filesystem — `touch`, `mkdir`, `rm`, `cp`, `mv`, `echo "x" > file`, `echo "x" >> file` all work within the session.
- `ls` / `ls -la` shows real directory contents including session-created files.
- `cd` changes working directory and updates the shell prompt dynamically (`root@ubuntu-server:/etc$`).
- `cat` reads real fake file contents or session-created files; returns correct error for missing files.
- `wget` / `curl` simulate DNS timeout with realistic error messages after a delay.
- `sudo` shows password prompt for non-root users and logs credentials.
- `passwd` shows full password change dialog.
- `systemctl`, `apt`, `find`, `grep`, `wc`, `which`, `last`, `w`, `date` all added.
- Max commands per session increased from 200 to 500.

**`fim.py` — Directory scanning bug fixed**
- `_collect_paths()` used `os.path.isfile()` — directories like `/etc/ssh/` and `/var/www/` were silently skipped. Files created inside watched directories never triggered alerts. Fixed: directories now walked recursively with `os.walk()`.

**`notify.py`**
- All emoji removed from Telegram and Discord messages. Clean plain text labels used instead — more readable and avoids rendering issues.

**`logger.py` — new event types**
- All emoji console prefixes replaced with aligned text labels (`[ALERT]`, `[BLOCK]`, `[FIM]`, `[ML]`, etc.).
- Added prefixes for `ml_retrained`, `ml_error`, `fim_alert`, `honeypot_session_complete`, `redis_error`, `source_start`, `dashboard_started`.

**`reporter.py` — SVG added**
- HTML report: header and compliance checkmarks now use inline SVG icons.
- PDF report: all emoji replaced with plain text since reportlab cannot render emoji.

---

### v1.0.3 — Critical runtime fixes

**`parsers.py` — sshd-session regex mismatch (zero events on modern systems)**
Modern OpenSSH (Kali, Debian 12+, Ubuntu 24.04+) renamed the per-connection process from `sshd` to `sshd-session`. All three auth.log regexes only matched `sshd[PID]:` so no SSH events were detected at all on any modern system. Fixed: extracted shared `_SSHD_PREFIX = r"sshd(?:-session)?\[\d+\]:\s+"` and applied it to all three patterns.

**`config.py` — config file not auto-discovered**
Running without `--config` always loaded built-in defaults, silently ignoring any existing `/etc/cnsl/config.json`. Telegram tokens, thresholds, allowlist — all ignored. Fixed: `load_config()` now auto-discovers config from `/etc/cnsl/config.json` → `/etc/cnsl/config.yaml` → `./config.json` before falling back to defaults.

**Config: `allowlist` — `::1` blocked localhost SSH detection**
Default config had `::1` in allowlist. On Linux, `ssh localhost` connects via `::1` so brute-force tests from localhost were silently skipped. Removed `::1` from default allowlist. Also lowered default thresholds (`fails_threshold: 8→5`, `cooldown: 120→60s`) for faster detection feedback during testing.

---

### v1.0.2 — Bug Fixes & Dashboard Overhaul

**Critical Bug Fixes**

- `engine.py` — `ml_detector` and `fim_engine` were passed to `start_dashboard()` but the function signature didn't accept them — both were silently `None` inside the dashboard, causing ML and FIM to always show as disabled regardless of config. Fixed by adding `ml_detector` and `fim` parameters to the signature.
- `engine.py` — `engine_loop()` called `ml_detector.enabled` without a `None` guard — crashed with `AttributeError` when `ml_detector=None` (the default). Fixed: `if ml_detector and ml_detector.enabled`.
- `ml_detector.py` — `_retrain()` set `_last_train = now()` even when skipping due to insufficient samples. This prevented training from ever running because the interval check would never pass again. Fixed: only reset `_last_train` when actually attempting training.
- `ml_detector.py` — `_retrain()` exceptions were logged with only `str(e)` — no traceback. Fixed: full traceback now included in `ml_error` log entry.
- `fim.py` — `_collect_paths()` used `os.path.isfile()` to filter `watch_paths` — directories were silently skipped. Fixed: directories are now walked recursively with `os.walk()`.
- `dashboard.py` — `"low": 0` was hardcoded in `/api/stats` — LOW severity count was always zero. Fixed: reads from DB like HIGH and MEDIUM.
- `store.py` — `stats()` SQL query never counted LOW incidents. Fixed: added `SUM(CASE WHEN severity='LOW' ...)` to the query.

**New Dashboard Features**

- Tabbed UI — Overview / Incidents / Blocks / Honeypot / FIM / ML / Live Feed
- 8 stat cards including uptime, SSH fails total, events processed, all-time blocks
- ML tab — enabled/trained status, training progress bar, samples collected, last trained time
- Honeypot tab — session table with IP, duration, auth attempts, commands typed
- FIM tab — watched paths list and file integrity alert table
- Manual block form — type IP and press Enter or click Block IP
- Live feed enhancements — ML anomaly, FIM change, and honeypot session events
- Export PDF — full security report generated from live API data, printed via browser
- SVG icons throughout — no emoji dependency
- `/api/timeline` endpoint — incident counts per hour for last 24h chart
- `/api/ml-status` endpoint — ML training state
- `/api/honeypot` endpoint — honeypot sessions
- `/api/fim` endpoint — FIM alerts and watched paths
- `/api/system` endpoint — uptime, SSH fails, events processed, blocks total
- `/api/debug` endpoint — module wiring status for diagnostics

**Notify Fix**

- `notify.py` — Telegram Markdown v1 broke silently when ISP names, city names, or detection reason strings contained `_`, `*`, `` ` ``, or `[`. Fixed: `_tg_escape()` helper applied to all dynamic fields.

**Config Notes**

- `honeypot` config key: use `honeypot_port` (not `ports`).
- `fim.db_path` and `store.db_path` should be absolute paths to avoid baseline resets on restart.
- Remove `::1` from `allowlist` if you want localhost SSH to be detected.
- Always run with the virtualenv Python (`venv/bin/python`) to ensure `scikit-learn` is available under `sudo`.

**Simulator**

- Added `scenario_notify` (Scenario 12) — validates the full notification pipeline.
- `setup()` now returns `notifier`.
- Added `notify` to `SCENARIO_MAP`.

---

### v1.0.1 — Bug Fixes

**Critical**
- `engine_loop()` — `ml_detector` was used but never passed as a parameter — `NameError` crash on the very first event
- `start_dashboard()` — missing `rbac`, `assets`, `honeypot` parameters caused a `TypeError` at startup; dashboard never launched
- `engine.py` — `blocker.store` assigned before `store` was initialised — `UnboundLocalError` on startup

**Security**
- `/api/metrics` — now requires authentication (was publicly accessible)
- `/api/block` and `/api/unblock` — RBAC now enforced; `viewer` role can no longer perform write actions
- `/api/block` — IP address format validated before any iptables action
- `/api/incidents` — `?limit` parameter safely parsed and clamped to 1–500

**Logic**
- `metrics.dec_block()` — Prometheus `cnsl_blocks_active` gauge now decrements on unblock
- `store.remove_block()` — unblock now removes entry from SQLite
- Redis cluster sync — `publish_unblock()` now called on unblock
- Redis `subscribe_loop()` — `action == "unblock"` messages now handled
- `--no-geoip` / `--no-db` — config-file path was ignored; only CLI flag worked

**Performance**
- `fim._scan()` — all SQLite calls now run via `loop.run_in_executor()`

**Resource Leaks**
- `sources.py` and `log_sources.py` — subprocesses now always killed in a `finally` block

**Simulator**
- Added 7 new scenarios
- Wired `metrics`, `store`, and `correlator` into simulator setup

### v1.0.0 — Initial Release



## If CNSL helped you

⭐ Star this repo — it helps others find the project  
☕ [Buy me a coffee](https://ko-fi.com/rahadbhuiya)

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Made with by <a href="https://github.com/rahadbhuiya">Rahad Bhuiya</a>

</div>
