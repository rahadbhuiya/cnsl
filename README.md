# CNSL — Correlated Network Security Layer

[![CI](https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg)](https://github.com/rahadbhuiya/cnsl/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-26%20passing-brightgreen)]()

> **A pre-SIEM, intent-aware security layer for Linux servers.**
> Correlates SSH, web, database, and firewall signals to detect attacks
> that no single log source can see alone.

---

## What makes CNSL different

Most tools (Fail2ban, SSHGuard) count failures from one log.
CNSL **correlates across sources**:

```
Web scan from 1.2.3.4   ─┐
SSH brute-force from 1.2.3.4  ─┼─► HIGH alert: coordinated attack
DB auth failure from 1.2.3.4 ─┘
```

It also detects what others miss:
- **Credential breach** — SSH success after many failures (stolen password)
- **Honeypot port probe** — any hit on port 23/3389/6379 → instant block
- **Privilege escalation** — sudo failure after SSH login
- **File tampering** — `/etc/passwd`, `authorized_keys`, crontab changes
- **Behavioral anomaly** — login at unusual hour, new username, frequency spike

---

## Features

| Category | Feature |
|---|---|
| **Detection** | SSH brute-force, credential stuffing, credential breach |
| **Detection** | Web scanner detection (nikto, sqlmap, gobuster UA) |
| **Detection** | Web exploit path detection (`/wp-admin`, `/.env`, `/phpmyadmin`) |
| **Detection** | Database brute-force (MySQL auth failures) |
| **Detection** | Firewall honeypot port detection |
| **Detection** | Privilege escalation (sudo/su failure after login) |
| **Correlation** | 6 cross-source rules (web+SSH, multi-service, honeypot+SSH, etc.) |
| **Response** | iptables / ipset auto-block with auto-unblock timer |
| **Response** | Honeypot redirect — attacker hits fake SSH shell |
| **Response** | Redis distributed blocklist — share blocks across servers |
| **Intelligence** | GeoIP enrichment (MaxMind offline or ip-api.com) |
| **Intelligence** | AbuseIPDB threat intelligence |
| **Intelligence** | Behavioral baseline per IP |
| **Intelligence** | ML anomaly detection (IsolationForest) |
| **Monitoring** | File Integrity Monitoring (FIM) |
| **Monitoring** | Asset inventory (passive network discovery) |
| **Visibility** | Live web dashboard with SSE real-time feed |
| **Visibility** | Prometheus metrics + Grafana dashboard template |
| **Reporting** | PDF/HTML compliance reports (SOC2, ISO27001, PCI-DSS) |
| **Access** | JWT authentication + Role-Based Access Control (4 roles) |
| **Persistence** | SQLite incident history, FIM baseline |
| **Notifications** | Telegram, Discord, Slack, custom webhook |
| **Ops** | Dry-run safe by default, systemd ready, Docker ready |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl

# 2. Install
pip install -e ".[full]"

# 3. Run (dry-run — safe, no real blocks)
sudo python -m cnsl

# 4. Run with dashboard
sudo python -m cnsl --dashboard
# Open browser: http://127.0.0.1:8765

# 5. Enable real blocking when ready
sudo python -m cnsl --execute --dashboard
```

> `sudo` is required for `/var/log/auth.log`, `iptables`, and `tcpdump`.

---

## Installation

```bash
pip install -e .               # core only (stdlib, no external deps)
pip install -e ".[full]"       # everything recommended
pip install -e ".[dev]"        # + testing tools
```

| Extra | Installs | Needed for |
|---|---|---|
| `full` | aiohttp, aiosqlite, pyyaml, bcrypt, sklearn, numpy, reportlab | dashboard, DB, YAML, auth, ML, PDF |
| `auth` | bcrypt, PyJWT | dashboard login |
| `db` | aiosqlite | SQLite persistence |
| `geoip` | geoip2 | MaxMind offline GeoIP |
| `ml` | scikit-learn, numpy | ML anomaly detection |
| `reports` | reportlab | PDF compliance reports |
| `dev` | pytest + all above | running tests |

---

## Usage

```
sudo python -m cnsl [options]

Core options:
  --config FILE        Config file path (.json or .yaml)
  --authlog PATH       Auth log path  (default: /var/log/auth.log)
  --iface IFACE        Network interface for tcpdump  (default: any)
  --execute            Enable real blocking  (default: dry-run)
  --backend BACKEND    iptables or ipset  (default: iptables)

Features:
  --dashboard          Enable web dashboard at http://127.0.0.1:8765
  --no-tcpdump         Auth.log only (lower CPU)
  --no-geoip           Disable GeoIP lookups
  --no-db              Disable SQLite persistence

Reports:
  --report FORMAT      Generate report and exit (html|pdf|json)
  --report-days N      Report period in days (default: 30)
  --grafana-export     Export Grafana dashboard JSON and exit
```

### OS-specific auth log paths

| OS | Path | Flag |
|---|---|---|
| Ubuntu / Debian | `/var/log/auth.log` | *(default)* |
| CentOS / RHEL / Fedora | `/var/log/secure` | `--authlog /var/log/secure` |
| OpenSUSE | `/var/log/messages` | `--authlog /var/log/messages` |

---

## How to run (step by step)

### Step 1 — Minimal run (auth.log only, dry-run)

No config needed. Safe to run immediately:

```bash
sudo python -m cnsl --no-tcpdump
```

Watch the console. Every SSH event appears in real time.

---

### Step 2 — With dashboard

```bash
sudo python -m cnsl --dashboard --no-tcpdump
```

Open `http://127.0.0.1:8765` in browser.
Default login: `admin` / `cnsl-change-me`

---

### Step 3 — Create a config file

```bash
sudo mkdir -p /etc/cnsl
sudo cp config/config.example.json /etc/cnsl/config.json
sudo nano /etc/cnsl/config.json
```

**Minimum changes:**

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

> Add your own IP to `allowlist` **before** enabling `dry_run: false`.

---

### Step 4 — Enable live blocking

```bash
sudo python -m cnsl \
  --config /etc/cnsl/config.json \
  --execute \
  --dashboard
```

---

### Step 5 — Enable multi-log sources (optional)

Add to config.json:

```json
"log_sources": {
  "nginx":  "/var/log/nginx/access.log",
  "mysql":  "/var/log/mysql/error.log",
  "ufw":    "/var/log/ufw.log",
  "syslog": "/var/log/syslog"
}
```

---

### Step 6 — Enable FIM (optional)

```json
"fim": {
  "enabled": true,
  "scan_interval_sec": 300
}
```

CNSL will watch `/etc/passwd`, `authorized_keys`, `sshd_config`, crontab etc.

---

### Step 7 — Enable ML anomaly detection (optional)

```json
"ml": {
  "enabled": true,
  "min_samples": 100
}
```

Collects samples for a while, then starts flagging statistical outliers.

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

Get bot token from `@BotFather` on Telegram.

---

### Step 9 — Run as systemd service

```bash
sudo nano /etc/systemd/system/cnsl.service
```

```ini
[Unit]
Description=CNSL — Correlated Network Security Layer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cnsl --config /etc/cnsl/config.json --execute --dashboard
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cnsl
sudo journalctl -u cnsl -f
```

---

## Test without a real server

```bash
# Run all scenarios (brute-force, breach, stuffing, allowlist)
python simulate.py

# Interactive mode — type events manually
python simulate.py live
```

```
cnsl> fail 1.2.3.4 root     # fake SSH failure
cnsl> fail 1.2.3.4 admin
cnsl> fail 1.2.3.4 ubuntu
cnsl> ok   1.2.3.4 root     # fake success → HIGH breach alert
cnsl> status                 # show tracked IPs
cnsl> blocks                 # show active blocks
```

---

## Dashboard

Enable with `--dashboard` flag:

```
http://127.0.0.1:8765
```

| Section | What it shows |
|---|---|
| Stat cards | Total incidents, HIGH severity, active blocks, unique attackers |
| Charts | Incidents over time, severity breakdown |
| Active blocks | Currently blocked IPs with one-click unblock |
| Top attackers | IP, country, ISP, incident count |
| Recent incidents | Time, IP, location, severity, reason |
| Live feed | Every SSH event streamed in real time (SSE) |

> Dashboard binds to `127.0.0.1` only. Use SSH tunnel for remote access:
> `ssh -L 8765:127.0.0.1:8765 user@yourserver`

---

## Dashboard authentication

Enable in config:

```json
"auth": {
  "enabled": true,
  "secret_key": "run: python -c \"import secrets; print(secrets.token_hex(32))\""
}
```

Default credentials: `admin` / `cnsl-change-me` — change in production.

### Roles

| Role | Can do |
|---|---|
| `viewer` | Read stats, incidents, blocks, metrics |
| `analyst` | viewer + manual block/unblock (enforced — `viewer` cannot block) |
| `auditor` | analyst + generate reports + view assets |
| `admin` | Everything including config and honeypot management |

> **Note:** RBAC is enforced on all write endpoints. Manual block/unblock via the dashboard validates IP format and requires `analyst` role or above.

---

## Honeypot mode (optional)

Instead of blocking attackers, redirect them to a fake SSH server:

```json
"honeypot": {
  "enabled": true,
  "mode": "redirect",
  "honeypot_port": 2222
}
```

The attacker connects to what looks like a real Ubuntu server, types commands, and everything they do is logged. They never actually run anything.

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
# Generate HTML report (last 30 days)
python -m cnsl --report html --report-days 30

# Generate PDF report
python -m cnsl --report pdf

# Export Grafana dashboard JSON
python -m cnsl --grafana-export
```

Reports include: incident summary, top attackers, FIM alerts, SOC2/ISO27001/PCI-DSS compliance mapping.

---

## Grafana

```bash
# Export dashboard JSON
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

> **Note:** `/api/metrics` requires authentication. Generate a token via `POST /api/login` and add it as a Bearer token. If auth is disabled in config, no token is needed.

---

## REST API

When dashboard is enabled:

```bash
GET  /api/stats            # engine summary
GET  /api/incidents        # recent incidents
GET  /api/blocks           # active blocks
GET  /api/top-attackers    # top attacker IPs
GET  /api/assets           # network asset inventory
GET  /api/assets/summary   # trust level breakdown
GET  /api/metrics          # Prometheus metrics
GET  /api/rbac/roles       # role/permission info
GET  /api/honeypot/status  # honeypot status

POST /api/block            # {"ip": "1.2.3.4"}
POST /api/unblock          # {"ip": "1.2.3.4"}
POST /api/report           # {"format": "html", "days": 30}
POST /api/login            # {"username": "...", "password": "..."}
POST /api/logout
```

---

## JSON log format

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
    "geo": { "country": "China", "city": "Beijing", "flag": "CN" }
  }
}
```

```bash
# Live view
tail -f cnsl.jsonl | jq .

# HIGH incidents only
tail -f cnsl.jsonl | jq 'select(.type=="incident" and .payload.severity=="HIGH")'
```

Compatible with: Grafana Loki, Elasticsearch, Splunk, Vector, Fluentd, Datadog.

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

## Project structure

```
cnsl/
├── cnsl/
│   ├── __init__.py        package version info
│   ├── __main__.py        python -m cnsl entrypoint
│   │
│   ├── models.py          Event, Detection dataclasses
│   ├── config.py          config loading + all defaults
│   ├── validator.py       startup config validation
│   ├── logger.py          async structured JSON logger
│   │
│   ├── parsers.py         auth.log + tcpdump parsers
│   ├── log_sources.py     nginx, apache, mysql, ufw, syslog parsers
│   ├── sources.py         async log file tailers
│   │
│   ├── detector.py        stateful per-IP detection engine
│   ├── correlator.py      cross-source correlation rules (6 rules)
│   ├── ml_detector.py     ML anomaly detection (IsolationForest)
│   ├── threat_intel.py    AbuseIPDB + behavioral baseline
│   │
│   ├── blocker.py         iptables / ipset blocking backend
│   ├── honeypot.py        fake SSH server + active response
│   ├── redis_sync.py      distributed blocklist via Redis
│   │
│   ├── geoip.py           GeoIP (MaxMind offline + ip-api.com)
│   ├── assets.py          passive asset inventory
│   ├── fim.py             file integrity monitoring
│   │
│   ├── auth.py            JWT authentication
│   ├── rbac.py            role-based access control (4 roles)
│   ├── dashboard.py       web dashboard + REST API + SSE
│   ├── metrics.py         Prometheus metrics
│   ├── grafana.py         Grafana dashboard template generator
│   ├── reporter.py        PDF/HTML compliance reports
│   ├── notify.py          Telegram, Discord, Slack, webhook
│   ├── store.py           SQLite persistence
│   └── engine.py          main loop + CLI
│
├── tests/
│   └── test_cnsl.py       26 unit tests
│
├── config/
│   └── config.example.json
│
├── .github/workflows/ci.yml
├── simulate.py            local test simulator
├── Dockerfile
├── setup.py
├── requirements.txt
└── README.md
```

---

## Roadmap

- [ ] Country-based blocking (`block_countries: ["CN", "RU"]`)
- [ ] Community threat feed (opt-in shared blocklist)
- [ ] Kafka support for high-volume environments
- [ ] Multi-tenant support
- [ ] Web UI auth hardening (2FA, session management)
- [ ] Zeek log ingestion (richer network signals)
- [ ] Email notifications (SMTP)
- [ ] Grafana alerting rules template

---

## Safety

`--execute` modifies firewall rules. Before enabling:

1. Add your management IP to `allowlist` in config
2. Test in dry-run mode first (this is the default)
3. Have console / out-of-band access to the server
4. The authors are not responsible for accidental lockouts

---

## Contributing

1. Fork and create a feature branch
2. Add tests in `tests/test_cnsl.py`
3. Run `pytest tests/ -v` — all 26 must pass
4. Submit a pull request

Code style: type hints, docstrings on all public functions, no external dependencies in core.

---

## Changelog

### v1.0.1 — Bug fixes

**Critical fixes:**
- `engine_loop()` — `ml_detector` was used but never passed as a parameter (`NameError` on first event)
- `start_dashboard()` — missing `rbac`, `assets`, `honeypot` parameters caused `TypeError` on startup; dashboard never launched

**Security fixes:**
- `/api/metrics` — now requires authentication (was publicly accessible)
- `/api/block` and `/api/unblock` — RBAC now enforced; `viewer` role can no longer block/unblock
- `/api/block` — IP address format is now validated before acting
- `/api/incidents` — `?limit` parameter is now safely parsed and clamped (1–500); invalid values no longer crash the endpoint

**Logic fixes:**
- `metrics.dec_block()` — was defined but never called; `cnsl_blocks_active` Prometheus gauge now decrements correctly on unblock
- `store.remove_block()` — manual/auto unblock now removes the entry from SQLite; dashboard block count was previously stale
- Redis cluster sync — `publish_unblock()` was never called; unblock events now propagate to all cluster nodes
- Redis `subscribe_loop()` — `action == "unblock"` messages were silently dropped; now handled via `on_remote_unblock` callback
- `--no-geoip` / `--no-db` CLI flags — only checked `args`, not `cfg["_no_geoip"]`/`cfg["_no_db"]`; config-file path now works correctly

**Performance fixes:**
- `ml_detector._retrain()` — `_last_train` was only updated on successful training; if `min_samples` not yet reached, retrain was attempted on every single event
- `fim._scan()` — all SQLite calls (`all_baselines`, `upsert_baseline`, `delete_baseline`, `save_alert`) now run via `loop.run_in_executor()` to avoid blocking the async event loop

**Resource leak fixes:**
- `sources.py` (`tail_authlog`, `run_tcpdump`) and `log_sources.py` (`tail_log_file`) — `tail`/`tcpdump` subprocesses were never killed on EOF or exception; each reconnect spawned a new zombie process. Now always killed in a `finally` block.

**Concurrency fix:**
- `AbuseIPDB.check()` — concurrent calls could both slip through the rate-limit gap simultaneously, firing multiple HTTP requests. Now serialized with `asyncio.Lock` and double-checked cache pattern.

---

## License

MIT — see [LICENSE](LICENSE).