# CNSL Guard — Cyber Network Security Layer

[![CI](https://github.com/YOUR_USERNAME/cnsl/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/cnsl/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-26%20passing-brightgreen)]()
[![Dry-run safe](https://img.shields.io/badge/default-dry--run%20safe-blue)]()

**CNSL Guard** is an open-source, production-grade **SSH brute-force and intent-drift detection engine** for Linux servers.

It watches your `auth.log` in real-time, detects attack patterns using stateful per-IP analysis, automatically blocks attackers via `iptables` or `ipset`, sends alerts to Telegram/Discord/Slack, and shows everything in a live web dashboard.

---

## Features

| Feature | Details |
|---|---|
| **Real-time detection** | Tails `auth.log` live — reacts in milliseconds |
| **3 detection rules** | Brute-force, credential-stuffing, credential-breach |
| **Per-IP stateful tracking** | Sliding time window, separate state per attacker IP |
| **Auto-block** | `iptables` or `ipset` (faster for high volume) |
| **Auto-unblock** | Temporary blocks expire automatically (default: 15 min) |
| **GeoIP enrichment** | Country, city, ISP, proxy/datacenter detection — no API key needed |
| **Notifications** | Telegram, Discord, Slack, custom webhook |
| **Live web dashboard** | Real-time charts, blocked IPs, top attackers, incident log |
| **SQLite persistence** | Incident history survives restarts |
| **Prometheus metrics** | `/api/metrics` endpoint — plug into Grafana |
| **Allowlist** | Your own IPs are never blocked |
| **Dry-run mode** | Default: plans only, no real commands — safe to try |
| **JSON structured logging** | Every event to `.jsonl` — ingest with Loki, Elastic, Splunk |
| **tcpdump hints** | Optional secondary signal: ARP, SMB, mDNS |
| **Zero mandatory dependencies** | Pure stdlib core; all extras are optional |
| **Docker ready** | Dockerfile included |

---

## Detection Rules

| Rule | What it means | Severity |
|---|---|---|
| **Brute-force** | >= 8 failed logins from one IP within 60 seconds | MEDIUM |
| **Credential stuffing** | >= 4 distinct usernames tried from one IP | MEDIUM |
| **Credential breach** | SSH success after >= 5 recent failures — likely stolen password | **HIGH** -> auto-block |

All thresholds are configurable in `config.json`.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/cnsl.git
cd cnsl

# 2. Install
pip install -e ".[full]"

# 3. Run (safe dry-run — no real blocks)
sudo python -m cnsl

# 4. Open web dashboard
sudo python -m cnsl --dashboard
# Browser: http://127.0.0.1:8765

# 5. Enable real blocking when ready
sudo python -m cnsl --execute --dashboard
```

> `sudo` is required for `/var/log/auth.log`, `iptables`, and `tcpdump`.

---

## Installation

```bash
pip install -e .                 # core only (stdlib, no external deps)
pip install -e ".[full]"         # everything recommended
pip install -e ".[dev]"          # + testing tools
```

| Extra | Installs | Needed for |
|---|---|---|
| `full` | aiohttp, aiosqlite, pyyaml | dashboard, database, YAML config |
| `notify` | aiohttp | Telegram/Discord/Slack alerts |
| `db` | aiosqlite | SQLite persistence |
| `yaml` | pyyaml | YAML config file support |
| `dev` | pytest + all above | running tests |

### Via pip (once published to PyPI)

```bash
pip install cnsl-guard
```

---

## Usage

```
sudo python -m cnsl [options]

Options:
  --config FILE      Config file path (.json or .yaml)
  --iface IFACE      Network interface for tcpdump  (default: any)
  --authlog PATH     Auth log path  (default: /var/log/auth.log)
  --execute          Enable real blocking  (default: dry-run)
  --backend BACKEND  iptables or ipset  (default: iptables)
  --dashboard        Enable web dashboard at http://127.0.0.1:8765
  --no-tcpdump       Disable tcpdump — auth.log only
  --no-geoip         Disable GeoIP lookups
  --no-db            Disable SQLite persistence
  --version          Show version
```

### Common examples

```bash
# Ubuntu/Debian
sudo python -m cnsl --dashboard

# CentOS / RHEL / Fedora
sudo python -m cnsl --authlog /var/log/secure --dashboard

# ipset backend (faster for production)
sudo python -m cnsl --execute --backend ipset --dashboard

# Auth.log only, lower CPU
sudo python -m cnsl --no-tcpdump

# Custom config
sudo python -m cnsl --config /etc/cnsl/config.json --execute --dashboard
```

---

## Configuration

```bash
sudo mkdir -p /etc/cnsl
sudo cp config/config.example.json /etc/cnsl/config.json
sudo nano /etc/cnsl/config.json
```

**Minimum to change:**

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

Full config reference: [`config/config.example.json`](config/config.example.json)

---

## Notifications

```json
"notifications": {
  "min_severity": "MEDIUM",

  "telegram": {
    "enabled": true,
    "bot_token": "123456:ABC...",
    "chat_id": "-1001234567890"
  },

  "discord": {
    "enabled": true,
    "webhook_url": "https://discord.com/api/webhooks/..."
  },

  "slack": {
    "enabled": true,
    "webhook_url": "https://hooks.slack.com/services/..."
  }
}
```

**Telegram bot setup:**
1. Open Telegram -> search `@BotFather`
2. Send `/newbot` -> follow the steps -> copy the token
3. Add the bot to your group
4. Get your `chat_id`: `https://api.telegram.org/bot<TOKEN>/getUpdates`

---

## Web Dashboard

```bash
sudo python -m cnsl --dashboard
# Open: http://127.0.0.1:8765
```

- Live stat cards — total incidents, HIGH alerts, active blocks, unique attackers
- Charts — incidents over time, severity breakdown  
- Active blocks table — with one-click manual unblock
- Top attackers — with country, city, ISP
- Recent incidents log
- Live event feed — every SSH fail/success via SSE

> Dashboard binds to `127.0.0.1` only. Use SSH tunnel or nginx + auth for remote access.

---

## REST API

Available when dashboard is enabled:

```bash
curl http://127.0.0.1:8765/health            # liveness probe
curl http://127.0.0.1:8765/api/stats         # engine summary
curl http://127.0.0.1:8765/api/incidents     # recent incidents
curl http://127.0.0.1:8765/api/blocks        # active blocks
curl http://127.0.0.1:8765/api/top-attackers # top IPs
curl http://127.0.0.1:8765/api/metrics       # Prometheus metrics

# Manual block
curl -X POST http://127.0.0.1:8765/api/block \
  -H 'Content-Type: application/json' -d '{"ip": "1.2.3.4"}'

# Manual unblock
curl -X POST http://127.0.0.1:8765/api/unblock \
  -H 'Content-Type: application/json' -d '{"ip": "1.2.3.4"}'
```

---

## JSON Log Format

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
    "unique_users": 2,
    "geo": {
      "country": "China", "city": "Beijing",
      "isp": "China Telecom", "flag": "CN",
      "proxy": false, "hosting": true
    }
  }
}
```

```bash
# Live view
tail -f cnsl_guard.jsonl | jq .

# Filter HIGH only
tail -f cnsl_guard.jsonl | jq 'select(.type=="incident" and .payload.severity=="HIGH")'
```

Compatible with: Grafana Loki, Elasticsearch, Splunk, Vector, Fluentd, Datadog.

---

## Prometheus / Grafana

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: cnsl
    static_configs:
      - targets: ['localhost:8765']
    metrics_path: /api/metrics
```

Metrics: `cnsl_incidents_total{severity}`, `cnsl_blocks_active`, `cnsl_blocks_total`,
`cnsl_ssh_fails_total`, `cnsl_ip_fails_total{ip,country}`

---

## Docker

```bash
docker build -t cnsl-guard .

docker run --rm \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --network host \
  -v /var/log:/var/log:ro \
  -v /etc/cnsl:/etc/cnsl:ro \
  cnsl-guard --config /etc/cnsl/config.json --execute --dashboard
```

---

## systemd Service

```bash
sudo nano /etc/systemd/system/cnsl.service
```

```ini
[Unit]
Description=CNSL Guard — SSH Intrusion Detection
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
|
+-- cnsl/                     <- Python package
|   +-- __init__.py           <- package version info
|   +-- __main__.py           <- enables: python -m cnsl
|   +-- models.py             <- Event, Detection dataclasses
|   +-- config.py             <- config loading + all defaults
|   +-- logger.py             <- async structured JSON logger
|   +-- parsers.py            <- auth.log + tcpdump parsers
|   +-- detector.py           <- stateful per-IP detection engine
|   +-- blocker.py            <- iptables / ipset blocking backend
|   +-- sources.py            <- async log tailers (auto-restart)
|   +-- geoip.py              <- GeoIP lookup + in-memory cache
|   +-- notify.py             <- Telegram, Discord, Slack, webhook
|   +-- store.py              <- SQLite persistent state
|   +-- metrics.py            <- Prometheus metrics counters
|   +-- dashboard.py          <- web dashboard + REST API + SSE
|   +-- api.py                <- standalone REST API (legacy)
|   +-- engine.py             <- main loop + CLI entrypoint
|
+-- tests/
|   +-- test_cnsl.py          <- 26 unit tests
|
+-- config/
|   +-- config.example.json   <- full config reference
|
+-- .github/
|   +-- workflows/
|       +-- ci.yml            <- GitHub Actions CI (Python 3.10-3.12)
|
+-- Dockerfile
+-- setup.py
+-- requirements.txt
+-- LICENSE
+-- README.md
```

---

## Auth Log Path by OS

| OS | Path | Flag |
|---|---|---|
| Ubuntu / Debian | `/var/log/auth.log` | *(default)* |
| CentOS / RHEL / Fedora | `/var/log/secure` | `--authlog /var/log/secure` |
| OpenSUSE | `/var/log/messages` | `--authlog /var/log/messages` |

---

## Roadmap

- [ ] Country-based blocking (`block_countries: ["CN", "RU"]`)
- [ ] AbuseIPDB integration — community threat intelligence
- [ ] Repeat offender memory — lower threshold for known bad IPs
- [ ] Distributed mode — multiple servers share blocklist via Redis
- [ ] Honeypot port detection — instant block on Telnet/RDP probes
- [ ] Grafana dashboard JSON template
- [ ] Web UI authentication (JWT / Basic Auth)
- [ ] Email notifications (SMTP)
- [ ] Zeek log ingestion

---

## Contributing

1. Fork the repo and create a feature branch
2. Add tests in `tests/test_cnsl.py`
3. Run `pytest tests/ -v` — all 26 must pass
4. Submit a pull request

Code style: type hints everywhere, docstrings on all public functions, no external dependencies in the core package.

---

## Safety Warning

`--execute` modifies firewall rules. Before enabling:

- Add your management IP to `allowlist` in config
- Test in dry-run mode first (this is the default)
- Ensure you have console/out-of-band server access
- The authors are not responsible for accidental lockouts

---

## License

MIT — see [LICENSE](LICENSE).