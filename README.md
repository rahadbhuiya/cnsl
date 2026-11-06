<div align="center">

# CNSL

### Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/cnsl"><img src="https://img.shields.io/pypi/v/cnsl" alt="PyPI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
</p>

**Correlated log analysis and automated IP blocking for Linux servers.**  
Connects auth, web, database, and system events to detect coordinated attacks in real time.

</div>

---

## What it does

Most tools watch one log and count failures. CNSL watches multiple log streams simultaneously.

When an attacker scans your web server, probes your database, then tries SSH with stolen credentials -- CNSL correlates the activity from that IP and responds before the breach completes:

```
Web scan      from 45.33.32.1  --+
SSH brute     from 45.33.32.1  --+--->  HIGH alert + auto-block
DB auth fail  from 45.33.32.1  --+
```

It tracks attacker progression, learns recurrent attack patterns, and can share threat intelligence across multiple servers.

Includes a local web dashboard, dynamic iptables/ipset blocking, attacker fingerprinting, opt-in predictive blocking, multi-node federation, and integrations for Kubernetes, Wazuh, STIX/TAXII, Redis, and common SIEM forwarders.
---

## Quick start

```bash
pip install cnsl[full]
sudo python -m cnsl --dashboard --no-tcpdump
# Open http://127.0.0.1:8765
# Default login: admin / cnsl-change-me
```

Or from source:

```bash
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl
python3 -m venv venv && source venv/bin/activate
pip install -e ".[full]"
sudo venv/bin/python -m cnsl --dashboard --no-tcpdump
```

> Start in dry-run mode (default) -- no real blocks until you add `--execute`.

Or on Kubernetes (one DaemonSet pod per node, protecting every node in the cluster):

```bash
helm install cnsl ./helm/cnsl --namespace cnsl --create-namespace
```

See [`docs/kubernetes.md`](docs/kubernetes.md) and [`helm/cnsl/README.md`](helm/cnsl/README.md) for the full walkthrough (federation, the multi-node hub view, enabling real blocking).

---

## Dashboard

Enable with `--dashboard`. Runs at `http://127.0.0.1:8765`.

Tabs: Overview, Incidents, Blocks, Live Feed, Kill Chain, Graph, Correlation, Hub, Campaigns, Cases, UEBA, ML, Honeypot, FIM, Rules, Rate Limit, Settings.

For remote access use an SSH tunnel:
```bash
ssh -L 8765:127.0.0.1:8765 user@yourserver
```

---

## Configuration

**Fastest path -- the setup wizard (under 5 minutes):**

```bash
sudo python -m cnsl --init
```

Asks a handful of questions (allowlist IP, dashboard on/off, notification channels), auto-detects which log files actually exist on this machine (nginx, apache, mysql, ufw, syslog, `auth.log` vs `secure`), and writes a working, validated `config.json` -- you don't need to read or understand the full reference config to get running.

**Full reference**, once you want to turn on optional features (Sigma rules, OIDC SSO, cloud identity, ATT&CK mapping, retention, case SLA, ...) -- all ~30 sections are documented individually in [`docs/configuration.md`](docs/configuration.md) and default to off/sensible, so nothing there is required reading up front:

```bash
cp config/config.example.json /etc/cnsl/config.json
```

Key sections: `thresholds`, `actions`, `dashboard`, `notifications`, `redis`, `cloud_identity`, `zero_trust`, `siem`, `federation`.

---

## Documentation

### Core Guides
- [Installation](docs/installation.md) -- Standalone, systemd service, and Docker setup
- [Configuration](docs/configuration.md) -- Reference for config.json options and thresholds
- [Architecture](docs/architecture.md) -- Engine pipeline and module layout
- [API Reference](docs/api.md) -- REST API endpoints and data models

### Detection & Rules
- [Rules & Tuning](docs/rules.md) -- Built-in detection logic and custom overrides
- [Attack Kill Chain](docs/kill-chain.md) -- Progression stages and predictive blocking
- [Pattern Learning](docs/pattern-learning.md) -- Auto-discovered signatures from traffic
- [Threat Feed & FIM](docs/threat-feed.md) -- Ingesting external feeds and file integrity checks

### Integrations & Deployment
- [Kubernetes & Helm](docs/kubernetes.md) -- DaemonSet and cluster deployment
- [Multi-Node Federation](docs/federation.md) -- Sharing state across server clusters
- [SIEM & Webhooks](docs/siem-connectors.md) -- Forwarding alerts to external platforms
- [Changelog](docs/changelog.md) -- Release notes and version history

*(Browse all 33 guides in [`docs/`](docs/))*

---

## Requirements

- Linux (Ubuntu 20.04+ / Debian 11+ / RHEL 8+)
- Python 3.10+
- Root or `CAP_NET_ADMIN` for iptables blocking

Optional: Redis (distributed blocklist + federation), MaxMind GeoIP database.

---

## License

MIT. See [LICENSE](LICENSE).