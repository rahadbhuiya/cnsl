<div align="center">

# CNSL

### Correlated Network Security Layer

<p>
  <a href="https://github.com/rahadbhuiya/cnsl/actions"><img src="https://github.com/rahadbhuiya/cnsl/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/cnsl"><img src="https://img.shields.io/pypi/v/cnsl" alt="PyPI"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
</p>

**A self-hosted SIEM for Linux.**  
Detects attacks that span SSH, web, database, and cloud logs simultaneously -- then blocks them automatically.

</div>

---

## What it does

Most tools watch one log and count failures. CNSL watches everything at once.

When an attacker scans your web server, probes your database, then tries SSH with stolen credentials -- CNSL sees all three as one coordinated attack and responds before the breach completes.

```
Web scan      from 45.33.32.1  --+
SSH brute     from 45.33.32.1  --+--->  HIGH alert + auto-block
DB auth fail  from 45.33.32.1  --+
```

It also tracks how far each attacker has progressed through the kill chain, learns new attack patterns automatically, and shares threat intelligence across multiple servers in real time.

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

---

## Dashboard

Enable with `--dashboard`. Runs at `http://127.0.0.1:8765`.

Tabs: Overview, Incidents, Blocks, Live Feed, Kill Chain, Graph, Cases, UEBA, ML, Honeypot, FIM, Rules, Rate Limit, Settings.

For remote access use an SSH tunnel:
```bash
ssh -L 8765:127.0.0.1:8765 user@yourserver
```

---

## Configuration

Copy and edit the example config:

```bash
cp config/config.example.json /etc/cnsl/config.json
```

All options are documented in [`docs/configuration.md`](docs/configuration.md).  
Key sections: `thresholds`, `actions`, `dashboard`, `notifications`, `redis`, `cloud_identity`, `zero_trust`, `siem`, `federation`.

---

## Documentation

| Document | What it covers |
|:---|:---|
| [`docs/installation.md`](docs/installation.md) | Full install, systemd, Docker |
| [`docs/configuration.md`](docs/configuration.md) | Every config option explained |
| [`docs/features.md`](docs/features.md) | Complete feature list |
| [`docs/architecture.md`](docs/architecture.md) | Module structure and design |
| [`docs/kill-chain.md`](docs/kill-chain.md) | Kill chain tracker |
| [`docs/federation.md`](docs/federation.md) | Multi-node setup |
| [`docs/cloud-identity.md`](docs/cloud-identity.md) | AWS + Azure AD integration |
| [`docs/zero-trust.md`](docs/zero-trust.md) | Trust score engine |
| [`docs/siem-connectors.md`](docs/siem-connectors.md) | Splunk, Sentinel, Webhook push |
| [`docs/pattern-learning.md`](docs/pattern-learning.md) | Automated rule discovery |
| [`docs/api.md`](docs/api.md) | Full REST API reference |
| [`docs/changelog.md`](docs/changelog.md) | Version history |

---

## Requirements

- Linux (Ubuntu 20.04+ / Debian 11+ / RHEL 8+)
- Python 3.10+
- Root or `CAP_NET_ADMIN` for iptables blocking

Optional: Redis (distributed blocklist + federation), MaxMind GeoIP database.

---

## License

MIT. See [LICENSE](LICENSE).