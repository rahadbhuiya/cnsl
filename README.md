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

**Beyond core detection:** multi-node federation with a unified hub view, STIX 2.1 export and a built-in TAXII 2.1 server for sharing IOCs, Wazuh/OSSEC integration, PostgreSQL support with a migration tool, a Kubernetes Helm chart, attacker fingerprinting (spots the same actor rotating IPs), graph-based campaign correlation, and opt-in predictive blocking that reacts to an attack's trajectory before any single rule's threshold fires.

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
| [`docs/api.md`](docs/api.md) | Full REST API reference |
| [`docs/kubernetes.md`](docs/kubernetes.md) | Helm chart deployment (DaemonSet, hub view, federation) |
| [`docs/kill-chain.md`](docs/kill-chain.md) | Kill chain tracker (predictive blocking: see [`docs/api.md`](docs/api.md#predictive-blocking)) |
| [`docs/federation.md`](docs/federation.md) | Multi-node setup and the hub view |
| [`docs/cloud-identity.md`](docs/cloud-identity.md) | AWS + Azure AD integration |
| [`docs/zero-trust.md`](docs/zero-trust.md) | Trust score engine |
| [`docs/siem-connectors.md`](docs/siem-connectors.md) | Splunk, Sentinel, Webhook push |
| [`docs/pattern-learning.md`](docs/pattern-learning.md) | Automated rule discovery |
| [`docs/rules.md`](docs/rules.md) | Detection rule tuning (correlation-rule tuning: see [`docs/api.md`](docs/api.md#correlation-rules)) |
| [`docs/ueba.md`](docs/ueba.md) | User/entity behavior analytics |
| [`docs/cases.md`](docs/cases.md) | Case management |
| [`docs/threat-feed.md`](docs/threat-feed.md) | External threat feed ingestion |
| [`docs/2fa.md`](docs/2fa.md) | Two-factor auth for the dashboard |
| [`docs/agent.md`](docs/agent.md) | Remote log-shipping agent |
| [`docs/kafka.md`](docs/kafka.md) | Kafka log ingestion |
| [`docs/zeek.md`](docs/zeek.md) | Zeek log integration |
| [`docs/ot-iot.md`](docs/ot-iot.md) | OT/ICS protocol support (Modbus, DNP3, SCADA) |
| [`docs/country-blocking.md`](docs/country-blocking.md) | Geo-based blocking |
| [`docs/rate-limiting.md`](docs/rate-limiting.md) | API rate limiting |
| [`docs/tenants.md`](docs/tenants.md) | Multi-tenant setup |
| [`docs/huddle.md`](docs/huddle.md) | Incident huddle/collaboration |
| [`docs/notifications.md`](docs/notifications.md) | Email/Slack/Telegram alerts |
| [`docs/changelog.md`](docs/changelog.md) | Version history |
| [`docs/`](docs/) | Browse all 27 guides |

---

## Requirements

- Linux (Ubuntu 20.04+ / Debian 11+ / RHEL 8+)
- Python 3.10+
- Root or `CAP_NET_ADMIN` for iptables blocking

Optional: Redis (distributed blocklist + federation), MaxMind GeoIP database.

---

## License

MIT. See [LICENSE](LICENSE).