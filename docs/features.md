# CNSL Features

## Detection

| Threat | How |
|:---|:---|
| SSH brute-force | Threshold-based failure counting per IP |
| Credential breach | SSH success after repeated failures |
| Credential stuffing | Many different usernames from one IP |
| Web scanner | Nikto, sqlmap, gobuster detection |
| Web exploit attempts | /.env, /wp-admin, path traversal |
| Database brute-force | MySQL auth failure spikes |
| Honeypot port probe | Any connection to port 23/3389/6379 |
| Privilege escalation | sudo/su failure after successful SSH login |
| File tampering | Watched paths: /etc/passwd, authorized_keys, etc. |
| Behavioral anomaly | Unusual login hour, new username, frequency spike |
| Coordinated attack | Same IP across SSH + web + DB simultaneously |
| Cloud sign-in brute-force | AWS CloudTrail + Azure AD failures |
| Cloud MFA failure | MFA challenge failed or bypassed |
| Cloud risky sign-in | Azure AD risk engine flag |
| Cloud impossible travel | Geographically impossible sign-in pair |

## Full Capability List

| Category | Capability |
|:---|:---|
| Detection | SSH brute-force, credential stuffing, credential breach |
| Detection | Web scanner + exploit paths (false positive resistant) |
| Detection | Database brute-force (MySQL), firewall honeypot ports |
| Detection | Privilege escalation (sudo/su after login) |
| Correlation | 6 cross-source rules -- web+SSH, multi-service, kill chain |
| Kill Chain | Per-IP attack progression across 7 stages (Recon to Actions) |
| Kill Chain | Confidence score (0-100%), complete-chain detection, SQLite persistence |
| Kill Chain | Dashboard tab with stage timeline, IP detail view, aggregate stats |
| Pattern Learning | Discovers recurring attack patterns automatically |
| Pattern Learning | Generates suggested detection rules, operator promotes or dismisses |
| ML | IsolationForest anomaly detection, unsupervised, auto-retrains |
| ML | Live parameter tuning from dashboard (contamination, threshold, min_samples) |
| ML | Manual retrain trigger, recent alerts table, feature importance bars |
| Federation | Cross-node detection sharing over Redis pub/sub |
| Federation | Combined kill chain visibility across all nodes |
| Federation | Cross-node attack detection: IPs seen by 2+ nodes flagged |
| Cloud | AWS CloudTrail polling for ConsoleLogin failures, MFA bypass |
| Cloud | Azure AD sign-in polling for risky sign-ins, MFA failures, impossible travel |
| Zero-Trust | Per-entity trust score (0-100%) per IP and username |
| Zero-Trust | Low-trust entities trigger alerts at lower event counts (threshold scaling) |
| Zero-Trust | Score decay and recovery over time, manual reset from dashboard |
| Graph | Force-directed attack behavior graph -- nodes colored by trust, sized by kill chain |
| OT/IoT | Modbus TCP/RTU log parsing -- read sweep detection, write command alerting |
| OT/IoT | DNP3 log parsing -- unsolicited response detection, Secure Authentication failures |
| OT/IoT | SCADA/HMI log parsing -- alarm flood detection, unauthorized command attempts |
| OT/IoT | Full kill chain integration: Modbus scan -> write -> SCADA alarm maps to Recon -> Exploit -> Actions |
| Response | iptables / ipset auto-block with configurable auto-unblock timer |
| Response | Country-based blocking before thresholds fire |
| Response | Honeypot redirect -- attacker lands on a fake Ubuntu shell (40+ commands) |
| Response | Redis distributed blocklist -- sync blocks across a server cluster |
| SIEM | Splunk HEC, Microsoft Sentinel, Generic Webhook push connectors |
| SIEM | Retry queue, min_severity filter, manual test/flush from dashboard |
| Intelligence | GeoIP enrichment (MaxMind offline or ip-api.com fallback) |
| Intelligence | AbuseIPDB threat score lookup |
| Intelligence | Community threat feeds (6 feeds, CIDR matching) |
| Ingestion | Remote syslog receiver -- UDP/TCP 514 or 5514 (RFC 3164 / RFC 5424) |
| Ingestion | Kafka consumer for high-volume log ingestion |
| Ingestion | Agent log forwarder (WebSocket) |
| Normalization | ECS-compatible event schema, CEF export for ArcSight/Splunk |
| Search | KQL-like full-text search, time-range filters, aggregations |
| Export | Elasticsearch/OpenSearch bulk push, NDJSON and CEF file export |
| Monitoring | File Integrity Monitoring -- watches files and directories recursively |
| Monitoring | Passive asset inventory via network events |
| Visibility | Live web dashboard with tabbed UI and real-time SSE feed |
| Visibility | Prometheus metrics + Grafana dashboard template |
| Reporting | PDF / HTML compliance reports (SOC2, ISO27001, PCI-DSS) |
| Access | JWT authentication + Role-Based Access Control (4 roles) |
| Access | 2FA (TOTP) support |
| Notifications | Telegram, Discord, Slack, Email, custom webhook |
| Persistence | SQLite incident history, FIM baseline, block records, kill chain, trust scores |
| Multi-tenant | Tenant isolation with per-tenant config overrides |
| Ops | Dry-run safe by default, systemd ready, Docker ready |

## Detection Rules (Built-in)

| Rule ID | Severity | Default Threshold | Window |
|:---|:---|:---|:---|
| `ssh.brute_force` | MEDIUM | 8 failures | 60s |
| `ssh.credential_stuffing` | MEDIUM | 6 unique users | 60s |
| `ssh.credential_breach` | HIGH | 3 prior failures | 300s |
| `web.scan_flood` | MEDIUM | 20 requests | 60s |
| `web.auth_flood` | MEDIUM | 10 failures | 60s |
| `web.exploit` | HIGH | 1 hit | -- |
| `db.brute_force` | MEDIUM | 8 failures | 60s |
| `fw.honeypot_port` | HIGH | 1 connection | -- |
| `net.repeat_offender` | HIGH | 3 incidents | 3600s |
| `cloud.signin_brute_force` | MEDIUM | 5 failures | 300s |
| `cloud.mfa_failure` | HIGH | 1 failure | -- |
| `cloud.risky_signin` | HIGH | 1 flag | -- |
| `cloud.signin_breach` | HIGH | 3 prior failures | 300s |
| `cloud.impossible_travel` | HIGH | 1 event | -- |

All rules can be adjusted or disabled from the dashboard Rules tab or via `PATCH /api/rules/{rule_id}`.

## Dashboard Tabs

| Tab | What it shows |
|:---|:---|
| Overview | Stat cards, 24h timeline chart, severity doughnut, top attackers |
| Incidents | Full incident table with time, IP, location, severity, fail count, reasons |
| Blocks | Active blocks with unblock button, manual block form |
| Honeypot | Status, active redirects, session table (IP, duration, auth attempts, commands) |
| FIM | Watched paths, file integrity alerts |
| ML | Status, training progress, parameter tuning form, retrain button, feature importance bars, recent anomalies |
| Live Feed | Every event streamed in real time via SSE |
| Kill Chain | Per-IP attack progression across 7 stages, score bar, complete-chain badge, detail view |
| Graph | Force-directed network graph: nodes = attacker IPs, colored by trust, sized by kill chain progress |
| Cases | Security case management (create, assign, comment, link incidents) |
| UEBA | Behavioral anomalies table, user profile viewer |
| Rules | Alert rules table with live edit, Suggested Rules panel from pattern learner |
| Rate Limit | Per-IP request rate state, top requesters |
| Settings | SIEM connectors, Federation panel, Cloud Identity status, Zero-Trust trust scores, Module Status |

## Simulator

`simulate.py` runs all detection scenarios locally without a real server.
22 scenarios covering every detection type:

```bash
python simulate.py all         # run all 22 scenarios
python simulate.py brute       # SSH brute-force
python simulate.py kill_chain  # kill chain tracker
python simulate.py pattern     # automated pattern learning
python simulate.py siem        # SIEM connector push (dry-run)
python simulate.py federation  # multi-node federation (simulated)
python simulate.py cloud       # cloud identity logs
python simulate.py zerotrust   # zero-trust trust scoring
python simulate.py live        # interactive mode
```

## Test Coverage

```bash
python -m pytest tests/test_cnsl.py   # runs 431 tests
```

Tests cover: config loading, event parsing, detection thresholds, correlation rules, blocking, UEBA, cases, rate limiting, kill chain, pattern learning, SIEM connectors, federation, cloud identity, zero-trust, ML tuning UI, graph tab presence, and all dashboard API signatures.