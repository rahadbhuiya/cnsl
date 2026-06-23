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
| Kill Chain | Dashboard tab with stage timeline, IP detail view, and aggregate stats |
| Pattern Learning | Discovers recurring attack patterns automatically |
| Pattern Learning | Generates suggested detection rules, operator promotes or dismisses |
| Federation | Cross-node detection sharing over Redis pub/sub |
| Federation | Combined kill chain visibility across all nodes |
| Federation | Cross-node attack detection: IPs seen by 2+ nodes flagged in Settings |
| Cloud | AWS CloudTrail polling for ConsoleLogin failures, MFA bypass |
| Cloud | Azure AD sign-in polling for risky sign-ins, MFA failures |
| Zero-Trust | Per-entity trust score (0-100%) per IP and username |
| Zero-Trust | Low-trust entities trigger alerts at lower event counts |
| Graph | Force-directed attack behavior graph in the dashboard |
| Response | iptables / ipset auto-block with configurable auto-unblock timer |
| Response | Country-based blocking before thresholds fire |
| Response | Honeypot redirect -- attacker lands on a fake Ubuntu shell (40+ commands) |
| Response | Redis distributed blocklist -- sync blocks across a server cluster |
| SIEM | Splunk HEC, Microsoft Sentinel, Generic Webhook push connectors |
| Intelligence | GeoIP enrichment (MaxMind offline or ip-api.com fallback) |
| Intelligence | AbuseIPDB threat score lookup |
| Intelligence | Behavioral baseline + ML anomaly detection (IsolationForest) |
| Ingestion | Remote syslog receiver -- UDP/TCP 514 or 5514 (RFC 3164 / RFC 5424) |
| Ingestion | Kafka consumer for high-volume log ingestion |
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
| Persistence | SQLite incident history, FIM baseline, block records |
| Multi-tenant | Tenant isolation with per-tenant config overrides |
| Ops | Dry-run safe by default, systemd ready, Docker ready |