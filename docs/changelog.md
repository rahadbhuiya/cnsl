# Changelog

All notable changes to CNSL are documented here.

---

### v2.9.0 -- ML Tuning UI

**`cnsl/ml_detector.py`**
- `update_params()` -- live update contamination, threshold, min_samples, retrain_interval without restart; clamps values to safe ranges
- `trigger_retrain()` -- force immediate retrain from dashboard; returns ok/reason dict
- `_recent_alerts` deque (max 200) -- stores recent anomaly alert dicts in memory
- `recent_alerts_list(limit)` -- returns recent alert history for dashboard display
- `feature_stats()` -- aggregates feature importance counts from recent alerts
- `status()` extended: now includes contamination, threshold, retrain_interval_sec, recent_alert_count

**`cnsl/dashboard.py`**
- ML tab fully rebuilt: 4-stat summary cards, parameter tuning form, Retrain Now button, feature importance bars, recent alerts table
- `PATCH /api/ml/params` -- live parameter update (contamination, threshold, min_samples, retrain_interval_sec)
- `POST /api/ml/retrain` -- force immediate retrain
- `GET /api/ml/alerts` -- recent ML anomaly alerts (limit param)
- `GET /api/ml/feature-stats` -- feature importance counts from recent alerts

**`cnsl/__init__.py`** -- version bumped to 2.9.0

**`tests/test_cnsl.py`** -- 25 new tests (431 total, zero regressions)

---

### v2.8.0 -- Attack Behavior Graph Visualization

**`cnsl/dashboard.py`**
- New Graph tab in nav with network icon
- Force-directed canvas-based network graph (pure JS + Canvas API, no external library)
- Nodes: one per attacker IP, sized by kill chain progress, colored by zero-trust label (green=trusted, amber=moderate, red=suspicious/untrusted)
- Kill chain progress ring: white arc around each node
- HIGH-severity nodes get a colored glow effect
- Edges: dashed lines between IPs sharing detection rules in recent incidents; line weight = number of shared rules
- Hover tooltip: IP, trust score/label, kill chain stage, incident count, location
- Click node: detail panel with all attributes below the graph
- Controls: min-incidents filter, label toggle, Refresh button
- Force-directed layout: 80-step spring-repulsion simulation, runs client-side on tab open
- `GET /api/graph` -- pre-computed nodes+edges JSON for external consumers; supports `limit` and `min_incidents` params

**`cnsl/__init__.py`** -- version bumped to 2.8.0

**`simulate.py`** -- version banner updated to v2.8.0

**`tests/test_cnsl.py`** -- TestGraphTabPresence, TestGraphAPIRoute, TestDashboardSignatureV4 (406 total)

---

### v2.7.0 -- Zero-Trust Trust Score Engine

**New module: `cnsl/zero_trust.py`**
- `ZeroTrustEngine` maintains per-entity (IP or username) trust score (0.05-1.0)
- `TrustSignal` constants: known_ip_login (+0.05), normal_hour_login (+0.02), unknown_ip_login (-0.10), ueba_anomaly (-0.20), brute_force_fail (-0.05), mfa_failure (-0.25), cloud_risk_flag (-0.30), impossible_travel (-0.35), block_applied (-0.40), correlation_alert (-0.15)
- Score labels: trusted (>=0.8), moderate (>=0.5), suspicious (>=0.2), untrusted (<0.2)
- Threshold scaling: `effective_threshold = ceil(normal * trust_score)` -- low-trust entities alert with fewer events
- Score decay toward `initial_score` at `recovery_per_day` rate per day of inactivity
- SQLite persistence via `zt_scores` table with score and last_updated indexes
- Max entity limit (default 50000) with oldest-first eviction

**`cnsl/store.py`**
- `ZT_SCHEMA` imported and applied on `init()` -- creates `zt_scores` table

**`cnsl/detector.py`**
- `zero_trust` parameter added to `Detector.__init__`
- `_zt_threshold()` helper -- returns trust-adjusted threshold; exceptions return normal threshold
- SSH brute-force and credential stuffing thresholds scaled by IP trust score
- Cloud signin brute-force threshold scaled by IP trust score
- SSH fail applies `BRUTE_FORCE_FAIL` signal to IP trust score
- UEBA anomaly in SSH success applies `UEBA_ANOMALY` signal to user trust score
- Normal login from known IP applies `KNOWN_IP_LOGIN` (trust boost); unknown IP applies `UNKNOWN_IP_LOGIN`
- Cloud MFA failure applies `MFA_FAILURE` to both IP and user trust scores
- Cloud risky signin applies `CLOUD_RISK_FLAG` to both IP and user trust scores

**`cnsl/engine.py`**
- `ZeroTrustEngine` instantiated after `CloudIdentityPoller`; scores loaded from SQLite on startup
- Passed to `Detector` and `start_dashboard`
- Version bumped to 2.7.0

**`cnsl/dashboard.py`**
- Zero-Trust Trust Scores panel added to Settings tab -- entity table sorted by score ascending (untrusted first), score bar, trust label, signal count, last signal, Reset button
- Stats bar: total entities, trusted/moderate/suspicious/untrusted counts, average score
- `GET /api/zero-trust/stats` -- aggregate trust statistics
- `GET /api/zero-trust/scores` -- all scored entities (type, max_score, limit params)
- `GET /api/zero-trust/scores/{entity}` -- score detail with recent signal history
- `POST /api/zero-trust/scores/{entity}/reset` -- reset entity to initial_score
- `/api/debug` extended with zero_trust_wired, zero_trust_enabled

**`config/config.example.json`** -- zero_trust block added

**`simulate.py`** -- scenario 22: zero-trust trust scoring demo; ZeroTrustEngine wired into setup()

**`tests/test_cnsl.py`** -- 9 new test classes, 27 tests (396 total)

---

### v2.6.0 -- Cloud Identity Log Connectors

**New module: `cnsl/cloud_identity.py`**
- `AWSCloudTrailConnector` -- polls CloudTrail `LookupEvents` for ConsoleLogin events; AWS SigV4 signing with hmac/hashlib only (no boto3); per-EventId cursor deduplication
- `AzureADConnector` -- polls Microsoft Graph `signIns` with OAuth2 client credentials flow; token cached and auto-refreshed; MFA error codes 50074/50079/50076 mapped to CLOUD_MFA_FAIL
- `CloudIdentityPoller` -- orchestrates both on shared poll interval, feeds Events into engine queue
- 5 new event kinds: CLOUD_SIGNIN_FAIL, CLOUD_SIGNIN_SUCCESS, CLOUD_MFA_FAIL, CLOUD_RISKY_SIGNIN, CLOUD_IMPOSSIBLE_TRAVEL

**`cnsl/rules.py`**
- 5 new detection rules: cloud.signin_brute_force (MEDIUM/5), cloud.mfa_failure (HIGH/1), cloud.risky_signin (HIGH/1), cloud.signin_breach (HIGH/3), cloud.impossible_travel (HIGH/1)

**`cnsl/detector.py`**
- `_CLOUD_KINDS` set added; `_ALL_HANDLED` updated
- `_on_cloud_event()` handler routes all 5 cloud event kinds, evaluates rules, calls `_kc_update()`, calls `_maybe_fire()`

**`cnsl/engine.py`**
- `CloudIdentityPoller` instantiated; poll loop started as background task when any connector enabled
- `cloud_identity.stop()` called on graceful shutdown
- Passed to `start_dashboard`; version bumped to 2.6.0

**`cnsl/dashboard.py`**
- Cloud Identity Connectors panel added to Settings tab -- AWS and Azure status cards with poll count, error count, token validity, last error
- `GET /api/cloud-identity/status` -- connector health, poll counts, events fed

**`config/config.example.json`** -- cloud_identity block added (aws + azure_ad sub-blocks)

**`simulate.py`** -- scenario 21: cloud account takeover sequence; CloudEventKind used directly

**`tests/test_cnsl.py`** -- 8 new test classes, 38 tests (369 total)

---

### v2.5.0 -- Multi-Node Federation

**New module: `cnsl/federation.py`**
- `FederationBus` reuses existing `redis_sync` Redis connection (no new infra dependency)
- Subscribes to new `{prefix}:federation` pub/sub channel separate from blocklist channel
- `FederatedSignal` (node_id, ip, kind, severity, ts) -- compact broadcast unit
- `FederatedIPRecord` -- per-IP record tracking which nodes saw which event kinds; `is_cross_node=True` when 2+ distinct nodes report on same IP
- Per-(ip, kind) dedup window (default 5s) prevents publish flooding
- Graceful degradation: if Redis unavailable, all publish/receive calls are no-ops; local detection unaffected
- `on_remote_signal` callback invoked for every remote signal received

**`cnsl/detector.py`**
- `federation` parameter added to `Detector.__init__`
- `_kc_update()` helper -- single hook point for all kill chain updates AND federation publishes; replaces 7 scattered `kill_chain.update()` call sites in `_on_ssh_fail`, `_on_ssh_success`, `_on_web_event`, `_on_db_event`, `_on_fw_event` (x2), `_on_sys_event`

**`cnsl/engine.py`**
- `FederationBus` instantiated after `redis_sync.connect()`; reuses same connection object
- `federation.on_remote_signal` wired to feed remote signals into local `kill_chain_tracker`
- `federation.start()` called alongside `redis_sync.subscribe_loop()` and `heartbeat_loop()` tasks
- `federation.stop()` called on graceful shutdown
- Passed to `Detector` and `start_dashboard`; version bumped to 2.5.0

**`cnsl/dashboard.py`**
- Federation panel added to Settings tab -- peer node table, cross-node attack table (IPs seen by 2+ nodes, which nodes, which event kinds)
- Stats cards: connection status, signals sent/received, cross-node IP count
- `GET /api/federation/status` -- this node's federation health and stats
- `GET /api/federation/nodes` -- all peer nodes with last-seen timestamp
- `GET /api/federation/cross-node` -- IPs reported by 2+ distinct nodes
- `GET /api/federation/ip/{ip}` -- combined per-node view for one IP

**`config/config.example.json`** -- federation block added

**`simulate.py`** -- scenario 20: simulated 2-node cluster demo; RedisSync + FederationBus wired into setup(); ZeroTrustEngine wired into setup()

**`tests/test_cnsl.py`** -- 6 new test classes, 25 tests (331 total)

---

### v2.4.0 -- SIEM/SOAR Native Push Connectors

**New module: `cnsl/siem_connectors.py`**
- `SplunkHECConnector` -- pushes to Splunk HEC (`POST /services/collector/event`); Authorization: Splunk {token}; configurable index, sourcetype, host, verify_ssl, min_severity
- `SentinelConnector` -- pushes to Microsoft Sentinel Log Analytics Data Collector API; HMAC-SHA256 signed; configurable workspace_id, shared_key, log_type
- `WebhookConnector` -- generic HTTPS webhook (Palo Alto XSOAR, IBM QRadar, custom SOC); Bearer token auth, custom headers, configurable HTTP method
- `SIEMRouter` -- orchestrates all connectors; in-memory retry queue (max 1000 entries); exponential backoff; graceful shutdown closes all aiohttp sessions
- `min_severity` filtering per connector -- events below threshold silently skipped

**`cnsl/detector.py`**
- `siem_router` parameter added
- `asyncio.ensure_future(siem_router.push(detection))` called in `_maybe_fire()` after every alert -- non-blocking

**`cnsl/engine.py`**
- `SIEMRouter` instantiated; `siem_router.close()` called on graceful shutdown
- Passed to `Detector` and `start_dashboard`; version bumped to 2.4.0

**`cnsl/dashboard.py`**
- SIEM / SOAR Connectors section added to Settings tab -- status cards per connector with push/error counts and last error
- Send Test button per connector; Flush Now button for retry queue
- `GET /api/siem/status` -- connector health + retry queue depth
- `POST /api/siem/test/{name}` -- send test event to splunk|sentinel|webhook
- `POST /api/siem/flush` -- force flush retry queue

**`config/config.example.json`** -- siem.splunk, siem.sentinel, siem.webhook blocks added (all disabled by default)

**`simulate.py`** -- scenario 19: SIEM connector push dry-run demo

**`tests/test_cnsl.py`** -- TestSIEMSeverityFiltering, TestSIEMConnectorConfig, TestSIEMRouter, TestDashboardSignatureV2, TestDetectorAcceptsV2Modules (298 total)

---

### v2.3.0 -- Automated Pattern Learning

**New module: `cnsl/pattern_learner.py`**
- `PatternLearner` observes every detection event via per-IP sliding window buffer (default 5 min lookback)
- When alert fires, extracts event sequence and computes stable pattern fingerprint (sorted unique event kinds joined by `+`)
- Fingerprints counted; at `min_occurrences` (default 5) a `SuggestedRule` is born
- `SuggestedRule` includes: event kinds, occurrence count, confidence (0-1), suggested severity, suggested threshold (median observed), suggested window, up to 5 example IPs
- ML anomaly integration via `on_ml_anomaly()` -- ML anomaly reasons also feed pattern discovery
- Operators can promote (applies threshold/severity/window to live rule engine) or dismiss (suppresses permanently)
- SQLite persistence via `pl_suggestions` table

**`cnsl/store.py`**
- `PL_SCHEMA` imported and applied on `init()`

**`cnsl/detector.py`**
- `pattern_learner` parameter added
- `observe_event()` called in `handle()` for every inbound event
- `on_alert()` called in `_maybe_fire()` every time a detection fires

**`cnsl/engine.py`**
- `PatternLearner` instantiated; persisted suggestions loaded on startup
- `engine_loop` accepts `pattern_learner`; ML anomaly return value checked and fed to `on_ml_anomaly()`
- Passed to `Detector` and `start_dashboard`; version bumped to 2.3.0

**`cnsl/dashboard.py`**
- Suggested Rules panel added below Alert Rules table in Rules tab
- Stats bar: patterns tracked, active suggestions, promoted, dismissed, min_occurrences
- Table: pattern event kinds, confidence bar, occurrences, severity, threshold, window, example IPs, Promote/Dismiss buttons
- `GET /api/pattern-suggestions` -- active suggestions
- `GET /api/pattern-suggestions/stats` -- aggregate learner statistics
- `POST /api/pattern-suggestions/{id}/promote` -- promote suggestion
- `POST /api/pattern-suggestions/{id}/dismiss` -- dismiss suggestion

**`cnsl/reporter.py`** -- kill chain and pattern learning data included in all report formats (HTML, PDF, JSON)

**`config/config.example.json`** -- kill_chain and pattern_learning blocks added

**`simulate.py`** -- scenarios 17 (kill chain), 18 (pattern learning), 19 (SIEM push) added; KillChainTracker, PatternLearner, SIEMRouter wired into setup()

**`tests/test_cnsl.py`** -- TestKillChainStages, TestKillChainScore, TestKillChainQueries, TestPatternFingerprint, TestPatternLearnerObservation, TestPatternLearnerSuggestions (250 total after dedup)

---

### v2.2.0 -- Attack Kill Chain Tracker

**New module: `cnsl/kill_chain.py`**
- `KillChainTracker` tracks per-IP attack progression across 7 unified kill chain stages
- Stages: Reconnaissance (0), Weaponization (1), Delivery (2), Exploitation (3), Installation (4), C2 (5), Actions on Objectives (6)
- Stage mapped from event kind via `_KIND_TO_STAGE` dict; correlation rules mapped via `update_from_correlation()`
- Per-IP score: `(highest_stage + 1) / 7`; complete=True when stages 0+2+3 all observed
- SQLite persistence via `kc_chains` table with score and last_seen indexes
- Max chain limit (default 5000) with oldest-first eviction

**`cnsl/store.py`**
- `KC_SCHEMA` imported and applied on `init()` -- creates `kc_chains` table
- `db_execute(sql, params)` and `db_fetchall(sql, params)` generic async helpers added (used by kill chain persistence)

**`cnsl/detector.py`**
- `kill_chain` parameter added to `Detector.__init__`
- `kill_chain.update()` called in `_on_ssh_fail` (Delivery), `_on_ssh_success` (Exploitation), `_on_web_event` (Recon/Delivery/Weaponization), `_on_db_event` (Delivery), `_on_fw_event` (Recon), `_on_sys_event` (Installation)
- `kill_chain.update_from_correlation()` called after every correlation alert

**`cnsl/engine.py`**
- `KillChainTracker` instantiated; chains loaded from SQLite on startup
- Passed to `Detector` and `start_dashboard`; version bumped to 2.2.0

**`cnsl/dashboard.py`**
- Kill Chain tab added to nav
- `GET /api/kill-chain` -- all chains (limit, min_score, complete_only params)
- `GET /api/kill-chain/stats` -- aggregate stage distribution and average score
- `GET /api/kill-chain/{ip}` -- full chain detail
- `/api/debug` extended with kill_chain_wired, kill_chain_enabled

**`cnsl/__init__.py`** -- description updated; version bumped to 2.2.0

---

### v2.1.1 -- Security patches

**`cnsl/api.py`**
- `POST /block` and `POST /unblock` now require `X-CNSL-Secret` header matching `api.secret_value` in config; returns 403 on mismatch
- Both endpoints validate IP via `ipaddress.ip_address()` before passing to blocker; returns 400 on invalid input
- Auth failures logged via `api_auth_failure` event

**`cnsl/dashboard.py`**
- `escHtml()` helper added; all network-controlled data now escaped before `innerHTML` injection -- closes stored XSS vectors in incidents, blocks, attackers, honeypot sessions, FIM alerts, cases, UEBA anomalies/profiles, and HuddleCluster node list
- Header badge updated to v2.1.1

**`cnsl/threat_feed.py`**
- Feed URLs enforce HTTPS

**`cnsl/__init__.py`** -- `py.typed` marker file added (PEP 561); version bumped to 2.1.1

---

### v2.1.0 -- UEBA + Case Manager

**New module: `cnsl/ueba.py`**
- `UEBAEngine` tracks per-user behavioral profiles (login times, source IPs, usernames, frequency)
- 5 anomaly types: unusual_hour, unknown_ip, frequency_spike, new_username, lateral_movement
- SQLite persistence via `ueba_events` and `ueba_profiles` tables
- `observe(username, src_ip, ts)` called on every successful SSH login

**New module: `cnsl/cases.py`**
- Security case management: open, close, assign, comment, link incidents
- SQLite persistence via `cases` and `case_comments` tables
- REST API: `GET/POST /api/cases`, `PATCH /api/cases/{id}`, `POST /api/cases/{id}/comment`, `POST /api/cases/{id}/link`

**`cnsl/dashboard.py`**
- Cases tab added
- UEBA tab added with anomaly table and user profile view

---

### v2.0.0 -- Kafka, Multi-tenant, Rate Limiting, Enhanced Reports, HuddleCluster

**New module: `cnsl/kafka_consumer.py`**
- `KafkaConsumer` -- async Kafka consumer using aiokafka (with confluent-kafka fallback)
- Per-topic parser assignment: auth, nginx, apache, mysql, ufw, syslog, json, zeek_*
- Exponential backoff reconnect, periodic offset commit
- `GET /api/kafka` -- stats endpoint

**New module: `cnsl/tenants.py`**
- `TenantManager` -- multi-tenant registry with per-tenant isolation
- Per-tenant `RuleEngine` with lazy init and cache invalidation
- Single-tenant mode: transparent wrapper, zero breaking changes
- `GET /api/tenants`, `POST /api/tenants`, `DELETE /api/tenants/{id}`

**New module: `cnsl/rate_limiter.py`**
- `RateLimiter` -- sliding window per-IP rate limiting + DDoS detection
- Per-endpoint config (stricter limits for `/api/login`)
- Auto-block via Blocker on DDoS threshold
- aiohttp middleware: `make_rate_limit_middleware()`
- `GET /api/rate-limit`, `GET /api/rate-limit/top`, `POST /api/rate-limit/reset/{ip}`

**`cnsl/reporter.py`** -- Enhanced compliance reports
- Now includes: UEBA anomaly summary, case stats, rule engine state, rate limit stats
- `Reporter.__init__()` accepts `ueba`, `case_manager`, `rule_engine`, `rate_limiter`

**Tests** -- 30 new tests: TestRateLimiter (10), TestTenantManager (12), TestKafkaConsumer (6), TestReporterEnhanced (2) -- total 250 passing (was 240)

---

### v1.9.0 -- Agent System + WebSocket

**New module: `cnsl/agent.py`**
- `AgentQueue` -- bounded event queue with drop-oldest overflow and dropped-count tracking
- `tail_file()` -- async log file tailer with rotation detection
- `ws_sender()` -- WebSocket sender with exponential backoff reconnect
- `run_agent()` -- wires tailers + sender, prints queue/dropped stats every 60s
- Supports: auth, nginx, apache, mysql, ufw, syslog log sources
- CLI: `python -m cnsl.agent --server wss://... --token ... --hostname web-01`

**`cnsl/dashboard.py`** -- 2 new WebSocket endpoints
- `GET /ws` -- bidirectional WebSocket for dashboard browser; auth via first message; RBAC enforced server-side
- `GET /ws/agent` -- agent ingestion endpoint; events processed through full detection pipeline

**Tests** -- 14 new tests -- total 210 passing (was 196)

---

### v1.8.0 -- Full UEBA (User and Entity Behavior Analytics)

**New module: `cnsl/ueba.py`**
- `UEBAEngine` -- per-user behavioral profile engine with SQLite persistence
- `UserProfile` -- tracks login hours, known IPs, daily counts, recent IPs, anomaly log
- 5 detection capabilities: unusual login hour, new source IP, lateral movement, login after absence, frequency spike
- `min_observations` learning period -- no false positives during warmup
- Async SQLite persistence (`ueba_profiles`, `ueba_anomalies` tables)

**Tests** -- 19 new tests -- total 196 passing (was 177)

---

### v1.7.0 -- Zeek Log Ingestion

**New module: `cnsl/zeek_parser.py`**
- `ZeekLogParser` -- stateful line-by-line parser for Zeek TSV and JSON output
- Parsers for 6 log types: `conn`, `ssh`, `http`, `dns`, `notice`, `weird`
- `_shannon_entropy()` -- DNS tunneling detection via high-entropy subdomain names
- Both TSV (default Zeek) and JSON formats supported

**Tests** -- 32 new tests -- total 177 passing (was 145)

---

### v1.6.0 -- Community Threat Feed

**New module: `cnsl/threat_feed.py`**
- `ThreatFeed` -- downloads and caches known-bad IPs from 6 public feeds
- Built-in feeds: Emerging Threats, Feodo Tracker, CINS Army, abuse.ch SSLBL, Spamhaus DROP, Spamhaus EDROP
- Local custom blocklist file support (IPs and CIDRs)
- Periodic background refresh (default: every hour)
- `auto_block` mode -- blocks on first hit before thresholds fire

**Tests** -- 20 new tests -- total 145 passing (was 125)

---

### v1.5.0 -- Alert Rule Engine

**New module: `cnsl/rules.py`**
- `Rule` dataclass -- id, name, description, severity, threshold, window_sec, enabled, tags
- `RuleEngine` -- manages all 9 built-in rules with config override and runtime mutation
- Built-in rules: `ssh.brute_force`, `ssh.credential_stuffing`, `ssh.credential_breach`, `web.scan_flood`, `web.auth_flood`, `web.exploit`, `db.brute_force`, `fw.honeypot_port`, `net.repeat_offender`
- Runtime API: `enable()`, `disable()`, `update()`, `reset()` -- no restart required

**Tests** -- 22 new tests -- total 125 passing (was 103)

---

### v1.4.0 -- Case Management

**New module: `cnsl/cases.py`**
- `CaseManager` -- full async SQLite-backed case lifecycle
- Auto-create cases from every HIGH severity detection
- Status transitions: `open` -> `investigating` -> `closed` / `false_positive`
- Every status change and assignment logged as append-only system note (full audit trail)
- Analyst notes -- timestamped, append-only, author tracked

**Tests** -- 23 new tests -- total 103 passing (was 80)

---

### v1.3.0 -- Two-Factor Authentication (TOTP)

- `auth.py` -- TOTP 2FA (Google Authenticator / Authy compatible)
- Per-user enable/disable -- existing accounts unaffected until opted in
- Two-step login: password -> 6-digit OTP (partial token, 5 min expiry)
- 8 single-use backup codes generated on activation (SHA-256 hashed in storage)
- TOTP allows +-1 window (30s drift tolerance)
- `pyotp>=2.9.0` added to dependencies

**Tests** -- 22 new tests -- total 80 passing (was 58)

---

### v1.2.0 -- Country blocking, Email notifications, Docs

- Country-based blocking via `country_block.countries: ["CN", "RU"]`
- Email (SMTP) notifications -- STARTTLS, implicit SSL, and plain SMTP
- Standalone `docs/` folder with 6 guides

---

### v1.1.0 -- Remote ingestion, ECS normalization, search engine

**New modules:** `syslog_receiver.py`, `normalizer.py`, `search_engine.py`

**Bug fixes:**
- IPv6-mapped IPv4 addresses (`::ffff:1.2.3.4`) stripped to plain IPv4
- Web log parser rewritten -- bare 404 on normal paths no longer flagged as `WEB_SCAN`
- File write errors handled gracefully instead of crashing the engine
- `kind` column added to incidents table with automatic migration

**Tests** -- total 48 passing (was 26)

---

### v1.0.4 -- Honeypot overhaul, FIM fix, emoji removed

- `honeypot.py` -- Full shell simulation rewrite. 40+ commands, persistent virtual filesystem
- `fim.py` -- Directories in `watch_paths` now scanned recursively with `os.walk()`
- `notify.py` -- All emoji removed, plain text messages, Telegram escaping fixed
- `logger.py` -- Emoji prefixes replaced with aligned text labels

---

### v1.0.3 -- Critical runtime fixes

- `parsers.py` -- `sshd-session[PID]` regex added for modern OpenSSH
- `config.py` -- `/etc/cnsl/config.json` now auto-discovered on startup
- Default `allowlist` -- `::1` removed, `fails_threshold` lowered to 5

---

### v1.0.2 -- Dashboard overhaul

- Tabbed UI with 7 tabs, 8 stat cards, timeline chart, PDF export, SVG icons
- New endpoints: `/api/timeline`, `/api/ml-status`, `/api/honeypot`, `/api/fim`, `/api/system`, `/api/debug`

---

### v1.0.1 -- Bug fixes

- `engine_loop()` -- `NameError` crash on first event fixed
- RBAC enforced on block/unblock endpoints
- Prometheus gauge decrements on unblock
- Redis unblock propagation fixed

---

### v1.0.0 -- Initial release

First public release of CNSL. SSH brute-force detection and blocking, web scanner detection, GeoIP enrichment, basic dashboard, iptables/ipset backend.