# Changelog

All notable changes to CNSL are documented here.

---

### v2.8.0 -- Attack Behavior Graph Visualization

- New Graph tab: force-directed canvas-based network graph
- Nodes sized by kill chain progress, colored by zero-trust label
- Edges between IPs sharing detection rules in recent incidents
- Hover tooltip, click node detail panel, min-incidents filter
- GET /api/graph endpoint for external consumers

---

### v2.7.0 -- Zero-Trust Trust Score Engine

- New cnsl/zero_trust.py: per-entity (IP + username) trust scoring 0.05-1.0
- TrustSignal constants with calibrated deltas (+/-)
- Threshold scaling: effective_threshold = ceil(normal * trust_score)
- Score decay toward initial_score at recovery_per_day rate
- SQLite persistence via zt_scores table
- detector.py: threshold scaling for SSH + cloud brute-force rules
- UEBA anomaly/normal-login signals applied to user trust scores
- Dashboard: Zero-Trust panel in Settings, 4 API routes

---

### v2.6.0 -- Cloud Identity Log Connectors

- New cnsl/cloud_identity.py: AWSCloudTrailConnector + AzureADConnector
- AWS SigV4 signing with hmac/hashlib, no boto3 dependency
- Azure AD OAuth2 client credentials flow with auto token refresh
- 5 new event kinds: CLOUD_SIGNIN_FAIL/SUCCESS, CLOUD_MFA_FAIL, CLOUD_RISKY_SIGNIN, CLOUD_IMPOSSIBLE_TRAVEL
- 5 new detection rules: cloud.signin_brute_force, cloud.mfa_failure, cloud.risky_signin, cloud.signin_breach, cloud.impossible_travel
- Dashboard: Cloud Identity panel in Settings, /api/cloud-identity/status

---

### v2.5.0 -- Multi-Node Federation

- New cnsl/federation.py: FederationBus shares detection signals over redis_sync
- FederatedSignal broadcast on new cnsl:federation pub/sub channel
- Remote signals feed into local kill_chain_tracker on every node
- detector.py: _kc_update() helper -- single hook point for kill chain + federation
- Dashboard: Federation panel in Settings, 4 API routes

---

### v2.4.0 -- SIEM/SOAR Native Push Connectors

- New cnsl/siem_connectors.py: SplunkHECConnector + SentinelConnector + WebhookConnector
- SIEMRouter: orchestrates all connectors, retry queue, graceful shutdown
- Pushes every detection alert to enabled connectors in real time
- Dashboard: SIEM status cards, test/flush API, 3 new routes

---

### v2.3.0 -- Automated Pattern Learning

- New cnsl/pattern_learner.py: discovers recurring attack patterns
- Per-IP sliding window event buffer, fingerprint-based counting
- SuggestedRule with confidence score, promote/dismiss from dashboard
- ML anomaly integration via on_ml_anomaly()
- Dashboard: Suggested Rules panel in Rules tab, 4 API routes

---

### v2.2.0 -- Attack Kill Chain Tracker

- New cnsl/kill_chain.py: 7-stage kill chain tracker per source IP
- Per-IP score (0-100%), complete-chain detection, SQLite persistence
- Stages: Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions
- Dashboard: Kill Chain tab, 3 API routes, stage pipeline visualization

---

### v2.1.1 -- Security patches

- POST /block and /unblock now require X-CNSL-Secret header
- Dashboard escHtml() helper closes stored XSS vectors
- Threat feed URLs enforce HTTPS

---

### v2.1.0 -- UEBA + Case Manager

- New cnsl/ueba.py: user/entity behavior analytics (5 anomaly types)
- New cnsl/cases.py: case management (open/close/assign/comment)

---

### v2.0.0 -- Major rewrite

- Async engine (asyncio throughout)
- Multi-source correlation engine
- ML anomaly detection (IsolationForest)
- Live web dashboard with SSE
- Redis distributed blocklist
- GeoIP + AbuseIPDB integration
- File Integrity Monitoring
- Honeypot fake SSH shell