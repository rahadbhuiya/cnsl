# CNSL Architecture

## Overview

```
Log Sources --> Parsers --> Queue --> Detector --> Correlator --> Blocker
                                        |               |
                                   Kill Chain      Notifier
                                   Pattern Learner
                                   Zero-Trust
                                   ML Detector
                                        |
                                  Dashboard (Web UI + REST API)
                                  SIEM Router (push to Splunk/Sentinel/Webhook)
                                  Federation Bus (cross-node signal sharing)
                                  Reporter (PDF/HTML/JSON)
```

## Module Map

```
cnsl/
-- __init__.py              package version (2.9.0)
-- __main__.py              python -m cnsl entrypoint

-- models.py                Event, Detection, Severity dataclasses
-- config.py                config loading and all defaults
-- validator.py             startup config validation
-- logger.py                async JSON logger

-- parsers.py               auth.log + tcpdump parsers (sshd, sshd-session)
-- log_sources.py           nginx, mysql, ufw, syslog parsers + async file tailer
-- syslog_receiver.py       UDP/TCP syslog ingestion (RFC 3164/5424)
-- kafka_consumer.py        Kafka log ingestion
-- agent.py                 remote log forwarder (WebSocket client)

-- detector.py              per-IP stateful detection engine (routes by event kind)
-- correlator.py            cross-source correlation (6 rules)
-- rules.py                 rule engine (14 built-in rules, live override support)
-- normalizer.py            ECS schema normalization

-- kill_chain.py            attack kill chain tracker (7 stages, score, SQLite)
-- pattern_learner.py       automated pattern discovery + suggested rules
-- zero_trust.py            per-entity trust scoring (IP + username)
-- cloud_identity.py        AWS CloudTrail + Azure AD sign-in polling
-- federation.py            multi-node detection signal sharing (Redis pub/sub)

-- ml_detector.py           ML anomaly detection (IsolationForest, auto-retrains)
-- ueba.py                  user/entity behavior analytics (5 anomaly types)
-- threat_feed.py           community threat feeds (6 feeds, CIDR matching)
-- threat_intel.py          AbuseIPDB + behavioral baseline

-- blocker.py               iptables/ipset blocking backend
-- honeypot.py              fake SSH server (40+ commands, virtual filesystem)
-- active_response.py       honeypot redirect orchestration
-- rate_limiter.py          per-IP request rate limiting

-- siem_connectors.py       Splunk HEC + Sentinel + Webhook push connectors
-- es_pusher.py             Elasticsearch/OpenSearch bulk push
-- redis_sync.py            distributed blocklist sync + node heartbeat

-- dashboard.py             web UI + REST API + SSE/WebSocket (~4500 lines)
-- search_engine.py         KQL-like full-text search + Elasticsearch pusher
-- reporter.py              PDF/HTML/JSON compliance reports
-- metrics.py               Prometheus metrics exporter

-- store.py                 SQLite-backed persistent state (incidents, blocks,
                            kill chain, pattern suggestions, trust scores)
-- cases.py                 security case management
-- fim_engine.py            file integrity monitoring
-- asset_inventory.py       passive asset discovery

-- geoip.py                 GeoIP enrichment (MaxMind + ip-api.com fallback)
-- auth.py                  JWT + 2FA (TOTP) authentication
-- rbac.py                  role-based access control (4 roles)
-- tenants.py               multi-tenant support
-- huddle_integration.py    load balancing + temperature-based routing
```

## Data Flow

```
1. Source modules (parsers, log_sources, syslog_receiver, kafka_consumer,
   cloud_identity poller) produce Event objects and put them into a shared
   asyncio.Queue.

2. engine_loop() drains the queue and calls detector.handle(ev) for each event.

3. Detector routes by ev.kind to the appropriate handler:
     SSH_FAIL/SUCCESS    -> _on_ssh_fail / _on_ssh_success
     WEB_*               -> _on_web_event
     DB_AUTH_FAIL        -> _on_db_event
     FW_*                -> _on_fw_event
     SUDO_FAIL/SU_FAIL   -> _on_sys_event
     CLOUD_*             -> _on_cloud_event

4. Each handler:
   a. Updates per-IP state (fail deque, user deque)
   b. Applies zero-trust threshold scaling via _zt_threshold()
   c. Evaluates applicable rules
   d. Calls _kc_update() which updates kill chain + publishes to federation
   e. Calls _maybe_fire() if threshold exceeded

5. _maybe_fire() creates a Detection, then:
   - Logs the incident (store.py + JSON logger)
   - Notifies (Telegram/Discord/Slack/Email/Webhook)
   - Blocks the IP if HIGH severity (blocker.py)
   - Applies pattern learner on_alert()
   - Pushes to SIEM connectors (siem_router.push())
   - Updates zero-trust signals

6. Correlator runs cross-source rules after every detection.
   Correlation alerts may escalate severity and trigger additional blocks.

7. Dashboard reads live state via REST API and SSE stream.
   All tabs use the same auth + rate-limiting middleware.
```

## Key Design Decisions

**Async throughout.** Engine, dashboard, log tailers, network I/O -- all asyncio. No threads except where a library forces it (e.g. scikit-learn training runs in an executor).

**Dry-run safe by default.** `actions.dry_run: true` means no real iptables changes until the operator enables `--execute`. All tests run in dry-run mode.

**SQLite for everything.** Incidents, FIM baselines, kill chain records, trust scores, pattern suggestions, UEBA profiles, and case notes all persist in a single SQLite database. No external database dependency.

**No external dependencies for core detection.** The detection engine works with Python stdlib only. Optional packages (aiohttp, scikit-learn, MaxMind, Redis, aiosqlite) unlock additional features but are never required for basic SSH/web/DB detection.

**Single hook point per integration.** Rather than scattering `kill_chain.update()` and `federation.publish()` calls throughout the codebase, both are called through the `_kc_update()` helper in detector.py. This ensures kill chain and federation can never drift out of sync.

**Zero new infrastructure for federation.** The federation bus reuses the existing Redis connection from `redis_sync.py`. Operators who already have Redis for blocklist sync get cross-node detection sharing automatically when they set `federation.enabled: true`.