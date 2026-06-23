# CNSL Architecture

## Overview

```
Log Sources --> Parsers --> Queue --> Detector --> Correlator --> Blocker
                                        |               |
                                   Kill Chain      Notifier
                                   Pattern Learner
                                   Zero-Trust
                                        |
                                  Dashboard (Web UI)
                                  SIEM Router (push)
                                  Reporter
```

## Module Map

```
cnsl/
-- __init__.py              package version (2.8.0)
-- __main__.py              python -m cnsl entrypoint
--
-- models.py                Event, Detection dataclasses
-- config.py                config loading and defaults
-- logger.py                async JSON logger
--
-- parsers.py               auth.log + tcpdump parsers
-- log_sources.py           nginx, mysql, ufw, syslog parsers + file tailer
-- syslog_receiver.py       UDP/TCP syslog ingestion (RFC 3164/5424)
-- kafka_consumer.py        Kafka log ingestion
-- agent.py                 remote log forwarder (WebSocket client)
--
-- detector.py              per-IP stateful detection engine
-- correlator.py            cross-source correlation (6 rules)
-- rules.py                 rule engine (14 built-in rules)
-- normalizer.py            ECS schema normalization
--
-- kill_chain.py            attack kill chain tracker (7 stages)
-- pattern_learner.py       automated pattern discovery + suggested rules
-- zero_trust.py            per-entity trust scoring
-- cloud_identity.py        AWS CloudTrail + Azure AD sign-in polling
-- federation.py            multi-node detection sharing (Redis pub/sub)
--
-- ml_detector.py           ML anomaly detection (IsolationForest)
-- ueba.py                  user/entity behavior analytics
-- threat_feed.py           community threat feeds (6 feeds, CIDR matching)
-- threat_intel.py          AbuseIPDB + behavioral baseline
--
-- blocker.py               iptables/ipset blocking backend
-- honeypot.py              fake SSH server (40+ commands)
-- active_response.py       honeypot redirect orchestration
--
-- siem_connectors.py       Splunk HEC + Sentinel + Webhook push
-- es_pusher.py             Elasticsearch/OpenSearch bulk push
-- redis_sync.py            distributed blocklist sync
-- federation.py            cross-node detection signal sharing
--
-- dashboard.py             web UI + REST API + SSE/WebSocket (4000+ lines)
-- search_engine.py         KQL-like full-text search
-- reporter.py              PDF/HTML/JSON compliance reports
-- metrics.py               Prometheus metrics
--
-- store.py                 SQLite-backed persistent state
-- cases.py                 security case management
-- fim_engine.py            file integrity monitoring
-- asset_inventory.py       passive asset discovery
-- geoip.py                 GeoIP enrichment
--
-- auth.py                  JWT + 2FA authentication
-- rbac.py                  role-based access control
-- rate_limiter.py          per-IP rate limiting
-- tenants.py               multi-tenant support
-- huddle_integration.py    load balancing across nodes
```

## Data Flow

1. Log sources (auth.log, nginx, mysql, ufw, syslog, Kafka, cloud APIs) are tailed or polled by source modules.
2. Each line is parsed into an `Event` (ts, source, kind, src_ip, user, raw, meta).
3. Events are put into a shared `asyncio.Queue`.
4. `engine_loop()` drains the queue and calls `detector.handle(ev)`.
5. Detector routes by `ev.kind` to the appropriate handler (`_on_ssh_fail`, `_on_web_event`, etc.).
6. Each handler updates per-IP state, evaluates rules, and calls `_maybe_fire()`.
7. `_maybe_fire()` creates a `Detection`, logs it, notifies, and optionally blocks.
8. `Correlator` runs cross-source rules after every detection.
9. Kill chain, pattern learner, zero-trust, federation, and SIEM router are called at each detection point.
10. Dashboard reads from the store and live detector state via REST API and SSE.

## Key Design Decisions

**Async throughout.** The engine, dashboard, log tailers, and all network I/O use `asyncio`. No threads.

**Dry-run by default.** `actions.dry_run: true` in config means no real iptables changes until the operator explicitly enables execution.

**SQLite persistence.** All incident history, FIM baselines, kill chain records, trust scores, and pattern suggestions survive restarts.

**No external dependencies for core detection.** Core detection works with stdlib only. Optional packages (aiohttp, scikit-learn, MaxMind, Redis) unlock additional features but are never required.