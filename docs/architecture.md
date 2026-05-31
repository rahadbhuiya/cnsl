# Architecture

## Module Map

```
cnsl/
├── models.py            Event, Detection dataclasses + constants
├── config.py            Config loading, deep merge, typed accessors
├── validator.py         Startup config validation with actionable errors
├── logger.py            Async JSON logger (text labels, no emoji)
│
├── parsers.py           auth.log + tcpdump line parsers
├── log_sources.py       nginx, apache, mysql, ufw, syslog parsers
├── sources.py           Async log file tailers (inotify-style)
├── syslog_receiver.py   UDP/TCP syslog server (RFC 3164 / RFC 5424)
│
├── normalizer.py        ECS-compatible event normalization + CEF export
├── search_engine.py     KQL-like search, aggregations, Elasticsearch push
│
├── detector.py          Stateful per-IP detection engine (all rule evaluation)
├── correlator.py        Cross-source correlation (6 rules, 60s window)
├── ml_detector.py       ML anomaly detection (IsolationForest, auto-trains)
├── threat_intel.py      AbuseIPDB lookups + behavioral baseline
│
├── blocker.py           iptables / ipset blocking backend
├── honeypot.py          Fake SSH server (40+ commands, virtual filesystem)
├── redis_sync.py        Distributed blocklist via Redis pub/sub
│
├── geoip.py             GeoIP enrichment (MaxMind offline + ip-api.com fallback)
├── assets.py            Passive asset inventory via network events
├── fim.py               File Integrity Monitoring (recursive directory watch)
│
├── auth.py              JWT authentication (bcrypt password hashes)
├── rbac.py              Role-based access control (viewer/analyst/auditor/admin)
├── dashboard.py         Web dashboard + REST API + SSE live feed
├── metrics.py           Prometheus metrics (counters + gauges)
├── grafana.py           Grafana dashboard JSON template generator
├── reporter.py          PDF / HTML compliance reports (SOC2, ISO27001, PCI-DSS)
├── notify.py            Telegram, Discord, Slack, Email, generic webhook
├── store.py             SQLite async persistence (aiosqlite)
└── engine.py            Main async event loop + CLI argument parser
```

---

## Event Flow

```
Log Files / Network / Remote Syslog
           │
           ▼
    parsers / log_sources            ← parse raw lines into Event objects
           │
           ▼
    asyncio.Queue  (maxsize=10000)   ← backpressure — drops when full
           │
           ▼
    engine_loop()
      │
      ├── normalizer.py              ← attach ECS schema to ev.meta["_ecs"]
      │
      ├── detector.handle(ev)
      │     ├── country_block check  ← immediate HIGH block if in blocked list
      │     ├── per-IP state update  ← sliding windows (fails, users, web hits)
      │     ├── rule evaluation      ← brute-force, stuffing, breach, web, db, fw
      │     ├── AbuseIPDB pre-check  ← known-bad IPs flagged on first event
      │     ├── GeoIP enrichment     ← country, city, ISP, proxy flag
      │     ├── correlator.ingest()  ← cross-source rules (6 rules)
      │     ├── baseline.observe()   ← behavioral anomaly detection
      │     └── incident → log → store → notify → block (if HIGH)
      │
      └── ml_detector.ingest(ev)     ← feature extraction + anomaly score
           │
           └── (on anomaly) → incident logged
```

---

## Concurrency Model

CNSL is a single-process async application built on `asyncio`.

- All I/O (log tailing, HTTP API, GeoIP lookups, notifications) is non-blocking
- Blocking operations (iptables, SMTP, ML training) run in a thread executor
- One `asyncio.Queue` decouples producers (parsers) from consumers (detector)
- Queue `maxsize=10000` provides backpressure — events are dropped (not buffered forever) if the engine falls behind

---

## Persistence

SQLite via `aiosqlite`. Schema:

| Table | Columns | Purpose |
|:---|:---|:---|
| `incidents` | id, ts, ip, severity, kind, reasons, fail_count, geo_json | Incident history |
| `blocks` | ip, blocked_at, unblock_at, reason, dry_run | Active + expired blocks |
| `fim_baseline` | path, mtime, size, sha256, permissions | FIM file state |

The `store.init()` method runs `CREATE TABLE IF NOT EXISTS` and auto-migrates
old schemas (adds missing columns with `ALTER TABLE ADD COLUMN`).

---

## Dashboard (SSE + REST)

The dashboard is a single-file async HTTP server built on `aiohttp`.

- Static HTML/JS/CSS is served inline (no build step, no npm)
- Live events stream via SSE (`/api/events/stream`) — the browser keeps one
  long-lived connection open
- REST endpoints serve JSON from SQLite or in-memory state
- JWT tokens are issued on login and validated on every request
- RBAC checks happen at the route handler level before any data is returned

---

## Scaling

CNSL is designed for single-server deployment. For multi-server setups:

- Run one CNSL instance per server
- Enable Redis (`"redis": { "enabled": true }`) to share the blocklist
- Blocks propagated via Redis pub/sub are applied locally by each node
- Unblocks are also propagated — the cluster stays consistent

For high-volume environments (>10k events/sec) consider Kafka ingestion
(on the roadmap) or pre-filtering with a BPF/eBPF layer before CNSL.