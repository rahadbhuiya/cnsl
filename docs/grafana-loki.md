# Grafana Loki input

CNSL can pull logs from Loki with `query_range`. Configure one profile per
LogQL query under `observability_sources`; it is disabled by default. Alloy
should send logs to Loki. Direct Alloy HTTP/OTLP ingest is not included yet.

The example profile in `config/config.example.json` shows a JSON security event
with nested `field_map` paths. Set `observability_sources.enabled` and the
profile's `enabled` flag, then set the bearer secret in the CNSL process
environment (for example `CNSL_LOKI_TOKEN`). The `url` is the Loki base URL;
the client appends `/loki/api/v1/query_range`. TLS certificate verification is
on by default.

Supported parsers are `json_security`, `nginx`, `apache`, `mysql`, `ufw`,
`syslog`, and `wazuh`. JSON events need a mapped `kind` (or `event_kind`), and
may map `timestamp`, `src_ip`, `dst_ip`, `user`, and `message`. `labels` and
`services` are post-query allow-filters; they do not rewrite the LogQL query.
The service selector checks Loki's `service`, `app`, or `application` label.

Each profile feeds parsed events into CNSL's shared event queue. Loki timestamps
are checkpointed in the SQLite store, and stream/timestamp/line fingerprints
avoid replaying an already committed record. Queue pressure delays checkpoint
advancement and causes the profile to retry with exponential backoff. Source
activity and per-profile counters appear in the authenticated
`GET /api/source-health` response. Counters are in memory; checkpoints and
deduplication keys persist across restarts.

Install the `aiohttp` and `aiosqlite` optional dependencies to use Loki pull.
Loki profiles currently require the SQLite store. PostgreSQL and Alloy direct
ingest are not supported by this initial milestone.
