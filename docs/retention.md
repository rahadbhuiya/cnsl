# Data Retention

`cnsl/store.py`'s `incidents` table and `cnsl/audit.py`'s `audit_log`
table accumulate rows forever -- neither module deletes anything on its
own. On a long-running deployment that means unbounded disk growth and,
eventually, slower queries on tables with no natural cap. Retention
adds a time-based purge (with optional archival) to close that.

Disabled by default. Nothing is ever deleted unless you turn it on.

## Scope

**Purged**: `incidents`, and -- only if explicitly configured --
`audit_log`.

**Not touched**, deliberately:

| Table / data | Why not |
|:---|:---|
| `cases` (`cnsl/cases.py`) | An open investigation's age isn't a signal it's safe to delete. Cases store their own denormalized copy of severity/reasons/src_ip, so purging the originating incident doesn't break a case. |
| `blocks` (`cnsl/store.py`) | Already self-cleans when an IP is unblocked (`cnsl/blocker.py`); never accumulates stale rows. |
| Kill chains, UEBA profiles, pattern-learner suggestions | Each already has its own size-based cap (`kill_chain.max_chains`, `pattern_learning.max_suggestions`, ...) -- a different, already-solved problem from unbounded *time* growth. |

## Compliance warning

If you use compliance reporting (`cnsl/compliance.py` --
SOC2/ISO27001/PCI-DSS), **audit log retention must meet or exceed your
framework's minimum**. Most require at least one year of audit trail.

`audit_log_max_age_days` defaults to `0` (never purge) specifically so
that enabling incident retention doesn't silently start deleting audit
records too. Purging audit logs is a separate, deliberate opt-in, and
the config validator warns if you set it below 365 days.

## Config

```json
{
  "retention": {
    "enabled":                false,
    "run_interval_hours":     24,
    "incidents_max_age_days": 90,
    "audit_log_max_age_days": 0,
    "archive_before_delete":  true,
    "archive_dir":            "/var/lib/cnsl/archives"
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Master switch. Nothing is deleted while this is false |
| `run_interval_hours` | `24` | How often the background pass runs |
| `incidents_max_age_days` | `90` | Purge incidents older than this. `0` disables incident purging |
| `audit_log_max_age_days` | `0` | Purge audit rows older than this. `0` (default) means never -- see the compliance warning above |
| `archive_before_delete` | `true` | Export rows to a compressed file before deleting them |
| `archive_dir` | | Where archives are written. Required when `archive_before_delete` is true |

The validator warns if `incidents_max_age_days` is under 7 days
(incidents that recent may still matter to an open investigation) and
if `audit_log_max_age_days` is under 365.

## Archives

Archived rows are written as gzip-compressed JSONL -- one JSON object
per line -- named `<table>_<cutoff-date>_<row-count>.jsonl.gz`:

```
/var/lib/cnsl/archives/incidents_20260618_1423.jsonl.gz
```

```bash
zcat /var/lib/cnsl/archives/incidents_20260618_1423.jsonl.gz | head -1
```

This is a **flat-file export for cold storage, not a restorable CNSL
backup**. There's no "unarchive" command -- the format is meant for
grep/jq/ingestion into a data warehouse. For actual backup and restore,
see `cnsl/backup.py` and the backup CLI.

## API

```
GET /api/retention/status
```

Returns the current config plus the last run's result:

```json
{
  "enabled": true,
  "run_interval_hours": 24,
  "incidents_max_age_days": 90,
  "audit_log_max_age_days": 0,
  "archive_before_delete": true,
  "archive_dir": "/var/lib/cnsl/archives",
  "last_run_at": 1789534223.13,
  "last_result": {
    "ran": true,
    "incidents": {"purged": 1423, "archived_to": "/var/lib/cnsl/archives/incidents_20260618_1423.jsonl.gz"},
    "audit_log": {"purged": 0, "archived_to": null, "skipped": "not configured"}
  }
}
```

```
POST /api/retention/run
```

Runs a pass immediately instead of waiting for the next scheduled one
-- useful right after lowering `incidents_max_age_days`. Requires
`config:write` (admin).

Both a scheduled and a manual run log a `retention_run` event with the
purge counts and archive paths.

## Choosing a retention period

- **90 days** (the default) is a reasonable starting point for incident
  data -- long enough for trend analysis and retrospective
  investigation, short enough to bound growth.
- **Shorter** makes sense on a high-volume deployment where the store
  grows fast and older incidents are already exported to a SIEM
  (see `docs/siem-connectors.md`) -- in that case CNSL's own store is
  a working set, not the system of record.
- **Longer, or disabled**, makes sense if CNSL *is* your system of
  record and disk isn't a constraint.

Start with `archive_before_delete: true` until you're confident about
the retention period. Deleting is irreversible; archiving first costs
only disk.