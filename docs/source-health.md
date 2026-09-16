# Log Source Health Monitoring

CNSL's detectors are only as good as the log sources feeding them. A
filebeat agent that silently stops, a log rotation that breaks tailing,
a Wazuh forwarder that loses its syslog connection -- any of these
leaves CNSL running and reporting "no incidents" while actually just
not seeing anything. Source health monitoring answers a different
question than the rest of CNSL: not "is this traffic malicious" but
"is this pipe still flowing at all."

## Scope

Covers every source started via `cnsl/log_sources.py`'s
`tail_log_file()`:
- The configured `log_sources` (nginx, apache, mysql, ufw, syslog,
  wazuh file forwarding)
- Zeek logs (when `zeek.enabled`)
- OT/ICS log sources (when `ot.enabled`)

**Not covered**, and intentionally so:
- `cnsl/syslog_receiver.py`'s UDP/TCP listeners -- a different
  ingestion model. There's no single file whose activity to watch, and
  a listener with zero traffic isn't distinguishable from "no attacker
  traffic right now" the way a stalled file tailer is.
- Cloud identity pollers (`cnsl/cloud_identity.py`) -- these already
  have their own per-connector `status()` / `last_error` reporting
  (see `docs/cloud-identity.md`), which serves the same purpose for a
  different ingestion model (scheduled API polling, not file tailing).

## How it works

1. Every `tail_log_file()` call registers its source name on start,
   and records activity on **every line it reads off the file** --
   whether or not that line parsed into an `Event`. A source producing
   unparseable lines is still alive; the question here is "is the pipe
   flowing," not "is every line understood."
2. A background loop checks every registered source's
   time-since-last-activity against a silence threshold (per-source or
   default) every `check_interval_sec`.
3. A source crossing the threshold logs a `source_silent` event
   **exactly once** (not every check interval) -- and a
   `source_recovered` event once activity resumes.

## Config

```json
{
  "source_health": {
    "enabled": true,
    "check_interval_sec": 60,
    "default_silence_threshold_sec": 900,
    "per_source_thresholds": {
      "mysql": 3600
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable the health-check background loop |
| `check_interval_sec` | `60` | How often to check every source against its threshold |
| `default_silence_threshold_sec` | `900` (15 min) | How long a source can go quiet before it's flagged |
| `per_source_thresholds` | `{}` | Per-source override, e.g. a naturally low-volume source like an error log that might legitimately be silent for hours |

`check_interval_sec` should not exceed `default_silence_threshold_sec`
-- the validator warns if it does, since a source could go silent and
recover between two checks without ever being flagged.

## API

```
GET /api/source-health
```

```json
{
  "enabled": true,
  "check_interval_sec": 60,
  "sources": [
    {
      "source": "nginx",
      "last_seen": "2026-09-15T10:22:00Z",
      "threshold_sec": 900,
      "healthy": true,
      "silent_for_sec": 42.3
    },
    {
      "source": "mysql",
      "last_seen": null,
      "threshold_sec": 3600,
      "healthy": true,
      "silent_for_sec": null
    }
  ]
}
```

A source with `last_seen: null` has been registered (its tailer
started) but hasn't produced a line yet -- reported as healthy rather
than silent, since a freshly-started tailer for a naturally low-volume
source shouldn't be immediately flagged.

## What "silent" doesn't mean

A source going silent means CNSL stopped receiving lines from it --
it says nothing about whether that's because the log agent died, the
file was deleted, the underlying service (nginx, mysql, ...) simply
had nothing to log, or the disk filled up. Investigate the actual
source before assuming an outage; a low-traffic service crossing its
threshold during a genuinely quiet period is an expected false
positive, which is exactly what `per_source_thresholds` is for.

## Choosing thresholds

- **High-volume sources** (nginx/apache access logs on anything with
  regular traffic): the default 15 minutes is usually generous --
  tighten it if you want faster detection.
- **Low-volume sources** (mysql error log, a rarely-triggered ufw
  rule): raise the threshold well above their normal quiet periods, or
  the health check will flag them constantly. An error log that only
  writes on actual errors might reasonably go silent for days.
- **Zeek/OT sources**: threshold depends entirely on the monitored
  traffic's baseline -- an OT network segment with infrequent
  legitimate Modbus polling looks very different from a busy
  perimeter link.