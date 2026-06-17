# Automated Pattern Learning

CNSL observes recurring event sequences that precede attacks and automatically
generates suggested detection rules. Operators can promote suggestions to live
rules with one click from the dashboard.

This implements the "automated pattern discovery" goal from the original CNSL
research paper:

> "The system should be capable of automated discovery of new intent patterns
>  without requiring manual rule authoring."


## Why pattern learning?

The built-in ruleset covers known attack patterns. But every environment is
different -- your infrastructure may attract attack sequences that are not
covered by any hardcoded rule. Pattern learning watches what actually happens
in your environment and tells you what it found.

A suggested rule is not applied automatically. It is presented to you for
review. You decide whether it makes sense for your environment, then promote
or dismiss it.


## How it works

### 1. Event observation

Every event that passes through the detector is recorded in a per-IP sliding
window buffer. The buffer keeps the last N seconds of events for each source IP
(default: 5 minutes).

### 2. Alert trigger

When a detection alert fires for an IP, the learner extracts the event sequence
from that IP's buffer -- the full set of event kinds that appeared in the window
leading up to the alert.

### 3. Fingerprinting

The event sequence is normalized into a pattern fingerprint: a sorted,
deduplicated list of event kinds joined with `+`. This makes the fingerprint
stable regardless of event order or count.

Examples:
```
SSH_FAIL+WEB_SCAN
DB_AUTH_FAIL+SSH_FAIL+WEB_AUTH_FAIL
FW_HONEYPOT_PORT+SSH_FAIL+THREAT_FEED_HIT
```

### 4. Counting

Fingerprints are counted across all alerts. Each time a fingerprint appears,
its occurrence count increments. When it crosses `min_occurrences` (default: 5),
it becomes a `SuggestedRule`.

### 5. Suggested rule

Each suggestion includes:
- The event kinds in the pattern
- Occurrence count (how many times this preceded an alert)
- Confidence score (0.0-1.0)
- Suggested severity (HIGH if exploit/breach kinds present, else MEDIUM)
- Suggested threshold (median observed event count when pattern fired)
- Suggested detection window (equal to lookback_sec)
- Up to 5 example IPs that triggered the pattern
- First and last seen timestamps

### 6. Operator review

From the dashboard Rules tab, under Suggested Rules, you can:
- **Promote** -- marks the suggestion as promoted and applies the suggested
  threshold, severity, and window as an override to the matching rule in the
  rule engine. If no matching rule exists, the override is stored for future use.
- **Dismiss** -- suppresses this suggestion permanently. The pattern key is
  added to the dismissed set and will never generate a suggestion again.

### ML anomaly integration

When `ml_detector` reports an anomaly, the anomaly reasons are also fed into
the pattern learner alongside the current event buffer for that IP. This means
ML-detected anomalies contribute to pattern discovery even when they do not
trigger a threshold-based detection rule.


## Configuration

```json
{
  "pattern_learning": {
    "enabled":        true,
    "lookback_sec":   300,
    "min_occurrences": 5,
    "max_suggestions": 50,
    "persist":        true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable or disable pattern learning entirely |
| `lookback_sec` | `300` | How many seconds of events to look back when an alert fires |
| `min_occurrences` | `5` | How many times a pattern must be seen before generating a suggestion |
| `max_suggestions` | `50` | Maximum suggestions to keep in memory. Weakest (lowest confidence) is evicted when full. |
| `persist` | `true` | Persist suggestions to SQLite so they survive a restart |


## REST API

### List suggestions

```
GET /api/pattern-suggestions
```

Query parameters:

| Parameter | Default | Description |
|:---|:---|:---|
| `dismissed` | `false` | Include dismissed suggestions |
| `promoted` | `false` | Include already-promoted suggestions |

Returns an array of suggestion objects sorted by confidence descending.

---

### Get aggregate statistics

```
GET /api/pattern-suggestions/stats
```

Returns:

```json
{
  "enabled":            true,
  "total_suggestions":  12,
  "active_suggestions": 9,
  "dismissed":          2,
  "promoted":           1,
  "patterns_tracked":   47,
  "min_occurrences":    5
}
```

---

### Promote a suggestion

```
POST /api/pattern-suggestions/{id}/promote
```

Marks the suggestion as promoted and returns the full suggestion object.
The dashboard additionally calls `PATCH /api/rules/{rule_id}` to apply
the suggested threshold/severity/window as a live rule override.

---

### Dismiss a suggestion

```
POST /api/pattern-suggestions/{id}/dismiss
```

Suppresses the suggestion permanently. Returns `{"ok": true}`.


## Suggestion object schema

```json
{
  "id":              "a3f9c1b2e8d4",
  "pattern_key":     "SSH_FAIL+WEB_SCAN",
  "event_kinds":     ["SSH_FAIL", "WEB_SCAN"],
  "occurrences":     11,
  "confidence":      1.0,
  "severity":        "MEDIUM",
  "threshold":       8,
  "window_sec":      300,
  "example_ips":     ["45.33.32.1", "192.168.1.44"],
  "first_seen":      "2024-11-01T02:14:33Z",
  "last_seen":       "2024-11-01T09:41:07Z",
  "dismissed":       false,
  "promoted":        false,
  "suggested_rule_id": "learned.ssh_fail_web_scan"
}
```


## Database schema

```sql
CREATE TABLE pl_suggestions (
    id           TEXT PRIMARY KEY,
    pattern_key  TEXT NOT NULL,
    event_kinds  TEXT NOT NULL,
    occurrences  INTEGER DEFAULT 0,
    confidence   REAL DEFAULT 0.0,
    severity     TEXT DEFAULT 'MEDIUM',
    threshold    INTEGER DEFAULT 1,
    window_sec   INTEGER DEFAULT 60,
    example_ips  TEXT DEFAULT '[]',
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    dismissed    INTEGER DEFAULT 0,
    promoted     INTEGER DEFAULT 0
);
```


## Dashboard

The Suggested Rules panel appears below the Alert Rules table in the Rules tab.

**Stats bar** shows: patterns tracked, active suggestions, promoted count,
dismissed count, min_occurrences threshold.

**Table columns**: Pattern (event kinds), Confidence (progress bar + %), 
Occurrences, Severity, Threshold, Window, Example IPs, Last Seen, Actions.

**Promote** applies the suggestion to the live rule engine and marks it done.
**Dismiss** suppresses it permanently.

The panel reloads automatically when the Rules tab is opened.


## Tuning

**Too many suggestions appearing:** Increase `min_occurrences` (e.g. 10-20).

**Suggestions not appearing:** Decrease `min_occurrences` or increase
`lookback_sec` so more events are captured per alert.

**Pattern is too broad:** Dismiss it and wait -- if the specific sub-pattern
(e.g. only `SSH_FAIL+WEB_SCAN` rather than `DB_AUTH_FAIL+SSH_FAIL+WEB_SCAN`)
appears enough times it will generate its own suggestion.


## Origin

Pattern learning is the direct implementation of the research paper goal:
*"automated discovery of new intent patterns."*

The original research used hardcoded event sequences (day3-day13 prototypes)
and noted that manual rule authoring did not scale. The pattern learner
automates what was previously done by hand -- watching which event combinations
reliably preceded attacks and encoding them as rules.

See `../old-research/paper/paper.md` for the original research paper.