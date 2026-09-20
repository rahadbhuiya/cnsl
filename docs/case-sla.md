# Case SLA Tracking and Escalation

`cnsl/cases.py` tracks a case's status, assignee, and notes -- but
nothing watches how *long* a case has sat in a given state. A
HIGH-severity case auto-created at 2am and never picked up looks
exactly like one opened a minute ago. This adds per-severity time
targets and flags cases that breach them.

Disabled by default.

## Two clocks

Every open case is measured against two independent targets:

- **Response** -- time from creation until someone picks it up
  (assigned, or moved out of `open`). Answers "did anyone look at
  this?"
- **Resolution** -- time from creation until the case reaches a
  resolved status (`closed` / `false_positive`). Answers "did anyone
  finish it?"

Both stop once the case resolves. A case closed within its resolution
target never breaches resolution even if it sat unassigned for a
while first -- that still counts as a **response** breach. The two are
reported separately rather than collapsed into one "breached"
boolean, because they mean different things about a team's workflow:
response breaches point at triage/staffing gaps, resolution breaches
point at cases that are stuck.

## Config

```json
{
  "case_sla": {
    "enabled":            false,
    "check_interval_sec": 300,
    "targets": {
      "HIGH":   {"response_minutes": 30,   "resolution_minutes": 240},
      "MEDIUM": {"response_minutes": 240,  "resolution_minutes": 1440},
      "LOW":    {"response_minutes": 1440, "resolution_minutes": 10080}
    },
    "escalate_on_breach": true,
    "bump_severity":      true,
    "notify_on_breach":   false
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Master switch |
| `check_interval_sec` | `300` | How often the background pass runs |
| `targets.<SEVERITY>.response_minutes` | see above | Minutes before an unpicked-up case is a response breach |
| `targets.<SEVERITY>.resolution_minutes` | see above | Minutes before an unresolved case is a resolution breach |
| `escalate_on_breach` | `true` | Annotate breached cases (see below) |
| `bump_severity` | `true` | Also bump severity one step on breach |
| `notify_on_breach` | `false` | Reserved -- not yet wired to a notification channel |

The validator warns if `response_minutes` exceeds `resolution_minutes`
for the same severity (a case can't be resolved before it's even been
responded to), and if a `targets` key isn't `LOW`/`MEDIUM`/`HIGH`.

## What escalation does -- and deliberately doesn't

On a breach, when `escalate_on_breach` is true:

1. **Appends a system note** to the case (visible in the case timeline
   like any other note), starting with `[SLA BREACH]` and naming which
   target(s) were missed and the case's current age.
2. **Optionally bumps severity** one step (`LOW` -> `MEDIUM` ->
   `HIGH`) when `bump_severity` is true. `HIGH` is terminal -- there's
   nothing above it, so a breached HIGH case just gets the note.

Escalation **never** changes status or assignee. A machine deciding a
case is "investigating" because a timer expired would misrepresent who
actually did what -- the entire point of flagging a breach is that
nobody has engaged with it yet.

A case is escalated **at most once** -- detected by the `[SLA BREACH]`
note already being present -- so a case sitting breached for a week
doesn't climb severity repeatedly or spam the timeline with duplicate
notes on every check.

## API

```
GET /api/case-sla/status
```

Current config plus the last check's result:

```json
{
  "enabled": true,
  "check_interval_sec": 300,
  "targets": { "...": "..." },
  "escalate_on_breach": true,
  "bump_severity": true,
  "notify_on_breach": false,
  "last_check_at": 1789534223.13,
  "last_result": {
    "ran": true,
    "checked": 12,
    "breached": 2,
    "escalated": 1,
    "breaches": [
      {"case_id": 42, "severity": "HIGH", "status": "open",
       "age_sec": 5400.0, "response_breached": true,
       "resolution_breached": false, "breached": true}
    ]
  }
}
```

```
POST /api/case-sla/check
```

Runs a check immediately instead of waiting for the next scheduled
pass -- useful right after changing `targets`. Requires `config:write`
(admin).

A check that finds any breach logs a `case_sla_breach` event with the
affected case IDs.

## Choosing targets

- Base targets on your team's actual staffing model, not aspiration --
  a 15-minute HIGH response target with no on-call rotation just means
  every HIGH case "breaches" immediately, which trains people to
  ignore the signal.
- LOW severity resolution defaults to a full week (`10080` minutes) --
  low-priority cases are expected to sit; the target exists mainly to
  catch cases that were never actually closed out, not to create
  urgency.
- If you use `bump_severity`, remember a breached MEDIUM case becomes
  HIGH and will then be measured against HIGH's (usually tighter)
  targets going forward -- this is intentional escalation pressure,
  but size your HIGH-severity capacity with that in mind.