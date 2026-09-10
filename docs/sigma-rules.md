# Sigma Rule Import

CNSL can import [Sigma](https://github.com/SigmaHQ/sigma) detection rules
and evaluate them against every event it already processes. Sigma is the
closest thing the detection-engineering community has to a common rule
format -- importing a rule pack gives CNSL detection logic nobody here
had to hand-write, and gives teams already using Sigma elsewhere a way
to bring their rules along instead of re-learning CNSL's own rule format.

## What's supported

This is a practical **subset** of the Sigma spec, not the full spec.

Supported:
- `detection:` blocks with named selections and a `condition` string
- Selections as a map (AND of fields), a list of maps (OR), or a plain
  list of strings (keyword/full-text search)
- Field modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `cased`
- Condition operators: `and`, `or`, `not`, parentheses, `N of x*`,
  `all of x*`, `1 of them` / `all of them`
- `logsource`, `level`, `tags`, `falsepositives`, `references` --
  carried through as metadata (see note below on `logsource`)

**Not** supported -- rejected at import time with a specific reason,
never silently mis-evaluated:
- Sigma "correlation" rules (the newer cross-event spec extension). CNSL
  already has its own threshold/correlation engine (`cnsl/rules.py`,
  `cnsl/correlator.py`) for cross-event and aggregation logic -- Sigma
  import here is strictly per-event field matching.
- Field modifiers beyond the list above (`base64`, `cidr`, `fieldref`,
  `expand`, ...)

### Why `logsource` isn't used to filter events

Sigma's `logsource` block (`product`, `service`, `category`) assumes a
taxonomy built around Windows Event Log channels and Sysmon event types.
CNSL's Linux-focused, normalized `Event` model doesn't share that
taxonomy, and building (and inevitably getting wrong) a mapping from
every `logsource` combination to CNSL's own event kinds isn't worth it.

Instead, every enabled rule's detection logic is evaluated against every
event's actual fields. A rule whose fields never appear in any event
this instance produces simply never fires -- the same practical outcome
as filtering by `logsource`, without a mapping to maintain.

**Consequence**: most public Sigma rules target Windows/Sysmon fields
(`EventID`, `Image`, `CommandLine`, `TargetUserName`, ...) that CNSL's
sources don't produce. Only a fraction of any given community rule pack
will ever match live traffic here -- that's expected. The value is
interoperability, not "every imported rule fires."

## Field resolution

When a rule's selection checks a field, CNSL resolves it in this order:

1. **Alias table** -- common field names map onto the Event's own typed
   attributes, so rules don't need to match CNSL's exact field names:

   | Sigma field (any of) | Resolves to |
   |:---|:---|
   | `SourceIp`, `src_ip`, `ip`, `ClientIp`, `c-ip` | `event.src_ip` |
   | `DestinationIp`, `dst_ip` | `event.dst_ip` |
   | `User`, `TargetUserName`, `account`, `AccountName` | `event.user` |
   | `kind`, `EventKind` | `event.kind` (CNSL's own event-kind string, e.g. `SSH_FAIL`) |
   | `source` | `event.source` |

2. **`event.meta`** (case-insensitive) -- parsers already extract
   structured per-source fields here (`event_name`, `rule_id`,
   `agent_name`, `method`, `path`, ...). This is where most useful
   matching happens for CNSL-specific sources (cloud identity, Wazuh,
   OT/ICS).

3. **`event.raw`**, last resort -- a plain substring search over the raw
   log line, for a field that isn't captured anywhere else. No
   modifier logic applies here beyond containment.

## Setup

1. Get some Sigma rules. Point `sigma.rules_dir` at a checkout of the
   community rule repo, or a directory of your own `.yml` files:
   ```bash
   git clone https://github.com/SigmaHQ/sigma /etc/cnsl/sigma-rules
   ```
2. Enable it in `config.json`:
   ```json
   {
     "sigma": {
       "enabled":   true,
       "rules_dir": "/etc/cnsl/sigma-rules"
     }
   }
   ```
3. Restart CNSL. Import results are logged as a `sigma_import` event:
   `{"rules_dir": "...", "imported": N, "failed": M, "errors": [...]}`.
   `failed` rules are skipped, not fatal -- one malformed rule in a pack
   of 500 doesn't block the other 499. Check the `errors` list (each
   entry has `path` and `error`) to see why a specific file didn't import.

## Writing your own rule

A minimal rule CNSL can import:

```yaml
title: SSH login as root
id: cnsl-ssh-root-login
level: high
description: Flags any successful SSH login as the root user.
tags:
  - attack.initial_access
  - attack.t1078
logsource:
  product: linux
  service: sshd
detection:
  selection:
    kind: SSH_SUCCESS
    user: root
  condition: selection
falsepositives:
  - Legitimate root logins from an admin jump host
references:
  - https://attack.mitre.org/techniques/T1078/
```

A rule using OR, a keyword list, and a modifier:

```yaml
title: Suspicious download tool in a web request path
level: medium
detection:
  tool_in_path:
    path|contains:
      - wget
      - curl
  suspicious_keyword:
    - "/etc/passwd"
    - "../../"
  condition: tool_in_path or suspicious_keyword
```

## Severity mapping

Sigma's `level` maps onto CNSL's LOW/MEDIUM/HIGH:

| Sigma `level` | CNSL severity |
|:---|:---|
| `informational`, `low` | `LOW` |
| `medium` (or unrecognized) | `MEDIUM` |
| `high`, `critical` | `HIGH` |

## How matches are handled

Every enabled Sigma rule is evaluated on every event that reaches
CNSL's detector (the same events the built-in threshold rules see --
auth, web, db, firewall, cloud identity, OT/ICS, and relayed Wazuh
alerts). Unlike the threshold rules, Sigma matching is per-event, not
per-window: a matching rule fires immediately, and one event can trigger
more than one Sigma rule.

Each match:
- Updates the kill chain (`SIGMA_MATCH` -> Exploitation stage)
- Is logged as a `sigma_match` event (`ip`, `rule_id`, `title`,
  `severity`, `tags`)
- Goes through the same incident path as everything else (`_maybe_fire`)
  -- same per-IP cooldown, AbuseIPDB check, storage, case creation, and
  notification as a built-in rule firing

## Runtime control

- **Master switch**: the `sigma.match` entry in the rules API
  (`GET/PATCH /api/rules/sigma.match`) turns all Sigma matching on or
  off without re-importing anything.
- **Per-rule**: each imported rule can be individually enabled/disabled
  -- see `cnsl/sigma.py`'s `SigmaRuleStore.enable()` / `.disable()`.
  Disabled rules are skipped during evaluation but stay imported (no
  need to re-import to turn one back on).

## Troubleshooting

| Symptom | Likely cause |
|:---|:---|
| `sigma_import` log shows `failed > 0` | Check the `errors` list -- usually an unsupported modifier, a correlation rule, or a missing `condition` |
| A rule imports fine but never fires | Its fields likely don't appear in any event CNSL produces (see the `logsource` note above) -- this is expected for most Windows/Sysmon-oriented rules |
| `PyYAML not installed` error | `pip install PyYAML` (this is already a core CNSL dependency, so this usually means a broken environment) |
| Rule fires on every event | Check for a selection with an empty or overly broad field match, or a `condition` that evaluates unconditionally true |