# Zero-Trust Trust Score Engine

CNSL maintains a per-entity trust score that reflects how much it trusts
an IP address or username based on observed behavior. Low-trust entities
trigger alerts with fewer events -- a suspicious entity doesn't get the
same benefit of the doubt as a known-good one.

This implements the zero-trust architecture support gap from the CNSL
research paper:

> "Future work includes zero-trust architecture support: identity-based
>  trust scoring so the same IP from an admin account and an attacker
>  are treated differently."


## The problem without zero-trust

Traditional CNSL treats every IP identically. If the default SSH
brute-force threshold is 8 failures, an attacker needs exactly 8 failures
to trigger an alert -- whether they have been blocked 10 times before or
this is their first connection.

Zero-trust says: an entity that has already demonstrated risky behavior
should need to do less to trigger an alert. If an IP is seen launching
a port scan (lowering its trust score), subsequent SSH failures from that
same IP should alert sooner.


## Trust score mechanics

### Initial score

Every new entity starts at `initial_score` (default 0.8 -- trusted but
not implicitly). The score lives in the range `[min_score, 1.0]`.

### Score labels

| Score | Label | What it means |
|:---|:---|:---|
| 0.8 - 1.0 | Trusted | Known entity, good behavior history |
| 0.5 - 0.8 | Moderate | Some anomalies or unknown elements |
| 0.2 - 0.5 | Suspicious | Multiple anomalies or risk signals |
| 0.05 - 0.2 | Untrusted | Active threat signals -- alert aggressively |

### Signals

Trust signals are named events that increase or decrease the score:

| Signal | Delta | Trigger |
|:---|:---|:---|
| `known_ip_login` | +0.05 | SSH login from an IP the user has used before |
| `normal_hour_login` | +0.02 | Login at a normal hour for this user |
| `unknown_ip_login` | -0.10 | SSH login from a new, unseen IP |
| `ueba_anomaly` | -0.20 | UEBA engine detects behavioral anomaly |
| `brute_force_fail` | -0.05 | SSH or web auth failure (per event) |
| `mfa_failure` | -0.25 | Cloud MFA challenge failed or bypassed |
| `cloud_risk_flag` | -0.30 | Azure AD risk engine flags the sign-in |
| `impossible_travel` | -0.35 | Two sign-ins from geographically impossible locations |
| `block_applied` | -0.40 | CNSL blocks this entity |
| `correlation_alert` | -0.15 | Cross-source correlation alert fires |

### Score decay

Scores recover toward `initial_score` at a rate of `recovery_per_day`
per day of inactivity. An entity that goes quiet after suspicious
behavior will gradually return to trusted status.

Example: entity with score 0.3 (suspicious), `recovery_per_day=0.05`:
- After 2 days quiet: score = 0.3 + (2 * 0.05) = 0.4
- After 10 days quiet: score = min(0.8, 0.3 + (10 * 0.05)) = 0.8 (restored)


## How trust affects detection

When `apply_to_threshold` is true (default), the detection threshold for
an entity is multiplied by its trust score:

```
effective_threshold = ceil(normal_threshold * trust_score)
```

Examples with `ssh.brute_force` default threshold = 8:

| Trust score | Label | Effective threshold | Events needed to alert |
|:---|:---|:---|:---|
| 1.0 | Trusted | ceil(8 * 1.0) = 8 | 8 failures |
| 0.75 | Moderate | ceil(8 * 0.75) = 6 | 6 failures |
| 0.5 | Suspicious | ceil(8 * 0.5) = 4 | 4 failures |
| 0.2 | Untrusted | ceil(8 * 0.2) = 2 | 2 failures |
| 0.05 | Untrusted | ceil(8 * 0.05) = 1 | 1 failure |

The effective threshold is always at least 1 -- a zero-threshold is
never applied.

### Which rules use trust-adjusted thresholds

- `ssh.brute_force` -- IP trust score
- `ssh.credential_stuffing` -- IP trust score
- `cloud.signin_brute_force` -- IP trust score

Rules with `threshold = 1` (MFA failure, risky signin, impossible travel)
are unaffected since `ceil(1 * any_score) = 1`.


## Configuration

```json
{
  "zero_trust": {
    "enabled":            true,
    "initial_score":      0.8,
    "min_score":          0.05,
    "recovery_per_day":   0.05,
    "persist":            true,
    "max_entities":       50000,
    "apply_to_threshold": true
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `true` | Enable zero-trust scoring |
| `initial_score` | `0.8` | Starting score for new entities |
| `min_score` | `0.05` | Floor -- score never drops below this |
| `recovery_per_day` | `0.05` | Score improvement per day of quiet |
| `persist` | `true` | Save scores to SQLite |
| `max_entities` | `50000` | Max entities in memory (oldest evicted) |
| `apply_to_threshold` | `true` | Whether to scale detection thresholds |

To disable threshold scaling while keeping scoring visible:
```json
{"zero_trust": {"apply_to_threshold": false}}
```


## REST API

### Aggregate statistics

```
GET /api/zero-trust/stats
```

```json
{
  "enabled":        true,
  "total_entities": 142,
  "trusted":        98,
  "moderate":       30,
  "suspicious":     12,
  "untrusted":      2,
  "avg_score":      0.71,
  "min_score_seen": 0.12
}
```

### List all scored entities

```
GET /api/zero-trust/scores?type=ip&max_score=0.5&limit=50
```

Query parameters:

| Parameter | Default | Description |
|:---|:---|:---|
| `type` | (all) | Filter by entity type: `ip` or `user` |
| `max_score` | `1.0` | Return only entities with score <= this value |
| `limit` | `100` | Maximum rows to return |

Returns entities sorted by score ascending (lowest trust first).

### Get one entity

```
GET /api/zero-trust/scores/{entity_id}?type=ip
```

```json
{
  "entity_id":    "45.33.32.1",
  "entity_type":  "ip",
  "score":        0.35,
  "label":        "suspicious",
  "signal_count": 14,
  "last_updated": "2024-11-15T02:14:33Z",
  "recent_signals": [
    {"ts": "2024-11-15T02:01:00Z", "signal": "brute_force_fail", "delta": -0.05},
    {"ts": "2024-11-15T02:01:05Z", "signal": "brute_force_fail", "delta": -0.05},
    {"ts": "2024-11-15T02:14:33Z", "signal": "ueba_anomaly",     "delta": -0.20}
  ]
}
```

### Reset entity to initial score

```
POST /api/zero-trust/scores/{entity_id}/reset?type=ip
```

Returns `{"ok": true}`. Use this when an entity is known good and has
been unfairly penalized (e.g. a legitimate administrator tripped the
unusual-hour detector).


## Dashboard

The Zero-Trust Trust Scores panel appears in the Settings tab, above
the Cloud Identity Connectors section.

**Stats bar**: total entities, count per label, average score.

**Entity table**: sorted by score ascending (untrusted first). Columns:
entity ID, type (IP or user), trust label (color-coded), score bar,
signal count, last signal received, Reset button.

**Reset button**: restores the entity's score to `initial_score` and
records a `manual_reset` signal. Does not delete the signal history.


## Database schema

```sql
CREATE TABLE zt_scores (
    entity_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL DEFAULT 'ip',
    score         REAL NOT NULL DEFAULT 0.8,
    last_updated  REAL NOT NULL,
    signal_count  INTEGER DEFAULT 0,
    last_signal   TEXT DEFAULT '',
    PRIMARY KEY (entity_id, entity_type)
);
```


## Interaction with other modules

**UEBA**: when UEBA detects a behavioral anomaly on successful login,
`UEBA_ANOMALY` is applied to the *user's* trust score. When login is
normal from a known IP, `KNOWN_IP_LOGIN` is applied (small trust boost).

**Cloud identity**: MFA failures apply `MFA_FAILURE` to both the IP
and the user. Azure risky sign-ins apply `CLOUD_RISK_FLAG` to both.

**Kill chain**: zero-trust does not directly update the kill chain, but
because it lowers the effective threshold for suspicious entities, it
causes earlier kill chain stage transitions (e.g. Delivery fires sooner
when an IP already has a low trust score).

**Pattern learner**: zero-trust does not interact with pattern learning
directly, but because trust-adjusted thresholds cause earlier alerting,
patterns for low-trust IPs will have lower threshold values in their
suggested rules.


## Origin

Zero-trust support was listed as future work in the research paper,
specifically noting that "the same IP from an admin account and an
attacker" should be treated differently. This implementation uses
behavioral evidence (UEBA, cloud risk, MFA) to build the identity-based
trust score the paper described.

CNSL originated as a research prototype. The original research paper is available in the separate `cnsl-research` repository.