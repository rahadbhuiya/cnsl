# MITRE ATT&CK Technique Mapping

CNSL tags its built-in rules, correlation rules, and imported Sigma rules
with the [MITRE ATT&CK](https://attack.mitre.org/) technique(s) they
correspond to, and can report which techniques a given deployment
currently has live coverage for.

This is a tagging and reporting layer, not a new detector -- it doesn't
change what CNSL detects, only how that detection is labeled and
summarized.

## Scope

CNSL curates a **subset** of ATT&CK Enterprise techniques in
`cnsl/attack.py` -- only the ones its own detections plausibly
correspond to (brute force, scanning, exploitation of public-facing
services, privilege escalation, C2). It is not a copy of MITRE's full
knowledge base, and CNSL does not bundle or redistribute MITRE's
dataset; see [attack.mitre.org](https://attack.mitre.org/) for the
authoritative, current version of any technique.

ATT&CK's separate **ICS matrix** (technique IDs in a `T0xxx` namespace,
distinct from Enterprise's `T1xxx`) is out of scope. CNSL's two
OT/ICS-actuation rules (`ot.modbus_write`, `ot.scada_alarm`) describe
behavior the ICS matrix would represent more accurately than any
Enterprise technique, so they're intentionally left untagged rather
than force-fit onto the wrong matrix.

## Where technique tags live

| Source | Field | Example |
|:---|:---|:---|
| Built-in rules (`cnsl/rules.py`) | `Rule.attack_techniques` | `ssh.brute_force` -> `["T1110.001"]` |
| Correlation rules (`cnsl/correlator.py`) | `CorrelationRule.attack_techniques` | `web_recon_then_ssh` -> `["T1595", "T1110"]` |
| Sigma rules (`cnsl/sigma.py`) | the rule's own `tags:` list | `tags: [attack.t1190]` (Sigma's own community convention) |

Sigma rules don't get a separate CNSL-specific tagging scheme --
`cnsl/attack.py` reads the `attack.tNNNN` / `attack.tNNNN.NNN` tag
convention that Sigma rules already use, so imported community rules
contribute to the same coverage report without any extra work.

## Coverage report

```
GET /api/attack/coverage
```

Aggregates every **enabled** rule across all three sources above into
one report: which techniques are covered, by which rule(s), grouped by
ATT&CK tactic. A disabled rule doesn't count -- it isn't actually
watching for that technique right now.

```json
{
  "technique_count": 3,
  "techniques": [
    {
      "id": "T1110.001",
      "name": "Brute Force: Password Guessing",
      "tactic_id": "TA0006",
      "tactic_name": "Credential Access",
      "url": "https://attack.mitre.org/techniques/T1110/001/",
      "sources": [{"kind": "rule", "id": "ssh.brute_force"}]
    }
  ],
  "by_tactic": {
    "Credential Access": ["T1110.001"],
    "Initial Access": ["T1190"]
  }
}
```

A technique referenced by a rule but not in CNSL's curated table (for
example, a Sigma rule tagging a technique CNSL hasn't added to
`TECHNIQUES` yet) still appears in the report -- just with `name` and
`tactic_id` as `null` rather than being silently dropped.

## Kill chain cross-reference

Each kill chain stage (`cnsl/kill_chain.py`) also carries an
**approximate** ATT&CK tactic cross-reference, surfaced in
`StageRecord.to_dict()` as `attack_tactic_id` / `attack_tactic_name`:

| Kill chain stage | ATT&CK tactic |
|:---|:---|
| Reconnaissance | Reconnaissance |
| Weaponization | Resource Development |
| Delivery | Initial Access |
| Exploitation | Execution |
| Installation | Persistence |
| C2 | Command and Control |
| Actions on Objectives | Impact |

This is a convenience mapping, **not an official MITRE one** -- the
classic Lockheed Martin Cyber Kill Chain (7 linear stages) predates
ATT&CK and doesn't correspond 1:1 to its 14 tactics. Treat it as "the
tactic this stage is closest in spirit to," useful for cross-referencing
kill chain data with ATT&CK-oriented tooling (e.g. building an ATT&CK
Navigator layer from a chain's stage history), not as ground truth.

## Adding a technique

To tag a new built-in or correlation rule:

1. If the technique isn't already in `cnsl/attack.py`'s `TECHNIQUES`
   dict, add it: `"T1234": {"name": "...", "tactic": Tactic.SOMETHING}`.
2. Set `attack_techniques = ["T1234"]` on the `Rule(...)` definition
   (`rules.py`) or as a class attribute on the `CorrelationRule`
   subclass (`correlator.py`).
3. `tests/test_attack.py::TestDriftGuards` will fail the build if a
   rule references a technique id that isn't in `TECHNIQUES` --
   add the entry first, or the test tells you exactly which id is missing.

Sigma rules need no CNSL-side change -- just tag them with the standard
`attack.tNNNN` convention in the rule's own YAML.