"""
cnsl/attack.py -- MITRE ATT&CK technique reference and coverage mapping.

This module does NOT implement a new detector. It's a reference table
plus small helpers that let every other part of CNSL that already
raises an alert (built-in rules.py rules, correlator.py correlation
rules, imported Sigma rules) also say *which ATT&CK technique* that
alert corresponds to, and lets the dashboard/API answer "which
techniques does this deployment actually have coverage for right now."

Scope: this is a curated subset of ATT&CK Enterprise techniques --
only the ones CNSL's own detections plausibly correspond to (network-
and host-level Linux detection: brute force, scanning, exploitation of
public-facing services, privilege escalation, C2 beaconing). It is not
a full copy of the ATT&CK knowledge base, and CNSL does not bundle or
redistribute MITRE's dataset -- IDs and names are the tiny, factual
subset needed for tagging; see https://attack.mitre.org/ for the
authoritative, current version of any technique.

Sigma rules already have a community convention for this: a tag like
"attack.t1110" or "attack.t1110.001" in a rule's `tags:` list (see
cnsl/sigma.py). This module's coverage helper reads that convention
directly from imported Sigma rules, so Sigma-imported coverage and
CNSL's own built-in-rule coverage show up in the same report without
CNSL needing its own parallel tagging scheme for Sigma content.

Kill-chain-stage-to-tactic mapping: cnsl/kill_chain.py uses the
classic Lockheed Martin Cyber Kill Chain (7 linear stages), which
predates and doesn't map 1:1 onto ATT&CK's 14 tactics. The mapping
below is the commonly-used approximate correspondence (each kill-chain
stage to the ATT&CK tactic it's closest in spirit to) -- it's a
convenience for cross-referencing kill chain data with ATT&CK-oriented
tooling (e.g. an ATT&CK Navigator layer), not an official MITRE
mapping.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class Tactic:
    """ATT&CK Enterprise tactic IDs referenced by TECHNIQUES below."""
    RECONNAISSANCE     = "TA0043"
    RESOURCE_DEV       = "TA0042"
    INITIAL_ACCESS     = "TA0001"
    EXECUTION          = "TA0002"
    PERSISTENCE        = "TA0003"
    PRIV_ESCALATION    = "TA0004"
    DEFENSE_EVASION    = "TA0005"
    CREDENTIAL_ACCESS  = "TA0006"
    DISCOVERY          = "TA0007"
    LATERAL_MOVEMENT   = "TA0008"
    COLLECTION         = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION       = "TA0010"
    IMPACT             = "TA0040"


_TACTIC_NAMES: Dict[str, str] = {
    Tactic.RECONNAISSANCE:      "Reconnaissance",
    Tactic.RESOURCE_DEV:        "Resource Development",
    Tactic.INITIAL_ACCESS:      "Initial Access",
    Tactic.EXECUTION:           "Execution",
    Tactic.PERSISTENCE:         "Persistence",
    Tactic.PRIV_ESCALATION:     "Privilege Escalation",
    Tactic.DEFENSE_EVASION:     "Defense Evasion",
    Tactic.CREDENTIAL_ACCESS:   "Credential Access",
    Tactic.DISCOVERY:           "Discovery",
    Tactic.LATERAL_MOVEMENT:    "Lateral Movement",
    Tactic.COLLECTION:          "Collection",
    Tactic.COMMAND_AND_CONTROL: "Command and Control",
    Tactic.EXFILTRATION:        "Exfiltration",
    Tactic.IMPACT:              "Impact",
}


# Curated technique reference -- id -> (name, tactic). Only techniques
# actually referenced elsewhere in CNSL (rules.py, correlator.py, this
# module's docs) are listed; this is intentionally not exhaustive.
TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1595":       {"name": "Active Scanning",                         "tactic": Tactic.RECONNAISSANCE},
    "T1595.001":   {"name": "Active Scanning: Scanning IP Blocks",      "tactic": Tactic.RECONNAISSANCE},
    "T1595.002":   {"name": "Active Scanning: Vulnerability Scanning",  "tactic": Tactic.RECONNAISSANCE},
    "T1592":       {"name": "Gather Victim Host Information",          "tactic": Tactic.RECONNAISSANCE},
    "T1046":       {"name": "Network Service Discovery",               "tactic": Tactic.DISCOVERY},
    "T1190":       {"name": "Exploit Public-Facing Application",       "tactic": Tactic.INITIAL_ACCESS},
    "T1110":       {"name": "Brute Force",                             "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1110.001":   {"name": "Brute Force: Password Guessing",          "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1110.003":   {"name": "Brute Force: Password Spraying",          "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1110.004":   {"name": "Brute Force: Credential Stuffing",        "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1078":       {"name": "Valid Accounts",                          "tactic": Tactic.INITIAL_ACCESS},
    "T1078.003":   {"name": "Valid Accounts: Local Accounts",          "tactic": Tactic.INITIAL_ACCESS},
    "T1078.004":   {"name": "Valid Accounts: Cloud Accounts",          "tactic": Tactic.INITIAL_ACCESS},
    "T1621":       {"name": "Multi-Factor Authentication Request Generation", "tactic": Tactic.CREDENTIAL_ACCESS},
    "T1548":       {"name": "Abuse Elevation Control Mechanism",       "tactic": Tactic.PRIV_ESCALATION},
    "T1548.003":   {"name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": Tactic.PRIV_ESCALATION},
    "T1071":       {"name": "Application Layer Protocol",              "tactic": Tactic.COMMAND_AND_CONTROL},
    "T1071.001":   {"name": "Application Layer Protocol: Web Protocols", "tactic": Tactic.COMMAND_AND_CONTROL},
    "T1499":       {"name": "Endpoint Denial of Service",              "tactic": Tactic.IMPACT},
    "T1498":       {"name": "Network Denial of Service",               "tactic": Tactic.IMPACT},
    "T1210":       {"name": "Exploitation of Remote Services",         "tactic": Tactic.LATERAL_MOVEMENT},
    "T1021":       {"name": "Remote Services",                         "tactic": Tactic.LATERAL_MOVEMENT},
}


ATTACK_TECHNIQUE_URL = "https://attack.mitre.org/techniques/{id}/"


def technique_url(technique_id: str) -> str:
    return ATTACK_TECHNIQUE_URL.format(id=technique_id.replace(".", "/"))


def technique_info(technique_id: str) -> Optional[Dict[str, str]]:
    """Look up a technique's name/tactic. Returns None for an id not in TECHNIQUES."""
    t = TECHNIQUES.get(technique_id)
    if t is None:
        return None
    return {
        "id":          technique_id,
        "name":        t["name"],
        "tactic_id":   t["tactic"],
        "tactic_name": _TACTIC_NAMES.get(t["tactic"], t["tactic"]),
        "url":         technique_url(technique_id),
    }


def tactic_name(tactic_id: str) -> str:
    return _TACTIC_NAMES.get(tactic_id, tactic_id)


# Approximate kill-chain-stage -> ATT&CK-tactic correspondence.
# See module docstring: this is a convenience cross-reference, not an
# official MITRE mapping. Keys are cnsl.kill_chain.KCStage values (ints).
KC_STAGE_TO_TACTIC: Dict[int, str] = {
    0: Tactic.RECONNAISSANCE,      # KCStage.RECONNAISSANCE
    1: Tactic.RESOURCE_DEV,        # KCStage.WEAPONIZATION
    2: Tactic.INITIAL_ACCESS,      # KCStage.DELIVERY
    3: Tactic.EXECUTION,           # KCStage.EXPLOITATION
    4: Tactic.PERSISTENCE,         # KCStage.INSTALLATION
    5: Tactic.COMMAND_AND_CONTROL, # KCStage.C2
    6: Tactic.IMPACT,              # KCStage.ACTIONS
}


def sigma_tags_to_technique_ids(tags: List[str]) -> List[str]:
    """
    Extract ATT&CK technique IDs from a Sigma rule's `tags:` list, per
    the community convention (e.g. "attack.t1110", "attack.t1110.001").
    Unrecognized/non-attack tags are ignored. Returns uppercase
    technique IDs (e.g. "T1110.001") regardless of the tag's casing.
    """
    out = []
    for tag in tags:
        t = tag.lower()
        if t.startswith("attack.t") and t[8:].replace(".", "").isdigit():
            out.append("T" + t[8:].upper())
    return out


def build_coverage_report(
    builtin_rules:  Optional[List[Dict[str, Any]]] = None,
    correlation_rules: Optional[List[Dict[str, Any]]] = None,
    sigma_rules:    Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Aggregate which ATT&CK techniques this deployment currently has
    coverage for, and from which source(s). Each *_rules argument is
    the list-of-dicts shape each subsystem's own to_dict()/all_rules()
    already produces (rules.Rule.to_dict(), correlator.CorrelationRule
    .to_dict() with an added "attack_techniques" key, and
    sigma.SigmaRule.to_dict()).

    Only ENABLED rules count toward coverage -- a disabled rule isn't
    actually watching for that technique right now.
    """
    coverage: Dict[str, Dict[str, Any]] = {}

    def _add(technique_id: str, source_kind: str, source_id: str) -> None:
        info = technique_info(technique_id)
        entry = coverage.setdefault(technique_id, {
            "id":          technique_id,
            "name":        info["name"] if info else None,
            "tactic_id":   info["tactic_id"] if info else None,
            "tactic_name": info["tactic_name"] if info else None,
            "url":         technique_url(technique_id),
            "sources":     [],
        })
        entry["sources"].append({"kind": source_kind, "id": source_id})

    for r in (builtin_rules or []):
        if not r.get("enabled", True):
            continue
        for tid in r.get("attack_techniques", []) or []:
            _add(tid, "rule", r.get("id", "?"))

    for r in (correlation_rules or []):
        if not r.get("enabled", True):
            continue
        for tid in r.get("attack_techniques", []) or []:
            _add(tid, "correlation", r.get("name", "?"))

    for r in (sigma_rules or []):
        if not r.get("enabled", True):
            continue
        for tid in sigma_tags_to_technique_ids(r.get("tags", []) or []):
            _add(tid, "sigma", r.get("id", "?"))

    by_tactic: Dict[str, List[str]] = {}
    for tid, entry in coverage.items():
        by_tactic.setdefault(entry["tactic_id"] or "unknown", []).append(tid)

    return {
        "technique_count": len(coverage),
        "techniques":      sorted(coverage.values(), key=lambda e: e["id"]),
        "by_tactic": {
            tactic_name(t) if t != "unknown" else "unknown": sorted(ids)
            for t, ids in by_tactic.items()
        },
    }