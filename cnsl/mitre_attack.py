"""
cnsl/mitre_attack.py -- MITRE ATT&CK Enterprise Framework Engine for CNSL.

Maps detection rules, incidents, and kill chain stages to standard MITRE Tactics and Techniques,
and computes dynamic threat heatmaps.
"""

from __future__ import annotations

from typing import Any, Dict, List


TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

RULE_MITRE_MAP: Dict[str, Dict[str, Any]] = {
    "ssh.brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "ssh.credential_stuffing": {
        "tactic": "Credential Access",
        "technique_id": "T1110.004",
        "technique_name": "Credential Stuffing",
    },
    "web.scan_flood": {
        "tactic": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
    },
    "web.exploit": {
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    "db.brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
    },
    "honeytoken.triggered": {
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
    },
    "fim.file_modified": {
        "tactic": "Defense Evasion",
        "technique_id": "T1565",
        "technique_name": "Data Manipulation",
    },
    "container.privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
    },
}


class MitreAttackEngine:
    """
    Computes MITRE ATT&CK coverage and active incident heatmaps.
    """

    @staticmethod
    def get_rule_mapping(rule_name: str) -> Dict[str, Any]:
        return RULE_MITRE_MAP.get(rule_name, {
            "tactic": "Execution",
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
        })

    @staticmethod
    def generate_heatmap(incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates threat density per MITRE Tactic from active incidents.
        """
        tactic_counts: Dict[str, int] = {tactic: 0 for tactic in TACTICS}
        techniques_detected: List[Dict[str, Any]] = []

        for inc in incidents:
            rule_name = str(inc.get("rule_name", inc.get("type", "")))
            mapping = RULE_MITRE_MAP.get(rule_name, {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Application",
            })
            tactic = mapping["tactic"]
            if tactic in tactic_counts:
                tactic_counts[tactic] += 1
            techniques_detected.append({
                "ip": inc.get("ip"),
                "severity": inc.get("severity", "MEDIUM"),
                "tactic": tactic,
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
            })

        return {
            "tactics": TACTICS,
            "tactic_density": tactic_counts,
            "detected_techniques": techniques_detected,
            "total_incidents": len(incidents),
        }
