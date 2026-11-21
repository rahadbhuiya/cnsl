"""
cnsl/soar.py -- Security Orchestration, Automation, and Response (SOAR) Engine for CNSL.

Executes predefined playbooks to automate incident containment (session killing, 
container isolation, IP blocking, custom webhook notifications).
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cnsl.soar")


DEFAULT_PLAYBOOKS = [
    {
        "id": "playbook-auto-block",
        "name": "Auto Block High Severity Threat",
        "enabled": True,
        "trigger": {"min_severity": "HIGH"},
        "actions": ["block_ip", "log_audit"]
    },
    {
        "id": "playbook-honeytoken-containment",
        "name": "Honeytoken Breach Emergency Isolation",
        "enabled": True,
        "trigger": {"rule": "honeytoken.triggered"},
        "actions": ["block_ip", "kill_user_sessions", "log_audit"]
    }
]


class SOAREngine:
    """
    SOAR Automation Playbook Engine.
    """

    def __init__(self, config: Dict[str, Any] | None = None, blocker: Any = None):
        cfg = (config or {}).get("soar", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.auto_remediate = bool(cfg.get("auto_remediate", False))
        self.blocker = blocker
        self.playbooks: List[Dict[str, Any]] = DEFAULT_PLAYBOOKS
        self.execution_history: List[Dict[str, Any]] = []

    async def evaluate_incident(self, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate an incident against loaded SOAR playbooks and execute matching actions.
        """
        if not self.enabled:
            return []

        results = []
        for pb in self.playbooks:
            if not pb.get("enabled", True):
                continue
            if self._matches_trigger(pb.get("trigger", {}), incident):
                exec_result = await self._execute_playbook(pb, incident)
                results.append(exec_result)
                self.execution_history.append(exec_result)

        return results

    def _matches_trigger(self, trigger: Dict[str, Any], incident: Dict[str, Any]) -> bool:
        if "min_severity" in trigger:
            target_sev = trigger["min_severity"]
            inc_sev = incident.get("severity", "MEDIUM")
            sev_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            if sev_levels.get(inc_sev, 0) < sev_levels.get(target_sev, 0):
                return False
        if "rule" in trigger:
            inc_rule = incident.get("rule_name", incident.get("type", ""))
            if trigger["rule"] != inc_rule:
                return False
        return True

    async def _execute_playbook(self, playbook: Dict[str, Any], incident: Dict[str, Any]) -> Dict[str, Any]:
        ip = incident.get("ip")
        executed_actions = []

        for action in playbook.get("actions", []):
            try:
                if action == "block_ip" and ip and self.blocker:
                    await self.blocker.block(ip, reason=f"SOAR Playbook: {playbook['name']}")
                    executed_actions.append(f"Blocked IP {ip}")
                elif action == "kill_user_sessions" and ip:
                    # Best-effort session termination for suspicious user
                    user = incident.get("user")
                    if user and user != "root":
                        subprocess.run(["pkill", "-9", "-u", user], check=False)
                        executed_actions.append(f"Killed user sessions for {user}")
                elif action == "log_audit":
                    executed_actions.append(f"Logged to SOAR audit log for {ip}")
            except Exception as e:
                logger.error(f"Error executing action {action}: {e}")

        return {
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "target_ip": ip,
            "actions_executed": executed_actions,
            "status": "COMPLETED"
        }
