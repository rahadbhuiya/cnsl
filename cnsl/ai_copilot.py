"""
cnsl/ai_copilot.py -- AI Security Copilot & LLM Incident Analyzer for CNSL.

Supports local Ollama, Gemini, OpenAI, or smart heuristic fallback.
Generates root cause analysis, MITRE ATT&CK mappings, and remediation shell scripts.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger("cnsl.ai_copilot")


class AICopilot:
    """
    AI Security Copilot for analyzing incidents, logs, and attack chains.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = (config or {}).get("ai_copilot", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.provider = cfg.get("provider", "ollama")  # "ollama", "gemini", "openai", "heuristic"
        self.endpoint = cfg.get("endpoint", "http://localhost:11434/api/generate")
        self.model = cfg.get("model", "llama3:8b")
        self.api_key = cfg.get("api_key")

    async def analyze_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a correlated incident or alert payload.
        Returns root cause, MITRE tactic, threat score, and remediation steps.
        """
        prompt = self._build_incident_prompt(incident)
        
        # Try external/local LLM provider if configured
        if self.provider == "ollama":
            res = await self._query_ollama(prompt)
            if res:
                return self._parse_llm_response(res, incident)
        elif self.provider == "openai" and self.api_key:
            res = await self._query_openai(prompt)
            if res:
                return self._parse_llm_response(res, incident)
        elif self.provider == "gemini" and self.api_key:
            res = await self._query_gemini(prompt)
            if res:
                return self._parse_llm_response(res, incident)

        # Fallback to CNSL Heuristic Threat Intelligence Engine
        return self._heuristic_analysis(incident)

    def _build_incident_prompt(self, incident: Dict[str, Any]) -> str:
        ip = incident.get("ip", "unknown")
        severity = incident.get("severity", "MEDIUM")
        events = incident.get("events", [])
        rule_name = incident.get("rule_name", incident.get("type", "Unknown Attack"))
        
        return f"""You are a Lead SOC Security Analyst inspecting an incident detected by CNSL SIEM.
Incident Summary:
- Attacker IP: {ip}
- Severity: {severity}
- Rule Triggered: {rule_name}
- Total Correlated Events: {len(events)}

Events Detail:
{json.dumps(events[:10], indent=2)}

Provide a structured JSON response with keys:
"summary": brief natural language root-cause explanation
"mitre_tactics": list of MITRE ATT&CK tactics (e.g., ["Initial Access", "Credential Access"])
"mitre_techniques": list of technique IDs (e.g., ["T1110.001", "T1078"])
"risk_score": integer 1-100
"remediation_steps": list of recommended shell commands or actions to contain the threat.
"""

    async def _query_ollama(self, prompt: str) -> Optional[str]:
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json"
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(self.endpoint, json=payload, timeout=aiohttp.ClientTimeout(total=8.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response")
        except Exception as e:
            logger.debug(f"Ollama request failed: {e}")
        return None

    async def _query_openai(self, prompt: str) -> Optional[str]:
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "system", "content": prompt}],
                "response_format": {"type": "json_object"}
            }
            url = "https://api.openai.com/v1/chat/completions"
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=8.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.debug(f"OpenAI request failed: {e}")
        return None

    async def _query_gemini(self, prompt: str) -> Optional[str]:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=8.0)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            logger.debug(f"Gemini request failed: {e}")
        return None

    def _parse_llm_response(self, text_resp: str, incident: Dict[str, Any]) -> Dict[str, Any]:
        try:
            clean = text_resp.strip()
            if clean.startswith("```json"):
                clean = clean[7:]
            if clean.endswith("```"):
                clean = clean[:-3]
            parsed = json.loads(clean.strip())
            parsed["analyzed_by"] = f"LLM ({self.provider}:{self.model})"
            return parsed
        except Exception:
            return self._heuristic_analysis(incident)

    def _heuristic_analysis(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """
        Smart offline heuristic SOC analysis engine fallback.
        """
        ip = incident.get("ip", "Unknown")
        rule = str(incident.get("rule_name", incident.get("type", ""))).lower()
        severity = incident.get("severity", "MEDIUM")

        tactics = []
        techniques = []
        summary = ""
        remediation = [
            f"sudo iptables -A INPUT -s {ip} -j DROP",
            f"sudo pkill -u $(whoami) -f {ip}"
        ]

        if "ssh" in rule or "brute" in rule:
            tactics = ["Credential Access", "Initial Access"]
            techniques = ["T1110 - Brute Force", "T1078 - Valid Accounts"]
            summary = f"High-frequency SSH credential stuffing attack originating from IP {ip}. Threat actor attempting dictionary brute-force against local login accounts."
            remediation.append("sudo systemctl restart sshd")
            remediation.append("Review /var/log/auth.log for compromised account handles.")
        elif "web" in rule or "scan" in rule or "exploit" in rule:
            tactics = ["Reconnaissance", "Initial Access"]
            techniques = ["T1595 - Active Scanning", "T1190 - Exploit Public-Facing Application"]
            summary = f"Automated web vulnerability scanner / payload injection detected from IP {ip} targeting web services."
            remediation.append("Verify web application firewall (WAF) rule coverage.")
            remediation.append(f"Inspect Nginx access log: grep '{ip}' /var/log/nginx/access.log")
        elif "honeytoken" in rule or "canary" in rule:
            tactics = ["Credential Access", "Discovery"]
            techniques = ["T1552 - Unsecured Credentials", "T1083 - File and Directory Discovery"]
            summary = f"CRITICAL: Deception honeytoken triggered! An attacker from IP {ip} accessed canary credential files on the filesystem."
            remediation.insert(0, f"IMMEDIATE AUTO-CONTAINMENT: Blocked {ip}")
            remediation.append("Rotate exposed credentials immediately!")
        else:
            tactics = ["Execution", "Persistence"]
            techniques = ["T1059 - Command and Scripting Interpreter"]
            summary = f"Suspicious security event activity ({rule}) detected for entity {ip} exceeding alert threshold."

        risk = 90 if severity in ("HIGH", "CRITICAL") else 65

        return {
            "summary": summary,
            "mitre_tactics": tactics,
            "mitre_techniques": techniques,
            "risk_score": risk,
            "remediation_steps": remediation,
            "analyzed_by": "CNSL Heuristic SOC Engine (Offline Mode)"
        }
