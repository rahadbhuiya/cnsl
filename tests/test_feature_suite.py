"""
tests/test_feature_suite.py -- Tests for AI Copilot, Honeytokens, MITRE ATT&CK,
SOAR Playbooks, Container Security, Config Service, and Loki Observability.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import pytest

from cnsl.ai_copilot import AICopilot
from cnsl.honeytokens import HoneytokenEngine
from cnsl.mitre_attack import MitreAttackEngine
from cnsl.soar import SOAREngine
from cnsl.container_security import ContainerSecurityEngine
from cnsl.config_service import ConfigService
from cnsl.observability_sources import ObservabilitySourceManager, _timestamp, _field


@pytest.mark.asyncio
async def test_ai_copilot_heuristic():
    copilot = AICopilot()
    incident = {
        "ip": "45.33.32.1",
        "severity": "HIGH",
        "rule_name": "ssh.brute_force",
        "events": [{"source_type": "ssh", "user": "admin"}],
    }
    result = await copilot.analyze_incident(incident)
    assert "summary" in result
    assert "Credential Access" in result["mitre_tactics"]
    assert result["risk_score"] == 90
    assert len(result["remediation_steps"]) > 0


def test_mitre_attack_heatmap():
    incidents = [
        {"ip": "1.2.3.4", "severity": "HIGH", "rule_name": "ssh.brute_force"},
        {"ip": "5.6.7.8", "severity": "MEDIUM", "rule_name": "web.scan_flood"},
    ]
    heatmap = MitreAttackEngine.generate_heatmap(incidents)
    assert len(heatmap["tactics"]) == 14
    assert heatmap["tactic_density"]["Credential Access"] == 1
    assert heatmap["tactic_density"]["Reconnaissance"] == 1
    assert heatmap["total_incidents"] == 2


@pytest.mark.asyncio
async def test_soar_engine():
    soar = SOAREngine()
    incident = {
        "ip": "10.0.0.99",
        "severity": "HIGH",
        "rule_name": "ssh.brute_force",
    }
    results = await soar.evaluate_incident(incident)
    assert len(results) >= 1
    assert results[0]["status"] == "COMPLETED"


def test_honeytoken_deploy():
    temp_dir = tempfile.mkdtemp()
    canary_path = os.path.join(temp_dir, "test_cnsl_canary.env")
    if os.path.exists(canary_path):
        os.remove(canary_path)

    engine = HoneytokenEngine(config={"honeytokens": {"canary_paths": [canary_path]}})
    engine.deploy_tokens()

    assert os.path.exists(canary_path)
    with open(canary_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "DB_USER=root" in content

    os.remove(canary_path)
    os.rmdir(temp_dir)


def test_container_security_inspection():
    engine = ContainerSecurityEngine()
    alert = engine.inspect_container_event({"action": "exec_start", "container_id": "c12345"})
    assert alert is not None
    assert alert["rule"] == "container.exec_start"
    assert alert["severity"] == "HIGH"


def test_config_service_schema_and_status():
    service = ConfigService()
    schema = service.schema()
    assert "fields" in schema
    assert len(schema["fields"]) > 0
    status = service.status()
    assert "config_path" in status
    assert "config_hash" in status


def test_observability_helpers():
    record = {"data": {"user": {"name": "alice"}}}
    assert _field(record, "data.user.name") == "alice"
    assert _field(record, "data.missing") is None

    ts = _timestamp("2026-11-21T10:00:00Z", fallback=0.0)
    assert ts > 0
