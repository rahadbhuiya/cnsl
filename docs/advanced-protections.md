# Advanced Protections: Honeytokens, Container Security, SOAR & AI Copilot

CNSL includes advanced deception, container runtime inspection, automated incident orchestration (SOAR), dynamic MITRE ATT&CK mapping, and an AI SOC Copilot.

---

## Deception & Canary Honeytokens

Honeytokens plant zero-false-positive lures across the filesystem (such as fake AWS credentials or decoy production database connection strings). Any unauthorized access immediately trips an automated containment alert.

### Configuration

```json
"honeytokens": {
  "enabled": true,
  "auto_block": true,
  "canary_paths": [
    "/tmp/fake_aws_credentials",
    "/tmp/fake_database.env"
  ]
}
```

When a canary path is accessed or read, CNSL triggers a `CRITICAL` alert (`honeytoken.triggered`) and instantly isolates the intruder.

---

## Container & Kubernetes Runtime Security

Monitors container lifecycle events, Docker daemon socket telemetry, and Kubernetes audit logs for privilege escalation, container escapes, and unauthorized interactive execution.

### Detection Criteria
- Interactive `exec` execution inside production containers (`container.exec_start`)
- Dangerous capability additions or privilege escalation attempts (`container.privilege_escalation`)

```json
"container_security": {
  "enabled": true,
  "docker_socket": "/var/run/docker.sock"
}
```

---

## Security Orchestration, Automation, and Response (SOAR)

CNSL executes automated response playbooks upon detection of high-severity incidents, isolating threat actors and reducing mean-time-to-containment (MTTC) to milliseconds.

### Predefined Playbooks
- `Auto Block High Severity Threat`: Triggered by any `HIGH` or `CRITICAL` severity incident.
- `Honeytoken Breach Emergency Isolation`: Automatically drops the offending IP, terminates active intruder user sessions (`pkill`), and logs a tamper-evident audit record.

```json
"soar": {
  "enabled": true,
  "auto_remediate": true
}
```

---

## MITRE ATT&CK Framework Mapping & Heatmaps

Every detection signature and correlated incident in CNSL maps to standard MITRE Enterprise Tactics and Techniques:
- Credential Access: `T1110` (Brute Force), `T1110.004` (Credential Stuffing), `T1552` (Unsecured Credentials)
- Reconnaissance: `T1595` (Active Scanning)
- Initial Access: `T1190` (Exploit Public-Facing Application)
- Defense Evasion: `T1565` (Data Manipulation)
- Privilege Escalation: `T1611` (Escape to Host)

Active threat density across all 14 tactics can be queried dynamically via `GET /api/mitre/heatmap`.

---

## AI SOC Incident Copilot

The AI Copilot performs real-time automated root-cause analysis, tactical classification, risk scoring (1-100), and containment script generation.

### Dual-Engine Architecture
1. **Offline Heuristic SOC Engine**: Zero external dependencies. Operates entirely locally and deterministically.
2. **LLM Connector**: Supports local Ollama models (`llama3:8b`), Google Gemini, or OpenAI API.

```json
"ai_copilot": {
  "enabled": true,
  "provider": "ollama",
  "endpoint": "http://localhost:11434/api/generate",
  "model": "llama3:8b",
  "api_key": null
}
```
