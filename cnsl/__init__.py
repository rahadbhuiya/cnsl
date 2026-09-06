"""
CNSL -- Correlated Network Security Layer
A self-hosted SIEM for Linux.

Core: cross-source correlation, ML anomaly detection (IsolationForest),
honeypot, kill-chain tracking, OT/ICS (Modbus/DNP3/SCADA) parsing, and
KQL-like search.

Beyond core detection: multi-node federation with a unified hub view,
attacker fingerprinting and graph-based campaign correlation, opt-in
predictive blocking, zero-trust trust scoring, UEBA, multi-tenant RBAC,
cloud identity monitoring (AWS/Azure), STIX 2.1 export + built-in TAXII
2.1 server, Wazuh/OSSEC and Kafka/Redis integration, Grafana/Prometheus
metrics, PostgreSQL migration, compliance reporting (SOC2/ISO27001/PCI-DSS),
backup/restore, and a Kubernetes Helm chart.

See docs/features.md for the full capability list.
"""

__version__ = "3.4.18"
__author__  = "Rahad Bhuiya"
__license__ = "MIT"