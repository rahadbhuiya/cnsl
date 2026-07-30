"""
cnsl/wazuh.py — Wazuh/OSSEC integration.

Wazuh (and its predecessor OSSEC) is a widely-deployed open-source HIDS.
CNSL doesn't replace it -- it ingests Wazuh's own already-vetted alerts
so they participate in CNSL's correlation, kill-chain tracking, and
blocking, alongside everything else CNSL sees directly.

Two ingestion paths, both using the parser below:

1. File tailing (cnsl/log_sources.py's tail_log_file + parse_wazuh_alert)
   -- reads the Wazuh manager's local alerts.json (JSON Lines, one
   alert object per line). Default Wazuh output; zero network config.
   config.json:
     "log_sources": {"wazuh": "/var/ossec/logs/alerts/alerts.json"}

2. Syslog forwarding -- for a Wazuh manager configured to forward
   alerts to a remote syslog destination (its built-in syslog output
   integration). This reuses CNSL's existing generic syslog receiver
   (cnsl/syslog_receiver.py, UDP+TCP, RFC 3164/5424) rather than a
   Wazuh-specific listener -- parse_wazuh_alert is registered as one
   of its parsers (see engine.py), same as the auth/web/mysql/ufw
   parsers already are. Enable via the existing config block:
     "syslog_receiver": {"enabled": true, "udp_port": 5514, ...}

Wazuh alert shape (abbreviated, only fields we use):
  {
    "rule":  {"level": 10, "description": "...", "id": "5712", "groups": [...]},
    "agent": {"id": "001", "name": "web01", "ip": "10.0.0.5"},
    "data":  {"srcip": "45.33.32.1", "srcuser": "root"},
    "full_log": "...", "location": "/var/log/auth.log"
  }
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from .models import Event, now

# Wazuh rule.level ranges from 0-16. Map to CNSL's three-tier severity.
_LEVEL_HIGH_MIN   = 12
_LEVEL_MEDIUM_MIN = 7

# When parse_wazuh_alert is called directly on a raw file line (the
# file-tailing path), a syslog header may still precede the JSON body
# if the alert was copied verbatim from a syslog capture -- strip up
# to the first '{'. When called via the generic syslog_receiver
# (cnsl/syslog_receiver.py), that header is already stripped upstream,
# so this regex is a defensive fallback, not the primary path.
_JSON_START_RE = re.compile(r"\{.*\}\s*$", re.DOTALL)

# Common field names Wazuh uses for the attacker IP across different
# rule decoders (ssh, web, generic auth) -- checked in order.
_SRCIP_FIELDS = ("srcip", "src_ip", "sourceip", "source_ip")


def _level_to_severity(level: Any) -> str:
    try:
        level = int(level)
    except (TypeError, ValueError):
        return "LOW"
    if level >= _LEVEL_HIGH_MIN:
        return "HIGH"
    if level >= _LEVEL_MEDIUM_MIN:
        return "MEDIUM"
    return "LOW"


def _extract_srcip(data: Dict[str, Any]) -> Optional[str]:
    for field in _SRCIP_FIELDS:
        val = data.get(field)
        if val:
            return str(val)
    return None


def parse_wazuh_alert(line: str) -> Optional[Event]:
    """
    Parse one Wazuh alert -- either a raw alerts.json line (file-tailing)
    or a syslog message body already stripped of its RFC 3164/5424
    header (cnsl/syslog_receiver.py's canonical reconstruction).
    Returns None for blank lines, lines with no attacker IP, or
    anything that doesn't parse as JSON -- a malformed or IP-less
    alert is skipped, not fatal to the caller.
    """
    line = line.strip()
    if not line:
        return None

    # If a syslog header still precedes the JSON body, keep only the
    # JSON tail (defensive -- see module docstring).
    if not line.startswith("{"):
        m = _JSON_START_RE.search(line)
        if not m:
            return None
        line = m.group(0)

    try:
        alert = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(alert, dict):
        return None

    data = alert.get("data") or {}
    if not isinstance(data, dict):
        data = {}
    src_ip = _extract_srcip(data)
    if not src_ip:
        return None

    rule  = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    level = rule.get("level", 0)

    meta = {
        "rule_id":          rule.get("id"),
        "rule_level":       level,
        "rule_description": rule.get("description", ""),
        "rule_groups":      rule.get("groups", []),
        "agent_id":         agent.get("id"),
        "agent_name":       agent.get("name"),
        "agent_ip":         agent.get("ip"),
        "severity":         _level_to_severity(level),
        "full_log":         alert.get("full_log", ""),
    }

    return Event(
        ts=now(),
        source="wazuh",
        kind="WAZUH_ALERT",
        src_ip=src_ip,
        user=data.get("srcuser"),
        raw=line,
        meta=meta,
    )