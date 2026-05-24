"""
cnsl/normalizer.py — Event normalization to a common schema.

Every source (SSH, nginx, MySQL, UFW, syslog, remote syslog) produces
Events in slightly different shapes. This module normalizes them all into
a single Elastic Common Schema (ECS)-inspired document so that:

  - The dashboard can display consistent fields regardless of source
  - The store saves uniform records
  - Alert rules can reference the same field names across sources
  - Future Elasticsearch/OpenSearch export works without extra mapping

Output schema (NormalizedEvent):
  @timestamp        ISO-8601 UTC
  event.kind        "event" | "alert" | "metric"
  event.category    ["authentication", "network", "file", "process"]
  event.type        ["start","end","info","allowed","denied","change"]
  event.outcome     "success" | "failure" | "unknown"
  event.severity    0-100 numeric score
  source.ip         attacker/sender IP
  source.port       port number if available
  destination.ip    target IP
  destination.port  target port
  user.name         username attempted
  host.hostname     reporting host
  process.name      sshd / nginx / mysqld / kernel
  log.original      raw log line
  log.logger        cnsl source name
  cnsl.kind         original EventKind (SSH_FAIL, WEB_SCAN, etc.)
  cnsl.meta         extra source-specific fields
  network.protocol  ssh / http / mysql / dns
  network.direction "inbound" | "outbound" | "unknown"

ECS reference: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
CEF reference: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional

from .models import Event, EventKind, now, iso_time



# Normalized event schema


@dataclass
class NormalizedEvent:
    """
    ECS-inspired normalized event.
    All fields use dot-notation names matching ECS where possible.
    """

    # Core ECS fields
    timestamp:            str   = ""          # @timestamp — ISO-8601 UTC
    event_kind:           str   = "event"     # event.kind
    event_category:       List[str] = field(default_factory=list)   # event.category
    event_type:           List[str] = field(default_factory=list)   # event.type
    event_outcome:        str   = "unknown"   # event.outcome
    event_severity:       int   = 0           # event.severity (0-100)
    event_dataset:        str   = ""          # event.dataset

    # Source (attacker)
    source_ip:            Optional[str]  = None   # source.ip
    source_port:          Optional[int]  = None   # source.port

    # Destination (target)
    destination_ip:       Optional[str]  = None   # destination.ip
    destination_port:     Optional[int]  = None   # destination.port

    # User
    user_name:            Optional[str]  = None   # user.name

    # Host (where the log came from)
    host_hostname:        Optional[str]  = None   # host.hostname

    # Process (what logged the event)
    process_name:         Optional[str]  = None   # process.name
    process_pid:          Optional[int]  = None   # process.pid

    # Log
    log_original:         Optional[str]  = None   # log.original
    log_logger:           str            = ""     # log.logger (cnsl source name)

    # Network
    network_protocol:     Optional[str]  = None   # network.protocol
    network_direction:    str            = "unknown"  # network.direction
    network_type:         Optional[str]  = None   # network.type (ipv4/ipv6)

    # HTTP (web events)
    http_request_method:  Optional[str]  = None   # http.request.method
    http_request_path:    Optional[str]  = None   # url.path
    http_response_status: Optional[int]  = None   # http.response.status_code
    user_agent_original:  Optional[str]  = None   # user_agent.original

    # CNSL-specific
    cnsl_kind:            str            = ""     # original EventKind
    cnsl_threat_score:    int            = 0      # 0-10 threat score
    cnsl_meta:            Dict[str, Any] = field(default_factory=dict)

    # Internal — unix timestamp in ms for CEF rt= field (not serialized)
    _ts_ms: float = field(default_factory=lambda: time.time() * 1000)

    def to_dict(self) -> Dict[str, Any]:
        """Return ECS-structured nested dict."""
        d: Dict[str, Any] = {
            "@timestamp": self.timestamp,
            "event": {
                "kind":     self.event_kind,
                "category": self.event_category,
                "type":     self.event_type,
                "outcome":  self.event_outcome,
                "severity": self.event_severity,
                "dataset":  self.event_dataset,
            },
            "log": {
                "original": self.log_original,
                "logger":   self.log_logger,
            },
            "cnsl": {
                "kind":        self.cnsl_kind,
                "threat_score": self.cnsl_threat_score,
                "meta":        self.cnsl_meta,
            },
        }

        if self.source_ip:
            d["source"] = {"ip": self.source_ip}
            if self.source_port:
                d["source"]["port"] = self.source_port

        if self.destination_ip:
            d["destination"] = {"ip": self.destination_ip}
            if self.destination_port:
                d["destination"]["port"] = self.destination_port

        if self.user_name:
            d["user"] = {"name": self.user_name}

        if self.host_hostname:
            d["host"] = {"hostname": self.host_hostname}

        if self.process_name:
            d["process"] = {"name": self.process_name}
            if self.process_pid:
                d["process"]["pid"] = self.process_pid

        if self.network_protocol or self.network_direction != "unknown":
            d["network"] = {
                "protocol":  self.network_protocol,
                "direction": self.network_direction,
            }
            if self.network_type:
                d["network"]["type"] = self.network_type

        if self.http_request_method:
            d["http"] = {
                "request":  {"method": self.http_request_method},
                "response": {"status_code": self.http_response_status},
            }
            if self.http_request_path:
                d["url"] = {"path": self.http_request_path}
            if self.user_agent_original:
                d["user_agent"] = {"original": self.user_agent_original}

        return d

    def to_cef(self) -> str:
        """
        Serialize as CEF (Common Event Format) string.
        CEF:Version|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extension
        """
        sev_cef = min(10, self.cnsl_threat_score)
        ext_parts = []

        if self.source_ip:
            ext_parts.append(f"src={self.source_ip}")
        if self.source_port:
            ext_parts.append(f"spt={self.source_port}")
        if self.destination_ip:
            ext_parts.append(f"dst={self.destination_ip}")
        if self.destination_port:
            ext_parts.append(f"dpt={self.destination_port}")
        if self.user_name:
            ext_parts.append(f"suser={self.user_name}")
        if self.host_hostname:
            ext_parts.append(f"dhost={self.host_hostname}")
        if self.network_protocol:
            ext_parts.append(f"proto={self.network_protocol}")
        if self.http_request_method:
            ext_parts.append(f"requestMethod={self.http_request_method}")
        if self.http_request_path:
            ext_parts.append(f"request={self.http_request_path}")
        if self.http_response_status:
            ext_parts.append(f"responseCode={self.http_response_status}")

        ext_parts.append(f"rt={int(self._ts_ms)}")  # event timestamp in ms
        ext_parts.append(f"outcome={self.event_outcome}")

        name = self.cnsl_kind.replace("_", " ").title()
        ext  = " ".join(ext_parts)

        return (
            f"CEF:0|CNSL|Correlated Network Security Layer|1.0.4|"
            f"{self.cnsl_kind}|{name}|{sev_cef}|{ext}"
        )

    def to_ecs_json(self) -> str:
        """JSON string ready for Elasticsearch/OpenSearch bulk index."""
        return json.dumps(self.to_dict(), default=str)



# Normalization rules — one per EventKind / source


def _ip_version(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    return "ipv6" if ":" in ip else "ipv4"


def _normalize_ssh_fail(ev: Event) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp        = iso_time(ev.ts),
        event_kind       = "event",
        event_category   = ["authentication", "network"],
        event_type       = ["start"],
        event_outcome    = "failure",
        event_severity   = 40,
        event_dataset    = "cnsl.auth",
        source_ip        = ev.src_ip,
        user_name        = ev.user,
        process_name     = "sshd",
        log_original     = ev.raw,
        log_logger       = ev.source,
        network_protocol = "ssh",
        network_direction = "inbound",
        network_type     = _ip_version(ev.src_ip),
        cnsl_kind        = ev.kind,
        cnsl_threat_score = 3,
        cnsl_meta        = ev.meta,
    )


def _normalize_ssh_success(ev: Event) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp        = iso_time(ev.ts),
        event_kind       = "event",
        event_category   = ["authentication", "network"],
        event_type       = ["start"],
        event_outcome    = "success",
        event_severity   = 25,
        event_dataset    = "cnsl.auth",
        source_ip        = ev.src_ip,
        user_name        = ev.user,
        process_name     = "sshd",
        log_original     = ev.raw,
        log_logger       = ev.source,
        network_protocol = "ssh",
        network_direction = "inbound",
        network_type     = _ip_version(ev.src_ip),
        cnsl_kind        = ev.kind,
        cnsl_threat_score = 1,
        cnsl_meta        = ev.meta,
    )


def _normalize_web(ev: Event) -> NormalizedEvent:
    meta   = ev.meta or {}
    kind   = ev.kind
    is_exploit = kind == "WEB_EXPLOIT_ATTEMPT"
    sev    = 70 if is_exploit else 40
    score  = 7  if is_exploit else 4

    return NormalizedEvent(
        timestamp         = iso_time(ev.ts),
        event_kind        = "event",
        event_category    = ["network", "web"],
        event_type        = ["access"],
        event_outcome     = "unknown",
        event_severity    = sev,
        event_dataset     = f"cnsl.{ev.source}",
        source_ip         = ev.src_ip,
        process_name      = ev.source,
        log_original      = ev.raw,
        log_logger        = ev.source,
        network_protocol  = "http",
        network_direction = "inbound",
        network_type      = _ip_version(ev.src_ip),
        http_request_method  = meta.get("method"),
        http_request_path    = meta.get("path"),
        http_response_status = meta.get("status"),
        user_agent_original  = meta.get("ua"),
        cnsl_kind         = ev.kind,
        cnsl_threat_score = score,
        cnsl_meta         = meta,
    )


def _normalize_db(ev: Event) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp         = iso_time(ev.ts),
        event_kind        = "event",
        event_category    = ["authentication", "database"],
        event_type        = ["start"],
        event_outcome     = "failure",
        event_severity    = 50,
        event_dataset     = "cnsl.mysql",
        source_ip         = ev.src_ip,
        user_name         = ev.user,
        process_name      = "mysqld",
        log_original      = ev.raw,
        log_logger        = ev.source,
        network_protocol  = "mysql",
        network_direction = "inbound",
        network_type      = _ip_version(ev.src_ip),
        cnsl_kind         = ev.kind,
        cnsl_threat_score = 4,
        cnsl_meta         = ev.meta,
    )


def _normalize_firewall(ev: Event) -> NormalizedEvent:
    meta       = ev.meta or {}
    is_honeypot = ev.kind == "FW_HONEYPOT_PORT"
    sev        = 80 if is_honeypot else 50
    score      = 8  if is_honeypot else 4

    return NormalizedEvent(
        timestamp         = iso_time(ev.ts),
        event_kind        = "event",
        event_category    = ["network"],
        event_type        = ["denied"],
        event_outcome     = "failure",
        event_severity    = sev,
        event_dataset     = "cnsl.firewall",
        source_ip         = ev.src_ip,
        destination_ip    = ev.dst_ip,
        destination_port  = meta.get("dst_port"),
        process_name      = "kernel",
        log_original      = ev.raw,
        log_logger        = ev.source,
        network_direction = "inbound",
        network_type      = _ip_version(ev.src_ip),
        cnsl_kind         = ev.kind,
        cnsl_threat_score = score,
        cnsl_meta         = meta,
    )


def _normalize_privilege(ev: Event) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp        = iso_time(ev.ts),
        event_kind       = "event",
        event_category   = ["process", "iam"],
        event_type       = ["change"],
        event_outcome    = "failure",
        event_severity   = 60,
        event_dataset    = "cnsl.privilege",
        source_ip        = ev.src_ip,
        user_name        = ev.user,
        process_name     = "sudo" if ev.kind == "SUDO_FAIL" else "su",
        log_original     = ev.raw,
        log_logger       = ev.source,
        cnsl_kind        = ev.kind,
        cnsl_threat_score = 6,
        cnsl_meta        = ev.meta,
    )


def _normalize_net_hint(ev: Event) -> NormalizedEvent:
    meta = ev.meta or {}
    return NormalizedEvent(
        timestamp         = iso_time(ev.ts),
        event_kind        = "event",
        event_category    = ["network"],
        event_type        = ["info"],
        event_outcome     = "unknown",
        event_severity    = 20,
        event_dataset     = "cnsl.network",
        source_ip         = ev.src_ip,
        destination_ip    = ev.dst_ip,
        log_original      = ev.raw,
        log_logger        = ev.source,
        network_direction = "inbound",
        network_type      = _ip_version(ev.src_ip),
        cnsl_kind         = ev.kind,
        cnsl_threat_score = 1,
        cnsl_meta         = meta,
    )


def _normalize_generic(ev: Event) -> NormalizedEvent:
    """Fallback for unknown event kinds."""
    return NormalizedEvent(
        timestamp        = iso_time(ev.ts),
        event_kind       = "event",
        event_category   = ["network"],
        event_type       = ["info"],
        event_outcome    = "unknown",
        event_severity   = 20,
        event_dataset    = f"cnsl.{ev.source}",
        source_ip        = ev.src_ip,
        destination_ip   = ev.dst_ip,
        user_name        = ev.user,
        log_original     = ev.raw,
        log_logger       = ev.source,
        network_type     = _ip_version(ev.src_ip),
        cnsl_kind        = ev.kind,
        cnsl_threat_score = 1,
        cnsl_meta        = ev.meta,
    )



# Public API

_DISPATCH = {
    EventKind.SSH_FAIL:    _normalize_ssh_fail,
    EventKind.SSH_SUCCESS: _normalize_ssh_success,
    EventKind.NET_HINT:    _normalize_net_hint,
    "WEB_SCAN":            _normalize_web,
    "WEB_EXPLOIT_ATTEMPT": _normalize_web,
    "WEB_AUTH_FAIL":       _normalize_web,
    "DB_AUTH_FAIL":        _normalize_db,
    "FW_BLOCK":            _normalize_firewall,
    "FW_HONEYPOT_PORT":    _normalize_firewall,
    "SUDO_FAIL":           _normalize_privilege,
    "SU_FAIL":             _normalize_privilege,
}


def normalize(ev: Event) -> NormalizedEvent:
    """
    Normalize a CNSL Event into a NormalizedEvent.
    """
    handler = _DISPATCH.get(ev.kind, _normalize_generic)
    norm    = handler(ev)

    # Set event timestamp for CEF rt= field
    norm._ts_ms = ev.ts * 1000

    # Attach syslog remote metadata if present
    if ev.meta.get("syslog_host"):
        norm.host_hostname = ev.meta["syslog_host"]
    if ev.meta.get("syslog_remote_ip") and not norm.source_ip:
        norm.source_ip = ev.meta["syslog_remote_ip"]

    return norm


def normalize_batch(events: list) -> List[NormalizedEvent]:
    """Normalize a list of Events."""
    return [normalize(ev) for ev in events]


def to_ecs_bulk(events: list, index: str = "cnsl-events") -> str:
    """
    Produce Elasticsearch bulk API body from a list of Events.
    Each event becomes two lines: action + document.

    Usage:
        body = to_ecs_bulk(events)
        # POST /_bulk with body to Elasticsearch
    """
    lines = []
    for ev in events:
        norm = normalize(ev)
        action = json.dumps({"index": {"_index": index}})
        doc    = norm.to_ecs_json()
        lines.append(action)
        lines.append(doc)
    return "\n".join(lines) + "\n"