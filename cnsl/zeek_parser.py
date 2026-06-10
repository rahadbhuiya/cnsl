"""
cnsl/zeek_parser.py — Zeek (Bro) Network Security Monitor log ingestion.

Supported Zeek logs:
  Log file     Events produced        Detection triggered
  ──────────── ────────────────────── ────────────────────────────────────
  conn.log     NET_CONN               port scan, connection flood
  ssh.log      SSH_FAIL / SSH_SUCCESS brute-force, credential breach
  http.log     WEB_SCAN / WEB_EXPLOIT web scan flood, exploit attempt
  dns.log      DNS_QUERY              DNS tunneling (high entropy names)
  notice.log   ZEEK_NOTICE            Zeek's built-in detection framework
  weird.log    ZEEK_WEIRD             protocol anomalies

Both TSV (default Zeek output) and JSON formats are supported.

TSV format (default Zeek):
  Fields are separated by TAB, with a #fields header line.
  #separator \\x09
  #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p ...

JSON format (with @load policy/tuning/json-logs):
  {"ts":1620000000.0,"uid":"abc","id.orig_h":"1.2.3.4",...}

Config (config.json):
  "zeek": {
    "enabled": true,
    "log_dir": "/opt/zeek/logs/current",
    "format":  "tsv",
    "logs": {
      "conn":   true,
      "ssh":    true,
      "http":   true,
      "dns":    true,
      "notice": true,
      "weird":  true
    },
    "conn_scan_threshold":   20,   -- distinct dest ports before port-scan alert
    "dns_entropy_threshold": 3.5   -- Shannon entropy threshold for DNS tunneling
  }
"""

from __future__ import annotations

import json
import math
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .models import Event, now


#  Entropy helper (DNS tunneling detection) 


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. High entropy = possibly encoded/tunneled."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


#  Zeek TSV field maps 

# Default field positions for each log type (0-indexed).
# These match stock Zeek 4.x / 5.x — custom installations may differ.
# The TSV parser reads the actual #fields header, so this is just a fallback.

_DEFAULT_FIELDS: Dict[str, List[str]] = {
    "conn": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    ],
    "ssh": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "version", "auth_success", "auth_attempts", "direction",
        "client", "server", "cipher_alg", "mac_alg", "compression_alg",
        "kex_alg", "host_key_alg", "host_key",
    ],
    "http": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "trans_depth", "method", "host", "uri", "referrer", "version",
        "user_agent", "origin", "request_body_len", "response_body_len",
        "status_code", "status_msg", "info_code", "info_msg",
        "tags", "username", "password", "proxied", "orig_fuids",
        "orig_filenames", "orig_mime_types", "resp_fuids",
        "resp_filenames", "resp_mime_types",
    ],
    "dns": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
        "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC",
        "RD", "RA", "Z", "answers", "TTLs", "rejected",
    ],
    "notice": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "fuid", "file_mime_type", "file_desc", "proto", "note",
        "msg", "sub", "src", "dst", "p", "n", "peer_descr",
        "actions", "email_dest", "suppress_for", "dropped",
    ],
    "weird": [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "name", "addl", "notice", "peer",
    ],
}


#  TSV state (per-file field map, updated from #fields headers) 


class _TSVState:
    """Tracks the current #fields mapping for a Zeek TSV log file."""
    def __init__(self, log_type: str):
        self.fields: List[str] = _DEFAULT_FIELDS.get(log_type, [])
        self.separator: str = "\t"

    def update_from_header(self, line: str) -> bool:
        """Parse a Zeek header line. Returns True if this was a header."""
        if line.startswith("#separator"):
            sep = line.split(None, 1)[1].strip() if " " in line else "\t"
            self.separator = sep.encode("raw_unicode_escape").decode("unicode_escape")
            return True
        if line.startswith("#fields"):
            parts = line.split(self.separator)
            if len(parts) > 1:
                self.fields = [p.strip() for p in parts[1:]]
            return True
        return line.startswith("#")   # skip all other comment lines

    def row_to_dict(self, line: str) -> Optional[Dict[str, str]]:
        """Split a TSV data row into a dict using current field names."""
        if line.startswith("#"):
            return None
        parts = line.split(self.separator)
        if not self.fields or len(parts) < 2:
            return None
        return {
            k: v for k, v in zip(self.fields, parts)
            if v not in ("-", "(empty)", "")
        }


#  Per-log parsers 


def _safe_ip(d: Dict, key: str) -> str:
    v = d.get(key, "")
    return v if v and v not in ("-", "(empty)") else ""


def parse_zeek_conn(row: Dict[str, str]) -> Optional[Event]:
    """conn.log row → NET_CONN event."""
    src_ip = _safe_ip(row, "id.orig_h")
    if not src_ip:
        return None
    return Event(
        ts     = now(),
        source = "zeek_conn",
        kind   = "NET_CONN",
        src_ip = src_ip,
        user   = None,
        meta   = {
            "dst_ip":     _safe_ip(row, "id.resp_h"),
            "dst_port":   row.get("id.resp_p", ""),
            "proto":      row.get("proto", ""),
            "service":    row.get("service", ""),
            "conn_state": row.get("conn_state", ""),
            "duration":   row.get("duration", ""),
        },
    )


def parse_zeek_ssh(row: Dict[str, str]) -> Optional[Event]:
    """ssh.log row → SSH_FAIL or SSH_SUCCESS event."""
    src_ip = _safe_ip(row, "id.orig_h")
    if not src_ip:
        return None

    auth_val     = row.get("auth_success", "")
    # JSON gives bool, TSV gives string "T"/"F"/"true"/"false"
    if isinstance(auth_val, bool):
        auth_success_str = "t" if auth_val else "f"
    else:
        auth_success_str = str(auth_val).lower()
    kind = "SSH_SUCCESS" if auth_success_str in ("t", "true", "1") else "SSH_FAIL"

    return Event(
        ts     = now(),
        source = "zeek_ssh",
        kind   = kind,
        src_ip = src_ip,
        user   = None,
        meta   = {
            "dst_ip":         _safe_ip(row, "id.resp_h"),
            "auth_attempts":  row.get("auth_attempts", ""),
            "version":        row.get("version", ""),
            "client":         row.get("client", ""),
            "direction":      row.get("direction", ""),
        },
    )


# Reuse exploit + scan path regexes from log_sources.py
_EXPLOIT_RE = re.compile(
    r'(?i)(/\.env|/wp-login\.php|/phpmyadmin|'
    r'/cgi-bin/.*\.(sh|pl|cgi)|/xmlrpc\.php|'
    r'(?:\.\./)(?:\.\./)+(etc|proc|var)|'
    r'/(?:shell|cmd|exec|eval)(?:\b|\.)|'
    r'/(?:passwd|shadow|sudoers)\b|'
    r'\.git/config|/backup.*\.(sql|tar|zip|gz)|'
    r'/dump\.sql|/db\.sql)'
)
_SCAN_UA_RE = re.compile(
    r'(?i)(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|'
    r'nuclei|wfuzz|hydra|medusa|metasploit|nessus|acunetix|'
    r'openvas|arachni|\bpython-requests/\d|\bgo-http-client/\d)'
)


def parse_zeek_http(row: Dict[str, str]) -> Optional[Event]:
    """http.log row → WEB_SCAN, WEB_AUTH_FAIL, or WEB_EXPLOIT_ATTEMPT."""
    src_ip = _safe_ip(row, "id.orig_h")
    if not src_ip:
        return None

    uri        = row.get("uri", "")
    status     = row.get("status_code", "")
    method     = row.get("method", "")
    user_agent = row.get("user_agent", "")

    kind = "WEB_SCAN"

    if uri and _EXPLOIT_RE.search(uri):
        kind = "WEB_EXPLOIT_ATTEMPT"
    elif status in ("401", "403"):
        kind = "WEB_AUTH_FAIL"
    elif user_agent and _SCAN_UA_RE.search(user_agent):
        kind = "WEB_SCAN"
    elif status == "404":
        kind = "WEB_SCAN"
    else:
        return None   # normal traffic — skip

    return Event(
        ts     = now(),
        source = "zeek_http",
        kind   = kind,
        src_ip = src_ip,
        user   = row.get("username"),
        meta   = {
            "method":     method,
            "uri":        uri,
            "status":     status,
            "user_agent": user_agent[:200] if user_agent else "",
            "host":       row.get("host", ""),
        },
    )


def parse_zeek_dns(row: Dict[str, str], entropy_threshold: float = 3.5) -> Optional[Event]:
    """
    dns.log row → DNS_QUERY event.
    Flags high-entropy query names (possible DNS tunneling).
    """
    src_ip = _safe_ip(row, "id.orig_h")
    query  = row.get("query", "")
    if not src_ip or not query:
        return None

    # Only flag if entropy is above threshold — normal hostnames are low entropy
    label = query.split(".")[0]   # highest-entropy subdomain
    entropy = _shannon_entropy(label)
    if entropy < entropy_threshold:
        return None

    return Event(
        ts     = now(),
        source = "zeek_dns",
        kind   = "DNS_QUERY",
        src_ip = src_ip,
        user   = None,
        meta   = {
            "query":    query,
            "entropy":  round(entropy, 2),
            "qtype":    row.get("qtype_name", ""),
            "dst_ip":   _safe_ip(row, "id.resp_h"),
        },
    )


def parse_zeek_notice(row: Dict[str, str]) -> Optional[Event]:
    """notice.log row → ZEEK_NOTICE event (Zeek's built-in detection framework)."""
    # src can be in "src" or "id.orig_h"
    src_ip = _safe_ip(row, "src") or _safe_ip(row, "id.orig_h")
    note   = row.get("note", "")
    msg    = row.get("msg", "")

    if not note and not msg:
        return None

    return Event(
        ts     = now(),
        source = "zeek_notice",
        kind   = "ZEEK_NOTICE",
        src_ip = src_ip or "0.0.0.0",
        user   = None,
        meta   = {
            "note":   note,
            "msg":    msg[:300] if msg else "",
            "sub":    row.get("sub", "")[:200],
            "dst_ip": _safe_ip(row, "dst") or _safe_ip(row, "id.resp_h"),
        },
    )


def parse_zeek_weird(row: Dict[str, str]) -> Optional[Event]:
    """weird.log row → ZEEK_WEIRD event (protocol anomalies)."""
    src_ip = _safe_ip(row, "id.orig_h")
    name   = row.get("name", "")
    if not name:
        return None
    return Event(
        ts     = now(),
        source = "zeek_weird",
        kind   = "ZEEK_WEIRD",
        src_ip = src_ip or "0.0.0.0",
        user   = None,
        meta   = {
            "name": name,
            "addl": row.get("addl", "")[:200],
        },
    )


#  Line-level dispatcher 


class ZeekLogParser:
    """
    Stateful line-by-line parser for a single Zeek log file.

    Tracks the #fields header so it always uses the correct column mapping,
    even after log rotation (Zeek re-emits headers on rotation).

    Usage:
        parser = ZeekLogParser("ssh")
        for line in lines:
            event = parser.parse(line)
            if event:
                await queue.put(event)
    """

    # Row parsers for each supported log type
    _ROW_PARSERS = {
        "conn":   parse_zeek_conn,
        "ssh":    parse_zeek_ssh,
        "http":   parse_zeek_http,
        "dns":    parse_zeek_dns,
        "notice": parse_zeek_notice,
        "weird":  parse_zeek_weird,
    }

    def __init__(self, log_type: str, fmt: str = "tsv",
                 dns_entropy_threshold: float = 3.5):
        self.log_type  = log_type
        self.fmt       = fmt.lower()   # "tsv" or "json"
        self._tsv      = _TSVState(log_type)
        self._row_fn   = self._ROW_PARSERS.get(log_type)
        self._dns_entropy = dns_entropy_threshold

    def parse(self, line: str) -> Optional[Event]:
        """Parse one log line. Returns Event or None."""
        line = line.strip()
        if not line:
            return None

        if self.fmt == "json":
            return self._parse_json(line)
        else:
            return self._parse_tsv(line)

    def _parse_tsv(self, line: str) -> Optional[Event]:
        if self._tsv.update_from_header(line):
            return None
        row = self._tsv.row_to_dict(line)
        if row is None or self._row_fn is None:
            return None
        if self.log_type == "dns":
            return parse_zeek_dns(row, self._dns_entropy)
        return self._row_fn(row)

    def _parse_json(self, line: str) -> Optional[Event]:
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(row, dict) or self._row_fn is None:
            return None
        # JSON uses dotted keys — normalise to match TSV field names
        flat = {k.replace(".", "_"): v for k, v in row.items()}
        # Also keep original dotted keys for compatibility
        flat.update(row)
        if self.log_type == "dns":
            return parse_zeek_dns(flat, self._dns_entropy)
        return self._row_fn(flat)


#  Public helpers 


SUPPORTED_LOGS = list(ZeekLogParser._ROW_PARSERS.keys())


def make_zeek_parser(log_type: str, cfg: Dict[str, Any]) -> ZeekLogParser:
    """Create a ZeekLogParser configured from the zeek config section."""
    zeek_cfg = cfg.get("zeek", {})
    fmt      = zeek_cfg.get("format", "tsv")
    entropy  = float(zeek_cfg.get("dns_entropy_threshold", 3.5))
    return ZeekLogParser(log_type, fmt=fmt, dns_entropy_threshold=entropy)