"""
cnsl/ot_parser.py -- OT/IoT Protocol Log Parsers.

Parsers for Operational Technology (OT) and Industrial Control System
(ICS) log formats. CNSL can ingest these from three sources:

  1. Syslog forwarded from OT gateways (most common in practice)
  2. Dedicated log files written by protocol converters
  3. Network-level capture logs from Wireshark/Zeek OT plugins

Supported protocols:

  Modbus TCP/RTU  -- most widely deployed industrial protocol
                     (PLCs, VFDs, energy meters, HVAC controllers)
  DNP3            -- power utility automation (substations, RTUs)
  Generic SCADA   -- vendor-agnostic syslog patterns from SCADA HMIs
                     (Wonderware, Ignition, Kepware, Inductive Automation)

How OT logs differ from IT logs:

  OT logs are sparse. A correctly functioning PLC may log nothing for
  days. Anomalies are therefore more meaningful here than in IT:
    - Any command to write a coil/register from an unexpected IP = HIGH
    - Repeated function-code scans = reconnaissance
    - DNP3 unsolicited responses from unknown IPs = C2/manipulation
    - SCADA alarm flooding = possible denial-of-service

New event kinds (added to detector routing table):

  OT_MODBUS_SCAN          -- function code 1-4 read sweep from new IP
  OT_MODBUS_WRITE         -- function code 5/6/15/16 write from any IP
  OT_MODBUS_EXCEPTION     -- device returned exception code (error/attack)
  OT_DNP3_UNSOLICITED     -- unsolicited response from unexpected source
  OT_DNP3_AUTH_FAIL       -- DNP3 Secure Authentication failure
  OT_SCADA_ALARM          -- HMI/SCADA alarm message (HIGH threshold)
  OT_UNAUTHORIZED_CMD     -- explicit "unauthorized" / "denied" in OT log

Limitation:

  These parsers read log file lines -- they do NOT do packet-level
  protocol parsing. For deep Modbus/DNP3 packet analysis, use Zeek
  with the Zeek-ICS plugin and feed the resulting logs through
  CNSL's Zeek parser (`zeek_parser.py`).

Config (config.json):
  "ot": {
    "enabled": true,
    "log_sources": {
      "modbus":  "/var/log/modbus-gateway.log",
      "dnp3":    "/var/log/dnp3-gateway.log",
      "scada":   "/var/log/scada-hmi.log"
    },
    "trusted_ips": ["192.168.100.10", "192.168.100.11"],
    "alert_on_any_write": true
  }
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Event, now



# OT event kind constants


class OTEventKind:
    MODBUS_SCAN       = "OT_MODBUS_SCAN"
    MODBUS_WRITE      = "OT_MODBUS_WRITE"
    MODBUS_EXCEPTION  = "OT_MODBUS_EXCEPTION"
    DNP3_UNSOLICITED  = "OT_DNP3_UNSOLICITED"
    DNP3_AUTH_FAIL    = "OT_DNP3_AUTH_FAIL"
    SCADA_ALARM       = "OT_SCADA_ALARM"
    UNAUTHORIZED_CMD  = "OT_UNAUTHORIZED_CMD"



# Modbus log parser


# Modbus function codes
_FC_READ  = {1, 2, 3, 4}       # read coils, discrete inputs, registers
_FC_WRITE = {5, 6, 15, 16, 22, 23}  # write coil(s) / register(s)

# Common Modbus log patterns from popular gateways:
# mbpoll, libmodbus, EasyModbus, Modbus Poll, and vendor gateway syslog

_RE_MODBUS_FULL = re.compile(
    r"(?:modbus|mbpoll|mbsrv)"
    r".*?(?:from|src|client)[:\s]+(\d+\.\d+\.\d+\.\d+)"
    r".*?(?:fc|function.code|func)[:\s=]+(\d+)",
    re.IGNORECASE,
)

_RE_MODBUS_EXCEPTION = re.compile(
    r"(?:modbus|mbpoll).*?exception.*?(?:from|src)[:\s]+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_RE_MODBUS_SIMPLE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+).*?"
    r"(?:FC|function.code)[:\s=]+(\d+)",
    re.IGNORECASE,
)


def parse_modbus(line: str, trusted_ips: Optional[set] = None,
                 alert_on_any_write: bool = True) -> Optional[Event]:
    """
    Parse one line from a Modbus gateway log.

    Detects:
      - Read function code sweeps from new/unexpected IPs -> OT_MODBUS_SCAN
      - Write function codes from any IP -> OT_MODBUS_WRITE
      - Exception responses -> OT_MODBUS_EXCEPTION
    """
    if not line.strip():
        return None

    # Exception check first (most critical)
    m = _RE_MODBUS_EXCEPTION.search(line)
    if m:
        return Event(
            ts=now(), source="modbus", kind=OTEventKind.MODBUS_EXCEPTION,
            src_ip=m.group(1), user=None, raw=line.strip()[:300],
            meta={"protocol": "modbus", "detail": "exception_code"},
        )

    # Full parse with IP + FC
    m = _RE_MODBUS_FULL.search(line) or _RE_MODBUS_SIMPLE.search(line)
    if not m:
        return None

    src_ip = m.group(1)
    try:
        fc = int(m.group(2))
    except (ValueError, IndexError):
        return None

    # Write from any IP is always suspicious in OT environments
    if fc in _FC_WRITE:
        return Event(
            ts=now(), source="modbus", kind=OTEventKind.MODBUS_WRITE,
            src_ip=src_ip, user=None, raw=line.strip()[:300],
            meta={
                "protocol":      "modbus",
                "function_code": fc,
                "trusted":       src_ip in (trusted_ips or set()),
            },
        )

    # Read sweep from non-trusted IP = scan
    if fc in _FC_READ and src_ip not in (trusted_ips or set()):
        return Event(
            ts=now(), source="modbus", kind=OTEventKind.MODBUS_SCAN,
            src_ip=src_ip, user=None, raw=line.strip()[:300],
            meta={
                "protocol":      "modbus",
                "function_code": fc,
            },
        )

    return None



# DNP3 log parser


_RE_DNP3_UNSOLICITED = re.compile(
    r"(?:dnp3?|dnp).*?"
    r"(?:unsolicited|unsolicit)"
    r".*?(?:from|src|master)[:\s]+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_RE_DNP3_AUTH_FAIL = re.compile(
    r"(?:dnp3?|dnp).*?"
    r"(?:auth.*?fail|authentication.*?fail|invalid.*?hmac|bad.*?mac|security.*?fail)"
    r".*?(?:from|src)[:\s]+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_RE_DNP3_IP_FIRST = re.compile(
    r"(\d+\.\d+\.\d+\.\d+).*?(?:dnp3?|dnp).*?"
    r"(?:unsolicited|auth.*?fail|authentication.*?fail)",
    re.IGNORECASE,
)


def parse_dnp3(line: str, trusted_ips: Optional[set] = None) -> Optional[Event]:
    """
    Parse one line from a DNP3 gateway log.

    Detects:
      - Unsolicited responses from non-trusted IPs -> OT_DNP3_UNSOLICITED
      - DNP3 Secure Authentication failures -> OT_DNP3_AUTH_FAIL
    """
    if not line.strip():
        return None

    # Auth failures
    m = _RE_DNP3_AUTH_FAIL.search(line)
    if m:
        return Event(
            ts=now(), source="dnp3", kind=OTEventKind.DNP3_AUTH_FAIL,
            src_ip=m.group(1), user=None, raw=line.strip()[:300],
            meta={"protocol": "dnp3", "detail": "auth_failure"},
        )

    # Unsolicited response
    m = _RE_DNP3_UNSOLICITED.search(line) or _RE_DNP3_IP_FIRST.search(line)
    if m:
        src_ip = m.group(1)
        if src_ip not in (trusted_ips or set()):
            return Event(
                ts=now(), source="dnp3", kind=OTEventKind.DNP3_UNSOLICITED,
                src_ip=src_ip, user=None, raw=line.strip()[:300],
                meta={"protocol": "dnp3", "detail": "unsolicited_response"},
            )

    return None



# SCADA / HMI log parser


# Patterns common across Ignition, Wonderware, Kepware, FactoryTalk
_RE_SCADA_ALARM = re.compile(
    r"(?:alarm|alert|critical|emergency|trip)"
    r".*?(?:from|src|operator|station)[:\s]+(\d+\.\d+\.\d+\.\d+|\S+)",
    re.IGNORECASE,
)

_RE_SCADA_UNAUTHORIZED = re.compile(
    r"(?:unauthorized|denied|rejected|forbidden|not.*?allowed)"
    r".*?(?:from|src|ip|operator)[:\s]+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_RE_SCADA_UNAUTHORIZED_IP_FIRST = re.compile(
    r"(\d+\.\d+\.\d+\.\d+).*?"
    r"(?:unauthorized|denied|rejected|forbidden)",
    re.IGNORECASE,
)

_RE_SCADA_ALARM_PLAIN = re.compile(
    r"(?:alarm|ALARM|critical|CRITICAL|TRIP|trip)",
)


def parse_scada(line: str, trusted_ips: Optional[set] = None) -> Optional[Event]:
    """
    Parse one line from a SCADA/HMI log.

    Detects:
      - Unauthorized command attempts -> OT_UNAUTHORIZED_CMD
      - SCADA alarms -> OT_SCADA_ALARM
    """
    if not line.strip():
        return None

    # Unauthorized access / denied command
    m = (_RE_SCADA_UNAUTHORIZED.search(line) or
         _RE_SCADA_UNAUTHORIZED_IP_FIRST.search(line))
    if m:
        src_ip = m.group(1)
        # Only use as src_ip if it looks like an IP
        if re.match(r"\d+\.\d+\.\d+\.\d+", src_ip):
            return Event(
                ts=now(), source="scada", kind=OTEventKind.UNAUTHORIZED_CMD,
                src_ip=src_ip, user=None, raw=line.strip()[:300],
                meta={"protocol": "scada", "detail": "unauthorized"},
            )

    # Alarm / critical condition
    m = _RE_SCADA_ALARM.search(line)
    if m:
        val = m.group(1)
        src_ip = val if re.match(r"\d+\.\d+\.\d+\.\d+", val) else None
        return Event(
            ts=now(), source="scada", kind=OTEventKind.SCADA_ALARM,
            src_ip=src_ip, user=None, raw=line.strip()[:300],
            meta={"protocol": "scada", "detail": "alarm", "source_tag": val},
        )

    # Plain alarm line without IP
    if _RE_SCADA_ALARM_PLAIN.search(line):
        return Event(
            ts=now(), source="scada", kind=OTEventKind.SCADA_ALARM,
            src_ip=None, user=None, raw=line.strip()[:300],
            meta={"protocol": "scada", "detail": "alarm"},
        )

    return None


# Unified OT parser factory


def make_ot_parser(protocol: str, cfg: dict):
    """
    Return a (line: str) -> Optional[Event] parser for the given OT protocol.

    protocol: "modbus" | "dnp3" | "scada"
    cfg:      the full CNSL config dict (reads cfg["ot"] for trusted_ips etc.)
    """
    ot_cfg = cfg.get("ot", {})
    trusted_ips = set(ot_cfg.get("trusted_ips", []))
    alert_on_any_write = bool(ot_cfg.get("alert_on_any_write", True))

    if protocol == "modbus":
        return lambda line: parse_modbus(line, trusted_ips, alert_on_any_write)
    elif protocol == "dnp3":
        return lambda line: parse_dnp3(line, trusted_ips)
    elif protocol == "scada":
        return lambda line: parse_scada(line, trusted_ips)
    else:
        return None