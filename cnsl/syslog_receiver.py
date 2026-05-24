"""
cnsl/syslog_receiver.py — Network syslog receiver (RFC 3164 / RFC 5424).

Listens on UDP and/or TCP port 514 (or any configured port) so remote
devices — routers, switches, firewalls, other Linux servers — can ship
their logs directly to CNSL without a file agent.

Supported formats:
  RFC 3164  — <priority>MMM DD HH:MM:SS hostname tag: message
  RFC 5424  — <priority>VERSION timestamp hostname app procid msgid msg
  Plain     — raw text lines (fallback)

Each received line is:
  1. Parsed for source IP and message text
  2. Passed through existing log parsers (auth, web, mysql, ufw, syslog)
  3. Dropped into the main event queue if a parser matches

Config:
  "syslog_receiver": {
    "enabled":      true,
    "host":         "0.0.0.0",
    "udp_port":     5514,
    "tcp_port":     5514,
    "udp_enabled":  true,
    "tcp_enabled":  true,
    "max_msg_size": 8192
  }

Note: Ports below 1024 (e.g. 514) require root. Use 5514 for non-root.
Remote devices must be configured to send to CNSL_IP:5514.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .logger import JsonLogger
from .models import now



# RFC 3164 / RFC 5424 syslog parser


# RFC 3164: <PRI>Mon DD HH:MM:SS hostname tag[pid]: message
_RFC3164_RE = re.compile(
    r'^<(\d{1,3})>'
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
    r'\s+(\S+)'
    r'\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)',
    re.DOTALL,
)

# RFC 5424: <PRI>VERSION timestamp hostname app procid msgid structured msg
_RFC5424_RE = re.compile(
    r'^<(\d{1,3})>'
    r'(\d+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'(?:\S+\s+)?'
    r'(.*)',
    re.DOTALL,
)

_SEVERITY_NAMES = [
    "emergency", "alert", "critical", "error",
    "warning",   "notice", "info",    "debug",
]
_FACILITY_NAMES = [
    "kern",     "user",    "mail",   "daemon",  "auth",   "syslog",
    "lpr",      "news",    "uucp",   "cron",    "authpriv","ftp",
    "local0",   "local1",  "local2", "local3",
    "local4",   "local5",  "local6", "local7",
]


def _decode_priority(pri: int) -> Tuple[str, str]:
    fac = pri >> 3
    sev = pri & 0x07
    return (
        _FACILITY_NAMES[fac] if fac < len(_FACILITY_NAMES) else str(fac),
        _SEVERITY_NAMES[sev],
    )


def parse_syslog_message(raw: str) -> Dict[str, Any]:
    """Parse a syslog line into a structured dict."""
    raw = raw.strip().lstrip("\x00")

    result: Dict[str, Any] = {
        "raw":      raw,
        "facility": "unknown",
        "severity": "info",
        "hostname": "unknown",
        "app":      "unknown",
        "pid":      None,
        "message":  raw,
    }

    # Try RFC 5424
    m = _RFC5424_RE.match(raw)
    if m:
        fac, sev = _decode_priority(int(m.group(1)))
        result.update({
            "facility": fac,
            "severity": sev,
            "hostname": m.group(4) if m.group(4) != "-" else "unknown",
            "app":      m.group(5) if m.group(5) != "-" else "unknown",
            "pid":      m.group(6) if m.group(6) != "-" else None,
            "message":  m.group(8).strip(),
        })
        return result

    # Try RFC 3164
    m = _RFC3164_RE.match(raw)
    if m:
        fac, sev = _decode_priority(int(m.group(1)))
        result.update({
            "facility": fac,
            "severity": sev,
            "hostname": m.group(3),
            "app":      m.group(4),
            "pid":      m.group(5),
            "message":  m.group(6).strip(),
        })
        return result

    # Plain fallback
    result["message"] = re.sub(r"^<\d{1,3}>", "", raw).strip()
    return result


def _route_syslog_message(
    parsed:  Dict[str, Any],
    src_ip:  str,
    parsers: List[Callable],
) -> Any:
    """
    Try each parser on the syslog message.
    Reconstructs a canonical log line so existing parsers (which expect
    full log lines with hostname/appname) can match correctly.
    """
    app    = parsed.get("app", "unknown")
    host   = parsed.get("hostname", "unknown")
    pid    = parsed.get("pid")
    msg    = parsed["message"]

    pid_str   = f"[{pid}]" if pid else ""
    canonical = f"{host} {app}{pid_str}: {msg}"

    for parser in parsers:
        ev = parser(canonical)
        if ev is None:
            ev = parser(msg)
        if ev is not None:
            if not ev.src_ip and src_ip:
                ev = ev._replace(src_ip=src_ip)
            ev.meta["syslog_host"]      = host
            ev.meta["syslog_app"]       = app
            ev.meta["syslog_facility"]  = parsed["facility"]
            ev.meta["syslog_severity"]  = parsed["severity"]
            ev.meta["syslog_remote_ip"] = src_ip
            return ev

    return None



# UDP protocol


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue, parsers, logger, max_msg_size, stats):
        self._queue        = queue
        self._parsers      = parsers
        self._logger       = logger
        self._max_msg_size = max_msg_size
        self._stats        = stats

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        src_ip = addr[0]
        self._stats["udp_received"] = self._stats.get("udp_received", 0) + 1
        try:
            raw    = data[:self._max_msg_size].decode(errors="ignore")
            parsed = parse_syslog_message(raw)
            ev     = _route_syslog_message(parsed, src_ip, self._parsers)
            if ev is not None:
                self._stats["udp_matched"] = self._stats.get("udp_matched", 0) + 1
                try:
                    self._queue.put_nowait(ev)
                except asyncio.QueueFull:
                    self._stats["queue_dropped"] = self._stats.get("queue_dropped", 0) + 1
        except Exception:
            pass

    def error_received(self, exc):
        pass



# TCP handler


async def _handle_tcp_client(reader, writer, queue, parsers, logger, max_msg_size, stats):
    peer   = writer.get_extra_info("peername", ("unknown", 0))
    src_ip = peer[0]
    stats["tcp_connections"] = stats.get("tcp_connections", 0) + 1
    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=120.0)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            raw = line[:max_msg_size].decode(errors="ignore").strip()
            if not raw:
                continue
            stats["tcp_received"] = stats.get("tcp_received", 0) + 1
            try:
                parsed = parse_syslog_message(raw)
                ev     = _route_syslog_message(parsed, src_ip, parsers)
                if ev is not None:
                    stats["tcp_matched"] = stats.get("tcp_matched", 0) + 1
                    try:
                        queue.put_nowait(ev)
                    except asyncio.QueueFull:
                        stats["queue_dropped"] = stats.get("queue_dropped", 0) + 1
            except Exception:
                pass
    except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass



# Main SyslogReceiver


class SyslogReceiver:
    """
    Network syslog receiver — listens on UDP and/or TCP.

    Config keys (under "syslog_receiver"):
      enabled      bool   — enable/disable (default False)
      host         str    — bind address   (default "0.0.0.0")
      udp_port     int    — UDP port       (default 514, use 5514 without root)
      tcp_port     int    — TCP port       (default 514, use 5514 without root)
      udp_enabled  bool   — enable UDP     (default True)
      tcp_enabled  bool   — enable TCP     (default True)
      max_msg_size int    — max bytes/msg  (default 8192)
    """

    def __init__(self, cfg: Dict[str, Any], queue, parsers: List[Callable], logger: JsonLogger):
        sr = cfg.get("syslog_receiver", {})
        self.enabled      = bool(sr.get("enabled", False))
        self.host         = sr.get("host", "0.0.0.0")
        self.udp_port     = int(sr.get("udp_port", 514))
        self.tcp_port     = int(sr.get("tcp_port", 514))
        self.udp_enabled  = bool(sr.get("udp_enabled", True))
        self.tcp_enabled  = bool(sr.get("tcp_enabled", True))
        self.max_msg_size = int(sr.get("max_msg_size", 8192))

        self._queue     = queue
        self._parsers   = parsers
        self._logger    = logger
        self._stats: Dict[str, int] = {}
        self._udp_transport = None
        self._tcp_server    = None

    async def start(self) -> None:
        if not self.enabled:
            return

        loop    = asyncio.get_running_loop()
        started = []

        if self.udp_enabled:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _SyslogUDPProtocol(
                        self._queue, self._parsers, self._logger,
                        self.max_msg_size, self._stats,
                    ),
                    local_addr=(self.host, self.udp_port),
                )
                self._udp_transport = transport
                started.append(f"udp:{self.udp_port}")
            except OSError as e:
                await self._logger.log("syslog_receiver_error", {
                    "proto": "udp", "port": self.udp_port, "error": str(e),
                    "hint":  "Use udp_port:5514 to avoid needing root for port 514",
                })

        if self.tcp_enabled:
            try:
                self._tcp_server = await asyncio.start_server(
                    lambda r, w: _handle_tcp_client(
                        r, w, self._queue, self._parsers,
                        self._logger, self.max_msg_size, self._stats,
                    ),
                    host=self.host,
                    port=self.tcp_port,
                )
                started.append(f"tcp:{self.tcp_port}")
            except OSError as e:
                await self._logger.log("syslog_receiver_error", {
                    "proto": "tcp", "port": self.tcp_port, "error": str(e),
                    "hint":  "Use tcp_port:5514 to avoid needing root for port 514",
                })

        if started:
            await self._logger.log("syslog_receiver_started", {
                "host": self.host, "listening": started,
            })

    def stop(self) -> None:
        if self._udp_transport:
            try:
                self._udp_transport.close()
            except Exception:
                pass
        if self._tcp_server:
            try:
                self._tcp_server.close()
            except Exception:
                pass

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":  self.enabled,
            "host":     self.host,
            "udp_port": self.udp_port if self.udp_enabled else None,
            "tcp_port": self.tcp_port if self.tcp_enabled else None,
            "stats":    dict(self._stats),
        }