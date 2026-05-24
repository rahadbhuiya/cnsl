"""
cnsl/logger.py — Structured async JSON logger with console output.

Every event written to the JSONL file has:
  { "ts": <unix float>, "time": <ISO-8601>, "type": <str>, "payload": {...} }

The file can be consumed by any log aggregator (Loki, Splunk, Elastic, jq, etc.).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

from .models import now, iso_time


class JsonLogger:
    """
    Thread-safe (via asyncio lock) structured logger.

    Usage:
        logger = JsonLogger("./cnsl.jsonl", verbose=True)
        await logger.log("incident", {"ip": "1.2.3.4", ...})
        logger.close()
    """

    def __init__(self, path: str, verbose: bool = True):
        self.path    = path
        self.verbose = verbose
        self._fp: Any = None
        self._lock   = asyncio.Lock()
        self._open_file()

    def _open_file(self) -> None:
        """Open log file, creating parent directories if needed."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            self._fp = open(self.path, "a", encoding="utf-8", buffering=1)
        except Exception as e:
            # Fall back to stderr — never crash because of log file issues
            print(f"[WARN] Cannot open log file {self.path}: {e} — logging to stderr only",
                  file=sys.stderr, flush=True)
            self._fp = None

    async def log(self, event_type: str, payload: Dict[str, Any]) -> None:
        record = {
            "ts":      now(),
            "time":    iso_time(),
            "type":    event_type,
            "payload": payload,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)

        async with self._lock:
            if self._fp is not None:
                try:
                    self._fp.write(line + "\n")
                except OSError:
                    # Disk full or file removed — try reopening once
                    try:
                        self._fp.close()
                    except Exception:
                        pass
                    self._open_file()
                    if self._fp:
                        try:
                            self._fp.write(line + "\n")
                        except OSError:
                            pass

        if self.verbose:
            prefix = _console_prefix(event_type)
            print(f"{prefix} {line}", flush=True)

    def close(self) -> None:
        if self._fp:
            try:
                self._fp.close()
            except Exception:
                pass
            self._fp = None



# Console formatting helpers


_PREFIXES = {
    "startup":                  "[START]  ",
    "shutdown":                 "[STOP]   ",
    "incident":                 "[ALERT]  ",
    "response_plan":            "[DEFEND] ",
    "action_block_scheduled":   "[BLOCK]  ",
    "action_block_executed":    "[BLOCK]  ",
    "action_unblock_executed":  "[UNBLOCK]",
    "action_skip_allowlist":    "[ALLOW]  ",
    "engine_error":             "[ERROR]  ",
    "event_auth":               "[AUTH]   ",
    "event_net_hint":           "[NET]    ",
    "ml_retrained":             "[ML]     ",
    "ml_error":                 "[ML-ERR] ",
    "fim_alert":                "[FIM]    ",
    "fim_error":                "[FIM-ERR]",
    "honeypot_session_complete": "[HP]     ",
    "redis_error":              "[REDIS]  ",
    "source_start":             "[SOURCE] ",
    "dashboard_started":        "[DASH]   ",
    "syslog_receiver_started":  "[SYSLOG] ",
    "syslog_receiver_error":    "[SYS-ERR]",
}


def _console_prefix(event_type: str) -> str:
    return _PREFIXES.get(event_type, "         ")