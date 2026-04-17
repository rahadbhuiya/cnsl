"""
cnsl/models.py — Shared data models and constants.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List


# ---------------------------------------------------------------------------
# Event kinds
# ---------------------------------------------------------------------------

class EventKind:
    SSH_FAIL    = "SSH_FAIL"
    SSH_SUCCESS = "SSH_SUCCESS"
    NET_HINT    = "NET_HINT"


class Severity:
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


# ---------------------------------------------------------------------------
# Core event
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """A single labelled event produced by a parser."""
    ts:      float
    source:  str                      # "auth" | "net"
    kind:    str                      # EventKind.*
    src_ip:  Optional[str] = None
    dst_ip:  Optional[str] = None
    user:    Optional[str] = None
    raw:     Optional[str] = None
    meta:    Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["time"] = _iso(self.ts)
        return d


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    src_ip:     str
    severity:   str
    reasons:    List[str]
    fail_count: int
    uniq_users: int
    window_sec: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now() -> float:
    return time.time()


def _iso(t: Optional[float] = None) -> str:
    if t is None:
        t = now()
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


iso_time = _iso