"""
cnsl/source_health.py -- log source health monitoring.

CNSL's detectors are only as good as the log sources feeding them. A
filebeat agent that silently stops, an nginx log rotation that breaks
tailing, a Wazuh forwarder that loses its syslog connection -- any of
these leaves CNSL running and reporting "no incidents" while actually
just not seeing anything. This module answers a different question
than the rest of CNSL: not "is this traffic malicious" but "is this
pipe still flowing at all."

Scope: covers every source started via cnsl/log_sources.py's
tail_log_file() -- the configured log_sources (nginx/apache/mysql/ufw/
syslog/wazuh file forwarding), Zeek logs, and OT/ICS log sources.
It does NOT cover cnsl/syslog_receiver.py's UDP/TCP listeners (a
different ingestion model -- there's no single file whose activity to
watch, and a listener with zero traffic is not distinguishable from
"no attacker traffic right now" the way a stalled file tailer is) or
the cloud identity pollers (cnsl/cloud_identity.py, which already have
their own per-connector status()/last_error reporting).

How it works:
  1. Each tail_log_file() call registers its source name and calls
     record_activity() on every line it reads off the file -- whether
     or not that line parsed into an Event. A source producing
     unparseable lines is still alive; the question here is "is the
     pipe flowing," not "is every line understood."
  2. A periodic background loop (run_health_loop) checks every
     registered source's time-since-last-activity against a
     per-source (or default) silence threshold.
  3. A source crossing the threshold logs a `source_silent` event
     exactly once (not every check interval) -- and a `source_recovered`
     event once activity resumes. GET /api/source-health (see
     cnsl/dashboard_source_health.py) exposes live status for the
     dashboard.

Config:
  "source_health": {
    "enabled": true,
    "check_interval_sec": 60,
    "default_silence_threshold_sec": 900,
    "per_source_thresholds": {
      "mysql": 3600
    }
  }
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set


@dataclass
class SourceStatus:
    source:            str
    last_seen:         Optional[float]
    threshold_sec:      int
    healthy:            bool
    silent_for_sec:     Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        from .models import iso_time
        return {
            "source":         self.source,
            "last_seen":      iso_time(self.last_seen) if self.last_seen else None,
            "threshold_sec":  self.threshold_sec,
            "healthy":        self.healthy,
            "silent_for_sec": round(self.silent_for_sec, 1) if self.silent_for_sec is not None else None,
        }


class SourceHealthTracker:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        sh = cfg.get("source_health", {}) or {}
        self.enabled              = bool(sh.get("enabled", True))
        self.check_interval_sec   = int(sh.get("check_interval_sec", 60))
        self.default_threshold    = int(sh.get("default_silence_threshold_sec", 900))
        self.per_source_thresholds: Dict[str, int] = dict(sh.get("per_source_thresholds", {}) or {})

        self._registered: Set[str] = set()
        self._last_seen: Dict[str, float] = {}
        # Tracks whether a source is CURRENTLY considered silent, so
        # transitions (healthy->silent, silent->healthy) are logged
        # exactly once each rather than every check_interval_sec.
        self._is_silent: Dict[str, bool] = {}

    def register_source(self, source: str) -> None:
        """Called once when a source's tailer task starts."""
        self._registered.add(source)
        self._last_seen.setdefault(source, time.time())
        self._is_silent.setdefault(source, False)

    def record_activity(self, source: str, ts: Optional[float] = None) -> None:
        """Called on every line a tailer reads, regardless of parse success."""
        self._last_seen[source] = ts if ts is not None else time.time()

    def threshold_for(self, source: str) -> int:
        return self.per_source_thresholds.get(source, self.default_threshold)

    def _status_for(self, source: str, now_ts: float) -> SourceStatus:
        last_seen = self._last_seen.get(source)
        threshold = self.threshold_for(source)
        if last_seen is None:
            return SourceStatus(source, None, threshold, healthy=True, silent_for_sec=None)
        silent_for = now_ts - last_seen
        return SourceStatus(
            source, last_seen, threshold,
            healthy=silent_for < threshold,
            silent_for_sec=silent_for,
        )

    def status_snapshot(self, now_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """Current status of every registered source, for the dashboard API."""
        now_ts = now_ts if now_ts is not None else time.time()
        return [self._status_for(s, now_ts).to_dict() for s in sorted(self._registered)]

    def check_transitions(self, now_ts: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Check every registered source against its threshold and return
        only the ones that just CHANGED state (silent<->healthy) since
        the last check -- the caller (run_health_loop) logs these.
        Calling this repeatedly with no state change returns [].
        """
        now_ts = now_ts if now_ts is not None else time.time()
        transitions = []
        for source in sorted(self._registered):
            status = self._status_for(source, now_ts)
            was_silent = self._is_silent.get(source, False)
            if status.healthy and was_silent:
                self._is_silent[source] = False
                transitions.append({"source": source, "event": "source_recovered", **status.to_dict()})
            elif not status.healthy and not was_silent:
                self._is_silent[source] = True
                transitions.append({"source": source, "event": "source_silent", **status.to_dict()})
        return transitions

    async def run_health_loop(self, logger: Any) -> None:
        """Background task: periodically check for silent/recovered sources and log transitions."""
        if not self.enabled:
            return
        while True:
            await asyncio.sleep(self.check_interval_sec)
            for t in self.check_transitions():
                await logger.log(t.pop("event"), t)