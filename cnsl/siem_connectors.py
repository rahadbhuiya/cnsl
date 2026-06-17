"""
cnsl/siem_connectors.py -- Native SIEM/SOAR Push Connectors.

Pushes CNSL incidents and detections to external SIEM and SOAR platforms
in real time. Unlike the export endpoints (/api/export/cef, /api/export/ecs)
which require a human to pull data, these connectors actively push events
as they happen.

Supported connectors:

  SplunkHECConnector       -- Splunk HTTP Event Collector (HEC)
                              Pushes JSON events to /services/collector/event
                              Supports index, sourcetype, host overrides

  SentinelConnector        -- Microsoft Sentinel / Azure Monitor Logs
                              Pushes via the Data Collection Rule (DCR) API
                              or the legacy Log Analytics Data Collector API
                              Supports custom table names

  WebhookConnector         -- Generic HTTPS webhook (Palo Alto XSOAR,
                              IBM QRadar, custom SOC tooling)
                              Pushes JSON payload with CNSL envelope

  SIEMRouter               -- Orchestrates all enabled connectors.
                              Called by engine after each detection fires.
                              Retries failed pushes up to max_retries times
                              with exponential backoff. Queues events in
                              memory if connector is temporarily unavailable.

Config (config.json):
  "siem": {
    "splunk": {
      "enabled":    false,
      "hec_url":    "https://splunk.example.com:8088",
      "token":      "your-hec-token",
      "index":      "cnsl",
      "sourcetype": "cnsl:incident",
      "host":       "",
      "verify_ssl": true,
      "timeout_sec": 5,
      "max_retries": 3,
      "min_severity": "MEDIUM"
    },
    "sentinel": {
      "enabled":        false,
      "workspace_id":   "your-workspace-id",
      "shared_key":     "your-shared-key",
      "log_type":       "CNSLIncident",
      "api_version":    "2016-04-01",
      "timeout_sec":    5,
      "max_retries":    3,
      "min_severity":   "MEDIUM"
    },
    "webhook": {
      "enabled":      false,
      "url":          "https://your-soar.example.com/api/ingest",
      "method":       "POST",
      "headers":      {},
      "bearer_token": "",
      "verify_ssl":   true,
      "timeout_sec":  5,
      "max_retries":  3,
      "min_severity": "MEDIUM"
    }
  }

API endpoints (added in dashboard.py):
  GET  /api/siem/status          -- connector health + queue stats
  POST /api/siem/test/{name}     -- send test event to one connector
  POST /api/siem/flush           -- force flush queued events
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .models import Detection, iso_time, now



# Severity ordering (for min_severity filtering)


_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _sev_passes(detection_severity: str, min_severity: str) -> bool:
    return _SEV_RANK.get(detection_severity, 0) >= _SEV_RANK.get(min_severity, 0)



# Shared event serializer


def _detection_to_dict(detection: Any, source: str = "cnsl") -> Dict[str, Any]:
    """Convert a Detection (or dict) to a flat dict safe for JSON push."""
    if isinstance(detection, dict):
        return detection
    try:
        d = detection.to_dict() if hasattr(detection, "to_dict") else vars(detection)
        d["_cnsl_source"]  = source
        d["_cnsl_version"] = "2.4.0"
        d["_push_time"]    = iso_time(now())
        return d
    except Exception:
        return {"raw": str(detection), "_cnsl_source": source}



# Retry queue entry


@dataclass
class _QueueEntry:
    connector: str
    payload:   Dict[str, Any]
    attempts:  int   = 0
    queued_at: float = field(default_factory=now)



# Splunk HEC Connector


class SplunkHECConnector:
    """
    Pushes events to Splunk via the HTTP Event Collector (HEC) API.

    Endpoint: POST {hec_url}/services/collector/event
    Auth:     Authorization: Splunk {token}
    Format:   {"time": ..., "host": ..., "sourcetype": ..., "index": ..., "event": {...}}

    Batching: events are sent one at a time on detection. For high-volume
    environments, increase batch_size in config to collect N events before
    flushing (default: 1 = immediate).
    """

    NAME = "splunk"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        sp = cfg.get("siem", {}).get("splunk", {})
        self.enabled      = bool(sp.get("enabled", False))
        self.hec_url      = sp.get("hec_url", "").rstrip("/")
        self.token        = sp.get("token", "")
        self.index        = sp.get("index", "cnsl")
        self.sourcetype   = sp.get("sourcetype", "cnsl:incident")
        self.host         = sp.get("host", "")
        self.verify_ssl   = bool(sp.get("verify_ssl", True))
        self.timeout      = int(sp.get("timeout_sec", 5))
        self.max_retries  = int(sp.get("max_retries", 3))
        self.min_severity = sp.get("min_severity", "MEDIUM")
        self._session     = None
        self._last_error: Optional[str] = None
        self._push_count  = 0
        self._error_count = 0

    async def push(self, detection: Any) -> bool:
        """Push one detection. Returns True on success."""
        if not self.enabled or not self.hec_url or not self.token:
            return False

        sev = getattr(detection, "severity", "MEDIUM")
        if hasattr(sev, "name"):
            sev = sev.name
        if not _sev_passes(str(sev), self.min_severity):
            return True  # filtered, not an error

        event = _detection_to_dict(detection, source="splunk_hec")
        payload = {
            "time":       event.get("ts", now()),
            "sourcetype": self.sourcetype,
            "index":      self.index,
            "event":      event,
        }
        if self.host:
            payload["host"] = self.host

        session = await self._get_session()
        if not session:
            return False

        try:
            async with session.post(
                f"{self.hec_url}/services/collector/event",
                json=payload,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type":  "application/json",
                },
                ssl=self.verify_ssl,
            ) as resp:
                ok = resp.status in (200, 201)
                if ok:
                    self._push_count += 1
                    self._last_error = None
                else:
                    body = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {body[:120]}"
                    self._error_count += 1
                return ok
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return False

    async def health(self) -> Dict[str, Any]:
        """Check HEC endpoint health via /services/collector/health."""
        if not self.enabled:
            return {"enabled": False}
        session = await self._get_session()
        if not session:
            return {"enabled": True, "error": "aiohttp not installed"}
        try:
            async with session.get(
                f"{self.hec_url}/services/collector/health",
                headers={"Authorization": f"Splunk {self.token}"},
                ssl=self.verify_ssl,
            ) as resp:
                return {
                    "enabled":     True,
                    "status":      resp.status,
                    "healthy":     resp.status == 200,
                    "push_count":  self._push_count,
                    "error_count": self._error_count,
                    "last_error":  self._last_error,
                }
        except Exception as e:
            return {
                "enabled":    True,
                "healthy":    False,
                "error":      str(e),
                "push_count": self._push_count,
                "error_count":self._error_count,
            }

    async def _get_session(self):
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                return None
        return self._session

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass



# Microsoft Sentinel Connector


class SentinelConnector:
    """
    Pushes events to Microsoft Sentinel via the Log Analytics
    Data Collector REST API (legacy, widely supported).

    Endpoint: POST https://{workspace_id}.ods.opinsights.azure.com
                   /api/logs?api-version={api_version}
    Auth:     HMAC-SHA256 signature using shared_key
    Format:   JSON array of event objects

    Microsoft docs:
    https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
    """

    NAME = "sentinel"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        sc = cfg.get("siem", {}).get("sentinel", {})
        self.enabled       = bool(sc.get("enabled", False))
        self.workspace_id  = sc.get("workspace_id", "")
        self.shared_key    = sc.get("shared_key", "")
        self.log_type      = sc.get("log_type", "CNSLIncident")
        self.api_version   = sc.get("api_version", "2016-04-01")
        self.timeout       = int(sc.get("timeout_sec", 5))
        self.max_retries   = int(sc.get("max_retries", 3))
        self.min_severity  = sc.get("min_severity", "MEDIUM")
        self._session      = None
        self._last_error: Optional[str] = None
        self._push_count   = 0
        self._error_count  = 0

    def _build_signature(self, date: str, content_length: int) -> str:
        """Build the HMAC-SHA256 Authorization header value."""
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        key     = base64.b64decode(self.shared_key)
        sig     = hmac.new(key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
        encoded = base64.b64encode(sig).decode("utf-8")
        return f"SharedKey {self.workspace_id}:{encoded}"

    async def push(self, detection: Any) -> bool:
        """Push one detection. Returns True on success."""
        if not self.enabled or not self.workspace_id or not self.shared_key:
            return False

        sev = getattr(detection, "severity", "MEDIUM")
        if hasattr(sev, "name"):
            sev = sev.name
        if not _sev_passes(str(sev), self.min_severity):
            return True

        event   = _detection_to_dict(detection, source="sentinel")
        body    = json.dumps([event], default=str)
        encoded = body.encode("utf-8")
        date    = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
        sig     = self._build_signature(date, len(encoded))

        url = (
            f"https://{self.workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version={self.api_version}"
        )

        session = await self._get_session()
        if not session:
            return False

        try:
            async with session.post(
                url,
                data=encoded,
                headers={
                    "Content-Type":  "application/json",
                    "Authorization": sig,
                    "Log-Type":      self.log_type,
                    "x-ms-date":     date,
                    "time-generated-field": "ts",
                },
            ) as resp:
                ok = resp.status == 200
                if ok:
                    self._push_count += 1
                    self._last_error = None
                else:
                    body_text = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {body_text[:120]}"
                    self._error_count += 1
                return ok
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return False

    async def health(self) -> Dict[str, Any]:
        return {
            "enabled":      self.enabled,
            "workspace_id": self.workspace_id,
            "log_type":     self.log_type,
            "push_count":   self._push_count,
            "error_count":  self._error_count,
            "last_error":   self._last_error,
            "healthy":      self._error_count == 0 or self._push_count > 0,
        }

    async def _get_session(self):
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                return None
        return self._session

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass



# Generic Webhook Connector


class WebhookConnector:
    """
    Generic HTTPS webhook push connector.

    Works with: Palo Alto XSOAR, IBM QRadar REST API,
    custom SOC ingest endpoints, PagerDuty Events v2,
    and any system that accepts JSON POST.

    Payload envelope:
    {
      "cnsl_version": "2.4.0",
      "push_time":    "...",
      "event":        { ...detection dict... }
    }
    """

    NAME = "webhook"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        wh = cfg.get("siem", {}).get("webhook", {})
        self.enabled       = bool(wh.get("enabled", False))
        self.url           = wh.get("url", "")
        self.method        = wh.get("method", "POST").upper()
        self.extra_headers = wh.get("headers", {})
        self.bearer_token  = wh.get("bearer_token", "")
        self.verify_ssl    = bool(wh.get("verify_ssl", True))
        self.timeout       = int(wh.get("timeout_sec", 5))
        self.max_retries   = int(wh.get("max_retries", 3))
        self.min_severity  = wh.get("min_severity", "MEDIUM")
        self._session      = None
        self._last_error: Optional[str] = None
        self._push_count   = 0
        self._error_count  = 0

    async def push(self, detection: Any) -> bool:
        """Push one detection. Returns True on success."""
        if not self.enabled or not self.url:
            return False

        sev = getattr(detection, "severity", "MEDIUM")
        if hasattr(sev, "name"):
            sev = sev.name
        if not _sev_passes(str(sev), self.min_severity):
            return True

        event = _detection_to_dict(detection, source="webhook")
        payload = {
            "cnsl_version": "2.4.0",
            "push_time":    iso_time(now()),
            "event":        event,
        }

        headers = {"Content-Type": "application/json"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        headers.update(self.extra_headers)

        session = await self._get_session()
        if not session:
            return False

        try:
            req_method = getattr(session, self.method.lower(), session.post)
            async with req_method(
                self.url,
                json=payload,
                headers=headers,
                ssl=self.verify_ssl,
            ) as resp:
                ok = 200 <= resp.status < 300
                if ok:
                    self._push_count += 1
                    self._last_error = None
                else:
                    body = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {body[:120]}"
                    self._error_count += 1
                return ok
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return False

    async def health(self) -> Dict[str, Any]:
        return {
            "enabled":     self.enabled,
            "url":         self.url,
            "push_count":  self._push_count,
            "error_count": self._error_count,
            "last_error":  self._last_error,
            "healthy":     self._error_count == 0 or self._push_count > 0,
        }

    async def _get_session(self):
        if self._session is None:
            try:
                import aiohttp
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                return None
        return self._session

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass



# SIEM Router -- orchestrates all connectors


class SIEMRouter:
    """
    Orchestrates all enabled SIEM/SOAR connectors.

    Usage:
        router = SIEMRouter(cfg)
        await router.push(detection)      # called after every detection
        status = await router.status()    # called by dashboard
        await router.close()              # called on shutdown
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.splunk   = SplunkHECConnector(cfg)
        self.sentinel = SentinelConnector(cfg)
        self.webhook  = WebhookConnector(cfg)

        self.enabled = (
            self.splunk.enabled
            or self.sentinel.enabled
            or self.webhook.enabled
        )

        # Retry queue (in-memory, not persisted)
        self._queue: Deque[_QueueEntry] = deque(maxlen=1000)
        self._flush_lock = asyncio.Lock()

    @property
    def connectors(self) -> List[Any]:
        return [self.splunk, self.sentinel, self.webhook]

    async def push(self, detection: Any) -> None:
        """
        Push a detection to all enabled connectors.
        Failed pushes are queued for retry.
        """
        if not self.enabled:
            return

        for connector in self.connectors:
            if not connector.enabled:
                continue
            ok = await self._push_with_retry(connector, detection)
            if not ok:
                self._queue.append(_QueueEntry(
                    connector = connector.NAME,
                    payload   = _detection_to_dict(detection),
                ))

    async def flush_queue(self) -> Dict[str, int]:
        """Retry all queued events. Returns counts by connector."""
        if not self._queue:
            return {}
        async with self._flush_lock:
            counts: Dict[str, int] = {}
            remaining: Deque[_QueueEntry] = deque()
            connector_map = {c.NAME: c for c in self.connectors}
            while self._queue:
                entry = self._queue.popleft()
                connector = connector_map.get(entry.connector)
                if connector is None or not connector.enabled:
                    continue
                entry.attempts += 1
                ok = await connector.push(entry.payload)
                if ok:
                    counts[entry.connector] = counts.get(entry.connector, 0) + 1
                elif entry.attempts < connector.max_retries:
                    remaining.append(entry)
            self._queue = remaining
            return counts

    async def status(self) -> Dict[str, Any]:
        """Return health and stats for all connectors."""
        results = {}
        for connector in self.connectors:
            results[connector.NAME] = await connector.health()
        return {
            "connectors":  results,
            "queue_depth": len(self._queue),
            "any_enabled": self.enabled,
        }

    async def close(self) -> None:
        for connector in self.connectors:
            await connector.close()

    async def _push_with_retry(
        self,
        connector: Any,
        detection: Any,
        max_attempts: int = 2,
    ) -> bool:
        """Try pushing with up to max_attempts immediate retries."""
        for attempt in range(max_attempts):
            ok = await connector.push(detection)
            if ok:
                return True
            if attempt < max_attempts - 1:
                await asyncio.sleep(0.5 * (attempt + 1))
        return False