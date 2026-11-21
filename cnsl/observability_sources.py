"""Remote observability log sources (initially Loki query_range pull only).

Each Loki profile normalizes records into the existing Event model and puts
them on the engine's shared queue. No detector or blocking logic lives here.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from .models import Event


@dataclass
class RemoteLogRecord:
    ts: float
    body: str
    labels: Dict[str, str]
    fields: Dict[str, Any]
    source: str
    stream_id: Optional[str]
    record_id: str
    raw: Dict[str, Any]


def _field(obj: Any, path: str) -> Any:
    value = obj
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _timestamp(value: Any, fallback: float) -> float:
    if value is None or value == "":
        return fallback
    try:
        if isinstance(value, (float, int)):
            n = float(value)
            return n / 1e9 if n > 1e15 else n / 1000 if n > 1e12 else n
        text = str(value).strip()
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            n = float(text)
            return n / 1e9 if n > 1e15 else n / 1000 if n > 1e12 else n
    except (TypeError, ValueError, OverflowError):
        return fallback


def _url_for_log(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def _event_source(kind: str, fallback: str) -> str:
    if kind in ("SSH_FAIL", "SSH_SUCCESS"):
        return "auth"
    if kind.startswith("WEB_"):
        return "web"
    if kind.startswith("DB_"):
        return "mysql"
    if kind.startswith("FW_"):
        return "ufw"
    if kind in ("SUDO_FAIL", "SU_FAIL"):
        return "syslog"
    return fallback


class ObservabilitySourceManager:
    def __init__(self, cfg: Dict[str, Any], queue: asyncio.Queue, logger: Any,
                 store: Any, health_tracker: Any = None, metrics: Any = None) -> None:
        self.cfg = cfg.get("observability_sources", {}) or {}
        self.queue = queue
        self.logger = logger
        self.store = store
        self.health_tracker = health_tracker
        self.metrics = metrics
        self.enabled = bool(self.cfg.get("enabled", False))
        self._session = None
        self.stats: Dict[str, Dict[str, Any]] = {}

    def start(self) -> List[asyncio.Task]:
        if not self.enabled:
            return []
        tasks = []
        for name, profile in (self.cfg.get("profiles", {}) or {}).items():
            if not isinstance(profile, dict) or not profile.get("enabled", False):
                continue
            if profile.get("transport", "loki") != "loki":
                # Direct Alloy ingestion intentionally isn't implemented in this milestone.
                tasks.append(asyncio.create_task(self.logger.log("source_warning", {
                    "source": f"{profile.get('transport')}", "profile": name,
                    "message": "only Loki query_range is supported in this release",
                }), name=f"observability-warning:{name}"))
                continue
            source = f"loki:{name}"
            if self.health_tracker:
                self.health_tracker.register_source(source)
            self.stats[name] = {"profile": name, "transport": "loki",
                                "parser": str(profile.get("parser", "json_security")),
                                "service_selectors": list(profile.get("services", []) or []),
                                "last_attempt": None,
                                "last_success": None, "last_event": None, "events": 0,
                                "parsed": 0, "rejected": 0, "deduplicated": 0,
                                "last_error": None, "backoff_sec": 0, "requests": 0,
                                "last_success_count": 0, "request_errors": 0, "lag_sec": 0.0,
                                "queue_backpressure": 0, "last_parse_error": None,
                                "checkpoint_updated": None}
            tasks.append(asyncio.create_task(self._run_profile(name, profile),
                                             name=f"loki:{name}"))
        return tasks

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _client(self):
        if self._session is None:
            import aiohttp
            timeout_sec = max(1, int(self.cfg.get("timeout_sec", 15)))
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_sec))
        return self._session

    async def _run_profile(self, name: str, profile: Dict[str, Any]) -> None:
        stats = self.stats[name]
        delay = 1.0
        interval = max(1.0, float(profile.get("poll_interval_sec", 5)))
        while True:
            stats["last_attempt"] = time.time()
            try:
                stats["requests"] += 1
                if not getattr(self.store, "available", False) or getattr(self.store, "_backend", "sqlite") != "sqlite":
                    raise RuntimeError("Loki checkpoints require an available SQLite store")
                count = await self._poll_once(name, profile)
                stats["last_success"] = time.time()
                stats["last_success_count"] += 1
                stats["checkpoint_updated"] = stats["last_success"]
                stats["last_error"] = None
                stats["backoff_sec"] = 0
                delay = 1.0
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                stats["request_errors"] += 1
                error = str(exc)[:500]
                configured_url = str(profile.get("url", ""))
                if configured_url:
                    error = error.replace(configured_url, _url_for_log(configured_url))
                configured_query = str(profile.get("query", ""))
                if configured_query:
                    error = error.replace(configured_query, "[query redacted]")
                auth_cfg = profile.get("auth", {}) or {}
                token_name = auth_cfg.get("token_env") if isinstance(auth_cfg, dict) else None
                token = os.environ.get(str(token_name), "") if token_name else ""
                if token:
                    error = error.replace(token, "[redacted]")
                stats["last_error"] = error or type(exc).__name__
                stats["backoff_sec"] = round(delay, 1)
                await self.logger.log("source_error", {
                    "source": f"loki:{name}", "error": stats["last_error"],
                    "url": _url_for_log(str(profile.get("url", ""))),
                })
                await asyncio.sleep(delay)
                delay = min(max(delay * 2, 1), 60)

    async def _poll_once(self, name: str, profile: Dict[str, Any]) -> int:
        import aiohttp
        url = str(profile.get("url", "")).rstrip("/")
        query = str(profile.get("query", ""))
        if not url.startswith(("http://", "https://")) or not query or len(query) > 4096:
            raise ValueError("profile requires an HTTP(S) url and a query up to 4096 characters")
        # Query is sent as a parameter, never interpolated into a URL or shell.
        headers: Dict[str, str] = {}
        tenant = profile.get("tenant_id")
        if tenant:
            headers["X-Scope-OrgID"] = str(tenant)
        auth = profile.get("auth", {}) or {}
        if auth.get("type") == "bearer":
            token_name = auth.get("token_env")
            token = os.environ.get(str(token_name), "") if token_name else ""
            if not token:
                raise ValueError("bearer token environment variable is unset")
            headers["Authorization"] = f"Bearer {token}"
        elif auth.get("type") not in (None, "", "none"):
            raise ValueError("unsupported Loki authentication type")

        checkpoint = await self.store.source_checkpoint(name)
        now_ns = time.time_ns()
        lookback_ns = int(max(0, float(profile.get("lookback_sec", 30))) * 1e9)
        if checkpoint:
            start_ns = max(0, checkpoint - lookback_ns)
        elif profile.get("start_position", "checkpoint") == "beginning":
            start_ns = 0
        elif profile.get("start_position") == "now":
            start_ns = now_ns
        else:
            start_ns = now_ns - lookback_ns
        max_range_ns = int(max(1, float(profile.get("max_query_range_sec", 60))) * 1e9)
        end_ns = min(now_ns, start_ns + max_range_ns)
        limit = min(max(1, int(self.cfg.get("max_batch_size", 500))), 5000)
        session = await self._client()
        records: List[RemoteLogRecord] = []
        page_start = start_ns
        while page_start < end_ns:
            params = {"query": query, "start": str(page_start), "end": str(end_ns),
                      "limit": str(limit), "direction": "forward"}
            async with session.get(f"{url}/loki/api/v1/query_range", params=params, headers=headers,
                                   ssl=profile.get("verify_tls", True)) as response:
                if response.status == 429 or response.status >= 500:
                    raise RuntimeError(f"Loki returned HTTP {response.status}")
                response.raise_for_status()
                payload = await response.json(content_type=None)
            if not isinstance(payload, dict) or payload.get("status") != "success":
                raise ValueError("invalid Loki response")
            page = self._records(name, payload)
            records.extend(page)
            if len(page) < limit:
                break
            last_ns = max(int(record.raw["timestamp_ns"]) for record in page)
            if last_ns < page_start:
                break
            page_start = last_ns + 1
        records.sort(key=lambda rec: (rec.ts, rec.record_id))
        checkpoint_ns = checkpoint
        added = parsed = rejected = deduped = 0
        timeout = max(0.05, float(self.cfg.get("queue_timeout_sec", 2)))
        profile_stats = self.stats[name]
        for record in records:
            checkpoint_ns = max(checkpoint_ns, int(record.raw["timestamp_ns"]))
            if self.health_tracker:
                self.health_tracker.record_activity(f"loki:{name}")
            fingerprint = record.record_id
            if await self.store.has_source_record(name, fingerprint):
                deduped += 1
                continue
            ev = self._event(profile, record)
            if ev is None:
                rejected += 1
                profile_stats["last_parse_error"] = "record did not match parser or configured selectors"
                await self.store.commit_source_batch(name, [fingerprint],
                                                     max(checkpoint_ns, int(record.raw["timestamp_ns"])))
                checkpoint_ns = max(checkpoint_ns, int(record.raw["timestamp_ns"]))
                continue
            try:
                await asyncio.wait_for(self.queue.put(ev), timeout=timeout)
            except asyncio.TimeoutError:
                # Do not advance the cursor; this batch will be replayed when the queue drains.
                profile_stats["queue_backpressure"] += 1
                raise RuntimeError("event queue is full; batch checkpoint was not advanced")
            parsed += 1
            added += 1
            await self.store.commit_source_batch(name, [fingerprint],
                                                 max(checkpoint_ns, int(record.raw["timestamp_ns"])))
            checkpoint_ns = max(checkpoint_ns, int(record.raw["timestamp_ns"]))
            profile_stats["last_event"] = time.time()
            profile_stats["lag_sec"] = max(0.0, time.time() - record.ts)
        profile_stats["events"] += added
        profile_stats["parsed"] += parsed
        profile_stats["rejected"] += rejected
        profile_stats["deduplicated"] += deduped
        return len(records)

    def _records(self, name: str, payload: Dict[str, Any]) -> List[RemoteLogRecord]:
        data = payload.get("data", {})
        result = data.get("result", []) if isinstance(data, dict) else []
        records = []
        for stream in result if isinstance(result, list) else []:
            if not isinstance(stream, dict):
                continue
            labels = {str(k): str(v) for k, v in (stream.get("stream", {}) or {}).items()}
            for pair in stream.get("values", []) or []:
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    continue
                try:
                    stamp_ns = int(pair[0])
                except (ValueError, TypeError):
                    continue
                body = str(pair[1])
                ts = stamp_ns / 1e9
                rid = hashlib.sha256((name + "\0" + json.dumps(labels, sort_keys=True) +
                                      "\0" + str(stamp_ns) + "\0" + body).encode()).hexdigest()
                try:
                    fields = json.loads(body) if body.lstrip().startswith("{") else {}
                    if not isinstance(fields, dict):
                        fields = {}
                except (ValueError, TypeError):
                    fields = {}
                records.append(RemoteLogRecord(ts, body, labels, fields, f"loki:{name}",
                                               hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest(),
                                               rid, {"timestamp_ns": stamp_ns, "stream": stream}))
        return records

    def _event(self, profile: Dict[str, Any], record: RemoteLogRecord) -> Optional[Event]:
        from .parsers import _clean_ip
        from .log_sources import parse_mysql, parse_syslog, parse_ufw, parse_web_access
        from .wazuh import parse_wazuh_alert

        parser_name = str(profile.get("parser", "json_security"))
        event = None
        mapping = profile.get("field_map", {}) or {}
        fields = record.fields
        if parser_name in ("json", "json_security"):
            get_value = lambda key, default=None: _field(fields, str(mapping.get(key, key))) if mapping.get(key, key) else default
            kind = get_value("kind", get_value("event_kind"))
            if not kind:
                return None
            ip = _clean_ip(str(get_value("src_ip", "") or "")) if get_value("src_ip") else None
            dst = _clean_ip(str(get_value("dst_ip", "") or "")) if get_value("dst_ip") else None
            user = get_value("user")
            message = get_value("message", record.body)
            ts = _timestamp(get_value("timestamp"), record.ts)
            event = Event(ts=ts, source=_event_source(str(kind), record.source), kind=str(kind), src_ip=ip, dst_ip=dst,
                          user=str(user) if user is not None else None,
                          raw=record.body, meta={"message": str(message) if message is not None else record.body})
        else:
            parsers = {"nginx": lambda line: parse_web_access(line, "nginx"),
                       "apache": lambda line: parse_web_access(line, "apache"),
                       "mysql": parse_mysql, "ufw": parse_ufw, "syslog": parse_syslog,
                       "wazuh": parse_wazuh_alert}
            parser = parsers.get(parser_name)
            if parser is None:
                raise ValueError(f"unknown Loki parser: {parser_name}")
            event = parser(record.body)
            if event is None:
                return None
        labels = record.labels
        for key, value in (profile.get("labels", {}) or {}).items():
            if labels.get(str(key)) != str(value):
                return None
        services = profile.get("services", []) or []
        service = labels.get("service") or labels.get("app") or labels.get("application")
        if services and service not in services:
            return None
        event.meta.update({"transport": "loki", "profile": record.source.split(":", 1)[-1],
                           "service": service, "labels": labels, "loki_stream": record.stream_id,
                           "loki_timestamp": record.ts, "record_id": record.record_id,
                           "container": labels.get("container"), "pod": labels.get("pod"),
                           "namespace": labels.get("namespace"), "parser": parser_name,
                           "parse_status": "parsed"})
        return event
