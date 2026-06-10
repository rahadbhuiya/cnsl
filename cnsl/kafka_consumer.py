"""
cnsl/kafka_consumer.py — Kafka log ingestion.

Consumes events from Kafka topics and feeds them into the CNSL
detection pipeline. Supports multiple topics with per-topic parsers.

Supported topic formats:
  - Raw log lines (syslog, auth.log, nginx, apache, mysql, ufw)
  - JSON events (pre-parsed, directly mapped to Event objects)
  - Zeek JSON logs

Config (config.json):
  "kafka": {
    "enabled":        true,
    "bootstrap_servers": "localhost:9092",
    "group_id":       "cnsl-consumer",
    "auto_offset_reset": "latest",
    "topics": {
      "auth_logs":    {"parser": "auth",   "enabled": true},
      "nginx_logs":   {"parser": "nginx",  "enabled": true},
      "syslog":       {"parser": "syslog", "enabled": true},
      "cnsl_events":  {"parser": "json",   "enabled": true},
      "zeek_ssh":     {"parser": "zeek_ssh", "enabled": false}
    },
    "batch_size":     100,
    "poll_timeout_ms":1000,
    "commit_interval": 5
  }

Supported parsers:
  auth, nginx, apache, mysql, ufw, syslog, json,
  zeek_conn, zeek_ssh, zeek_http, zeek_dns, zeek_notice, zeek_weird
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from .models import Event, now

if TYPE_CHECKING:
    from .detector import Detector
    from .logger   import JsonLogger


#  Parser registry 


def _build_parser_registry() -> Dict[str, Callable]:
    """Build a map of parser name → parse function."""
    registry: Dict[str, Callable] = {}

    # Standard log parsers
    try:
        from .parsers     import parse_auth_event
        from .log_sources import parse_web_access, parse_mysql, parse_ufw, parse_syslog
        registry["auth"]   = parse_auth_event
        registry["nginx"]  = lambda l: parse_web_access(l, "nginx")
        registry["apache"] = lambda l: parse_web_access(l, "apache")
        registry["mysql"]  = parse_mysql
        registry["ufw"]    = parse_ufw
        registry["syslog"] = parse_syslog
    except ImportError:
        pass

    # Zeek parsers
    try:
        from .zeek_parser import ZeekLogParser
        for log_type in ("conn", "ssh", "http", "dns", "notice", "weird"):
            zp = ZeekLogParser(log_type, fmt="json")
            registry[f"zeek_{log_type}"] = zp.parse
    except ImportError:
        pass

    # JSON passthrough parser
    registry["json"] = _parse_json_event

    return registry


def _parse_json_event(line: str) -> Optional[Event]:
    """Parse a pre-serialised CNSL Event JSON string."""
    try:
        d = json.loads(line)
        if not isinstance(d, dict):
            return None
        kind   = d.get("kind", "")
        src_ip = d.get("src_ip", "")
        if not kind or not src_ip:
            return None
        return Event(
            ts     = d.get("ts", now()),
            source = d.get("source", "kafka"),
            kind   = kind,
            src_ip = src_ip,
            user   = d.get("user"),
            meta   = d.get("meta", {}),
        )
    except (json.JSONDecodeError, Exception):
        return None


#  KafkaConsumer 


class KafkaConsumer:
    """
    Async Kafka consumer that feeds parsed events into the detector.

    Uses aiokafka (async) with a sync fallback to confluent-kafka via
    run_in_executor if aiokafka is not installed.

    Usage:
        consumer = KafkaConsumer(cfg, detector, logger)
        await consumer.start()   # returns; runs as background tasks
        await consumer.stop()
    """

    def __init__(
        self,
        cfg:      Dict[str, Any],
        detector: "Detector",
        logger:   "JsonLogger",
    ):
        kc = cfg.get("kafka", {})
        self.enabled           = bool(kc.get("enabled", False))
        self.bootstrap_servers = kc.get("bootstrap_servers", "localhost:9092")
        self.group_id          = kc.get("group_id", "cnsl-consumer")
        self.auto_offset_reset = kc.get("auto_offset_reset", "latest")
        self.topics_cfg        = kc.get("topics", {})
        self.batch_size        = int(kc.get("batch_size", 100))
        self.poll_timeout_ms   = int(kc.get("poll_timeout_ms", 1000))
        self.commit_interval   = int(kc.get("commit_interval", 5))
        self.detector          = detector
        self.logger            = logger
        self._parsers          = _build_parser_registry()
        self._tasks: List[asyncio.Task] = []
        self._stats: Dict[str, int]     = {
            "messages_received": 0,
            "events_parsed":     0,
            "parse_errors":      0,
        }

    #  Lifecycle 

    async def start(self) -> None:
        """Start consumers for all enabled topics."""
        if not self.enabled:
            return

        enabled_topics = {
            topic: cfg
            for topic, cfg in self.topics_cfg.items()
            if cfg.get("enabled", True)
        }

        if not enabled_topics:
            await self.logger.log("kafka_warning", {"msg": "No enabled Kafka topics"})
            return

        await self.logger.log("kafka_starting", {
            "bootstrap": self.bootstrap_servers,
            "group_id":  self.group_id,
            "topics":    list(enabled_topics.keys()),
        })

        # Try aiokafka first, fall back to sync confluent-kafka
        try:
            import aiokafka  # noqa: F401
            for topic, topic_cfg in enabled_topics.items():
                task = asyncio.create_task(
                    self._consume_aiokafka(topic, topic_cfg),
                    name=f"kafka_{topic}",
                )
                self._tasks.append(task)
        except ImportError:
            try:
                import confluent_kafka  # noqa: F401
                for topic, topic_cfg in enabled_topics.items():
                    task = asyncio.create_task(
                        self._consume_confluent(topic, topic_cfg),
                        name=f"kafka_{topic}",
                    )
                    self._tasks.append(task)
            except ImportError:
                await self.logger.log("kafka_error", {
                    "msg": "Neither aiokafka nor confluent-kafka is installed.",
                    "hint": "Run: pip install aiokafka  OR  pip install confluent-kafka",
                })

    async def stop(self) -> None:
        """Cancel all consumer tasks."""
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled":   self.enabled,
            "topics":    list(self.topics_cfg.keys()),
            **self._stats,
        }

    #  aiokafka consumer 

    async def _consume_aiokafka(self, topic: str, topic_cfg: Dict) -> None:
        import aiokafka

        parser_name = topic_cfg.get("parser", "auth")
        parser      = self._parsers.get(parser_name)

        consumer = aiokafka.AIOKafkaConsumer(
            topic,
            bootstrap_servers  = self.bootstrap_servers,
            group_id           = self.group_id,
            auto_offset_reset  = self.auto_offset_reset,
            enable_auto_commit = False,
            value_deserializer = lambda m: m.decode("utf-8", errors="replace"),
        )

        backoff = 2.0
        while True:
            try:
                await consumer.start()
                backoff = 2.0
                await self.logger.log("kafka_consumer_started", {"topic": topic})
                last_commit = time.time()

                async for msg in consumer:
                    self._stats["messages_received"] += 1
                    await self._process_message(msg.value, parser, topic)

                    # Periodic commit
                    if time.time() - last_commit >= self.commit_interval:
                        await consumer.commit()
                        last_commit = time.time()

            except asyncio.CancelledError:
                break
            except Exception as exc:
                await self.logger.log("kafka_consumer_error", {
                    "topic": topic, "error": str(exc), "retry_sec": backoff,
                })
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)
            finally:
                try:
                    await consumer.stop()
                except Exception:
                    pass

    #  confluent-kafka consumer (sync → executor) 

    async def _consume_confluent(self, topic: str, topic_cfg: Dict) -> None:
        import confluent_kafka

        parser_name = topic_cfg.get("parser", "auth")
        parser      = self._parsers.get(parser_name)

        def _sync_consume(q: asyncio.Queue) -> None:
            consumer = confluent_kafka.Consumer({
                "bootstrap.servers":  self.bootstrap_servers,
                "group.id":           self.group_id,
                "auto.offset.reset":  self.auto_offset_reset,
                "enable.auto.commit": False,
            })
            consumer.subscribe([topic])
            msg_count = 0
            try:
                while True:
                    msg = consumer.poll(timeout=self.poll_timeout_ms / 1000)
                    if msg is None:
                        continue
                    if msg.error():
                        continue
                    value = msg.value().decode("utf-8", errors="replace")
                    try:
                        q.put_nowait(value)
                    except asyncio.QueueFull:
                        pass
                    msg_count += 1
                    if msg_count % self.commit_interval == 0:
                        consumer.commit(asynchronous=True)
            finally:
                consumer.close()

        loop   = asyncio.get_event_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=self.batch_size * 2)

        task_sync = loop.run_in_executor(None, _sync_consume, q)

        try:
            while True:
                value = await q.get()
                self._stats["messages_received"] += 1
                await self._process_message(value, parser, topic)
        except asyncio.CancelledError:
            task_sync.cancel()

    #  Message processing 

    async def _process_message(
        self,
        value:  str,
        parser: Optional[Callable],
        topic:  str,
    ) -> None:
        if not parser or not value:
            return
        try:
            ev = parser(value)
            if ev and ev.src_ip:
                await self.detector.handle(ev)
                self._stats["events_parsed"] += 1
        except Exception:
            self._stats["parse_errors"] += 1