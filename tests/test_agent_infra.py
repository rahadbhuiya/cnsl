"""
tests/test_agent_infra.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_agent_infra.py -v
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from cnsl.config import DEFAULT_CONFIG, load_config, safe_int
from cnsl.models import Event, EventKind, Severity, iso_time, now
from cnsl.parsers import parse_auth_event, parse_tcpdump_hint
from cnsl.detector import Detector, IPState, _prune, _unique_users

from helpers import make_cfg, make_detector, _run, _det, _make_cm, _SKLEARN_AVAILABLE


class TestAgentQueue:
    """AgentQueue bounded queue with drop-oldest overflow."""

    def test_put_and_get(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=10)
        q.put_nowait({"event": "test"})
        assert q.qsize == 1

    def test_overflow_drops_oldest(self):
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=3)
        q.put_nowait({"id": 1})
        q.put_nowait({"id": 2})
        q.put_nowait({"id": 3})
        # This should drop {"id": 1}
        q.put_nowait({"id": 4})
        assert q.dropped == 1
        assert q.qsize == 3

    def test_get_batch_respects_max_items(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=100)
        for i in range(10):
            q.put_nowait({"id": i})
        batch = asyncio.run(q.get_batch(5, 0.1))
        assert len(batch) == 5

    def test_get_batch_returns_all_if_fewer_than_max(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=100)
        for i in range(3):
            q.put_nowait({"id": i})
        batch = asyncio.run(q.get_batch(10, 0.1))
        assert len(batch) == 3

    def test_get_batch_timeout_returns_empty(self):
        import asyncio
        from cnsl.agent import AgentQueue
        q = AgentQueue(maxsize=10)
        batch = asyncio.run(q.get_batch(5, 0.05))
        assert batch == []

class TestAgentConfig:
    """Agent config loading."""

    def test_default_config_has_required_keys(self):
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        assert "server" in DEFAULT_AGENT_CONFIG
        assert "token"  in DEFAULT_AGENT_CONFIG
        assert "sources" in DEFAULT_AGENT_CONFIG

    def test_load_config_returns_defaults_with_no_file(self):
        from cnsl.agent import load_agent_config
        cfg = load_agent_config("/nonexistent/path/config.json")
        assert cfg["queue_size"] == 1000
        assert "auth" in cfg["sources"]

    def test_load_config_merges_file(self):
        import json, tempfile
        from cnsl.agent import load_agent_config
        data = {"token": "test-token", "hostname": "myhost"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            fname = f.name
        cfg = load_agent_config(fname)
        assert cfg["token"]    == "test-token"
        assert cfg["hostname"] == "myhost"
        assert cfg["queue_size"] == 1000   # default preserved

    def test_hostname_default_is_machine_name(self):
        import socket
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        assert DEFAULT_AGENT_CONFIG["hostname"] == socket.gethostname()

class TestAgentModule:
    """Agent module structure tests."""

    def test_agent_module_importable(self):
        from cnsl import agent
        assert hasattr(agent, "AgentQueue")
        assert hasattr(agent, "run_agent")
        assert hasattr(agent, "load_agent_config")
        assert hasattr(agent, "main")

    def test_supported_sources(self):
        from cnsl.agent import DEFAULT_AGENT_CONFIG
        sources = DEFAULT_AGENT_CONFIG["sources"]
        assert "auth"   in sources
        assert "nginx"  in sources
        assert "apache" in sources
        assert "mysql"  in sources
        assert "ufw"    in sources
        assert "syslog" in sources

    def test_queue_dropped_counter_starts_zero(self):
        from cnsl.agent import AgentQueue
        q = AgentQueue()
        assert q.dropped == 0


# v2.0.0 — Kafka + Multi-tenant + Rate Limiting + Reports

class TestRateLimiter:
    """RateLimiter sliding window and DDoS detection."""

    def _make_rl(self, rpm=10, burst=5, ddos=20, ddos_window=5):
        from cnsl.rate_limiter import RateLimiter
        return RateLimiter({"rate_limiting": {
            "enabled": True, "requests_per_min": rpm, "burst": burst,
            "window_sec": 60, "ddos_threshold": ddos,
            "ddos_window_sec": ddos_window, "auto_block": False,
            "whitelist": ["127.0.0.1"],
        }})

    def test_allows_within_limit(self):
        rl = self._make_rl(rpm=10, burst=5)
        allowed, retry = rl.check("1.2.3.4")
        assert allowed is True
        assert retry == 0.0

    def test_blocks_above_limit(self):
        rl = self._make_rl(rpm=3, burst=0)
        ip = "1.2.3.4"
        for _ in range(3):
            rl.check(ip)
        allowed, retry = rl.check(ip)
        assert allowed is False
        assert retry > 0

    def test_whitelist_always_allowed(self):
        rl = self._make_rl(rpm=1, burst=0)
        for _ in range(100):
            allowed, _ = rl.check("127.0.0.1")
            assert allowed is True

    def test_disabled_always_allows(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": False}})
        allowed, _ = rl.check("1.2.3.4")
        assert allowed is True

    def test_ddos_detection(self):
        rl = self._make_rl(ddos=5, ddos_window=60)
        ip = "2.3.4.5"
        for _ in range(5):
            rl.check_ddos(ip)
        assert rl.check_ddos(ip) is True

    def test_ddos_whitelist_exempt(self):
        rl = self._make_rl(ddos=5, ddos_window=60)
        for _ in range(100):
            assert rl.check_ddos("127.0.0.1") is False

    def test_reset_clears_state(self):
        rl = self._make_rl(rpm=2, burst=0)
        ip = "3.3.3.3"
        for _ in range(3):
            rl.check(ip)
        rl.reset_ip(ip)
        allowed, _ = rl.check(ip)
        assert allowed is True

    def test_stats_structure(self):
        rl = self._make_rl()
        s  = rl.get_stats()
        assert "enabled" in s
        assert "requests_per_min" in s
        assert "total_requests" in s

    def test_top_requesters(self):
        rl = self._make_rl(rpm=100, burst=50)
        for _ in range(5):
            rl.check("1.1.1.1")
            rl.record("1.1.1.1")
        for _ in range(3):
            rl.check("2.2.2.2")
            rl.record("2.2.2.2")
        top = rl.top_requesters(2)
        assert len(top) <= 2

    def test_per_endpoint_config(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {
            "enabled": True, "requests_per_min": 100, "burst": 0,
            "window_sec": 60, "ddos_threshold": 500, "ddos_window_sec": 10,
            "auto_block": False, "whitelist": [],
            "endpoints": {"/api/login": {"requests_per_min": 2, "window_sec": 60}}
        }})
        ip = "4.4.4.4"
        for _ in range(2):
            rl.check(ip, "/api/login")
        allowed, _ = rl.check(ip, "/api/login")
        assert allowed is False

class TestTenantManager:
    """TenantManager single and multi-tenant modes."""

    def _make_single(self):
        from cnsl.tenants import TenantManager
        return TenantManager({
            "auth": {"users": {"admin": {"password_hash": "x", "role": "admin"}}},
            "tenants": {"enabled": False},
        })

    def _make_multi(self):
        from cnsl.tenants import TenantManager
        return TenantManager({"tenants": {
            "enabled": True,
            "default_tenant": "acme",
            "list": {
                "acme":   {"display_name": "Acme Corp", "users": {"alice": {"role": "admin"}}},
                "globex": {"display_name": "Globex Inc", "users": {"bob": {"role": "analyst"}}},
            },
        }})

    def test_single_tenant_default(self):
        tm = self._make_single()
        assert tm.enabled is False
        assert tm.count == 1

    def test_single_tenant_get_default(self):
        tm = self._make_single()
        t  = tm.get_default()
        assert t is not None
        assert t.id == "default"

    def test_multi_tenant_count(self):
        tm = self._make_multi()
        assert tm.count == 2

    def test_resolve_by_id(self):
        tm = self._make_multi()
        t  = tm.resolve("acme")
        assert t.display_name == "Acme Corp"

    def test_resolve_unknown_falls_back_to_default(self):
        tm = self._make_multi()
        t  = tm.resolve("unknown_tenant")
        assert t.id == "acme"

    def test_list_tenants(self):
        tm = self._make_multi()
        lst = tm.list_tenants()
        ids = [t["id"] for t in lst]
        assert "acme" in ids and "globex" in ids

    def test_add_tenant(self):
        tm  = self._make_multi()
        err = tm.add_tenant("newco", {"display_name": "NewCo"})
        assert err is None
        assert tm.count == 3

    def test_add_duplicate_tenant_returns_error(self):
        tm  = self._make_multi()
        err = tm.add_tenant("acme", {})
        assert err is not None

    def test_remove_tenant(self):
        tm  = self._make_multi()
        err = tm.remove_tenant("globex")
        assert err is None
        assert tm.count == 1

    def test_cannot_remove_default_tenant(self):
        tm  = self._make_multi()
        err = tm.remove_tenant("acme")  # acme is default
        assert err is not None

    def test_per_tenant_rules(self):
        from cnsl.tenants import TenantManager
        tm = TenantManager({"tenants": {
            "enabled": True,
            "default_tenant": "t1",
            "list": {
                "t1": {"rules": {"ssh.brute_force": {"threshold": 3}}},
            },
        }})
        t = tm.resolve("t1")
        re = t.get_rules({})
        assert re.threshold("ssh.brute_force") == 3

    def test_update_tenant_rules(self):
        tm  = self._make_multi()
        err = tm.update_tenant_rules("acme", {"ssh.brute_force": {"threshold": 2}})
        assert err is None
        t   = tm.resolve("acme")
        re  = t.get_rules({})
        assert re.threshold("ssh.brute_force") == 2

class TestKafkaConsumer:
    """KafkaConsumer config and parser registry."""

    def test_disabled_by_default(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({}, None, None)
        assert kc.enabled is False

    def test_config_loaded(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({"kafka": {
            "enabled": True,
            "bootstrap_servers": "kafka:9092",
            "group_id": "test-group",
            "topics": {"auth_logs": {"parser": "auth", "enabled": True}},
        }}, None, None)
        assert kc.enabled is True
        assert kc.bootstrap_servers == "kafka:9092"
        assert "auth_logs" in kc.topics_cfg

    def test_parser_registry_has_standard_parsers(self):
        from cnsl.kafka_consumer import _build_parser_registry
        registry = _build_parser_registry()
        assert "auth"   in registry
        assert "nginx"  in registry
        assert "syslog" in registry
        assert "json"   in registry

    def test_json_parser_valid_event(self):
        from cnsl.kafka_consumer import _parse_json_event
        import json
        line = json.dumps({
            "kind": "SSH_FAIL", "src_ip": "1.2.3.4",
            "source": "kafka", "ts": 1700000000.0
        })
        ev = _parse_json_event(line)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"
        assert ev.src_ip == "1.2.3.4"

    def test_json_parser_invalid_returns_none(self):
        from cnsl.kafka_consumer import _parse_json_event
        assert _parse_json_event("not json") is None
        assert _parse_json_event("{}") is None

    def test_stats_structure(self):
        from cnsl.kafka_consumer import KafkaConsumer
        kc = KafkaConsumer({"kafka": {"enabled": True}}, None, None)
        s  = kc.get_stats()
        assert "enabled" in s
        assert "messages_received" in s
        assert "events_parsed" in s

class TestDistributedRateLimiter:
    """RateLimiter accepts redis_sync param and exposes increment_distributed."""

    def test_accepts_redis_sync_param(self):
        from cnsl.rate_limiter import RateLimiter
        import inspect
        sig = inspect.signature(RateLimiter.__init__)
        assert "redis_sync" in sig.parameters

    def test_redis_sync_defaults_to_none(self):
        from cnsl.rate_limiter import RateLimiter
        import inspect
        sig = inspect.signature(RateLimiter.__init__)
        assert sig.parameters["redis_sync"].default is None

    def test_increment_distributed_method_exists(self):
        from cnsl.rate_limiter import RateLimiter
        assert hasattr(RateLimiter, "increment_distributed")
        assert callable(RateLimiter.increment_distributed)

    def test_increment_distributed_returns_minus_one_without_redis(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": True}}, redis_sync=None)
        result = _run(rl.increment_distributed("1.2.3.4", 60))
        assert result == -1

    def test_no_redis_does_not_crash_check(self):
        from cnsl.rate_limiter import RateLimiter
        rl = RateLimiter({"rate_limiting": {"enabled": True}}, redis_sync=None)
        allowed, retry = rl.check("1.2.3.4")
        assert isinstance(allowed, bool)

class TestRequestSizeLimit:
    """dashboard.py must set client_max_size on the aiohttp Application."""

    def test_client_max_size_set(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py"
               ).read_text(encoding="utf-8")
        assert "client_max_size" in src, \
            "client_max_size missing from web.Application() -- no request size limit"
