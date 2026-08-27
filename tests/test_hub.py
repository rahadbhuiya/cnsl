"""
tests/test_hub.py -- tests for the multi-node hub view (cnsl/hub.py)
and its RedisSync/dashboard wiring (cnsl/redis_sync.py's
heartbeat_loop/get_cluster_nodes, cnsl/dashboard_hub.py).
"""

from __future__ import annotations

import asyncio
import json

import pytest
from unittest.mock import AsyncMock, MagicMock

from cnsl.hub import get_hub_view


def _run(coro):
    return asyncio.run(coro)


class TestGetHubView:
    def test_aggregates_multiple_nodes(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(return_value={
            "node-a": {"ts": "2026-07-24T00:00:00Z", "stats": {"blocks_active": 3}},
            "node-b": {"ts": "2026-07-24T00:00:05Z", "stats": {"blocks_active": 7}},
        })
        view = _run(get_hub_view(rs, None))
        assert view["this_node"] == "node-a"
        assert view["node_count"] == 2
        node_ids = {n["node_id"] for n in view["nodes"]}
        assert node_ids == {"node-a", "node-b"}

    def test_self_node_flagged_and_listed_first(self):
        rs = MagicMock()
        rs.node_id = "node-b"
        rs.get_cluster_nodes = AsyncMock(return_value={
            "node-a": {"ts": "t1", "stats": {}},
            "node-b": {"ts": "t2", "stats": {}},
        })
        view = _run(get_hub_view(rs, None))
        assert view["nodes"][0]["node_id"] == "node-b"
        assert view["nodes"][0]["is_self"] is True
        assert view["nodes"][1]["is_self"] is False

    def test_single_node_no_peers(self):
        rs = MagicMock()
        rs.node_id = "solo"
        rs.get_cluster_nodes = AsyncMock(return_value={
            "solo": {"ts": "t1", "stats": {"blocks_active": 0}},
        })
        view = _run(get_hub_view(rs, None))
        assert view["node_count"] == 1
        assert view["nodes"][0]["is_self"] is True

    def test_includes_federation_cross_node_ips_when_given(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(return_value={"node-a": {"ts": "t", "stats": {}}})

        fed = MagicMock()
        rec = MagicMock()
        rec.to_dict.return_value = {"ip": "1.2.3.4", "node_count": 2}
        fed.get_cross_node_ips.return_value = [rec]
        fed.status.return_value = {"enabled": True, "connected": True}

        view = _run(get_hub_view(rs, fed))
        assert view["cross_node_ips"] == [{"ip": "1.2.3.4", "node_count": 2}]
        assert view["federation"] == {"enabled": True, "connected": True}

    def test_federation_none_gives_empty_cross_node_and_none_status(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(return_value={"node-a": {"ts": "t", "stats": {}}})
        view = _run(get_hub_view(rs, None))
        assert view["cross_node_ips"] == []
        assert view["federation"] is None

    def test_redis_failure_degrades_to_self_only(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(side_effect=Exception("redis down"))
        view = _run(get_hub_view(rs, None))  # must not raise
        assert view["node_count"] == 1
        assert view["nodes"][0]["node_id"] == "node-a"

    def test_federation_bus_exception_does_not_break_hub_view(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(return_value={"node-a": {"ts": "t", "stats": {}}})
        fed = MagicMock()
        fed.get_cross_node_ips.side_effect = Exception("boom")
        view = _run(get_hub_view(rs, fed))  # must not raise
        assert view["cross_node_ips"] == []
        assert view["federation"] is None

    def test_cross_node_limit_passed_through(self):
        rs = MagicMock()
        rs.node_id = "node-a"
        rs.get_cluster_nodes = AsyncMock(return_value={"node-a": {"ts": "t", "stats": {}}})
        fed = MagicMock()
        fed.get_cross_node_ips.return_value = []
        fed.status.return_value = {}
        _run(get_hub_view(rs, fed, cross_node_limit=5))
        fed.get_cross_node_ips.assert_called_once_with(limit=5)


class TestRedisSyncClusterHeartbeat:
    """RedisSync.heartbeat_loop()'s stats_provider + get_cluster_nodes()."""

    def _make_rs(self):
        from cnsl.redis_sync import RedisSync
        from cnsl.logger import JsonLogger
        rs = RedisSync({"redis": {"enabled": True}}, JsonLogger("/dev/null", verbose=False))
        rs.node_id = "test-node"
        return rs

    def test_get_cluster_nodes_when_disconnected_returns_self_only(self):
        rs = self._make_rs()
        rs._connected = False
        result = _run(rs.get_cluster_nodes())
        assert set(result.keys()) == {"test-node"}
        assert result["test-node"]["stats"] == {}

    def test_get_cluster_nodes_parses_json_heartbeats(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.keys = AsyncMock(return_value=["cnsl:node:a", "cnsl:node:b"])
        fake_redis.mget = AsyncMock(return_value=[
            json.dumps({"ts": "t1", "stats": {"blocks_active": 2}}),
            json.dumps({"ts": "t2", "stats": {"blocks_active": 9}}),
        ])
        rs._redis = fake_redis
        result = _run(rs.get_cluster_nodes())
        assert result["a"]["stats"]["blocks_active"] == 2
        assert result["b"]["stats"]["blocks_active"] == 9

    def test_get_cluster_nodes_tolerates_legacy_plain_timestamp(self):
        """Older CNSL nodes stored a raw ISO string, not JSON -- must not
        crash the hub view for the whole cluster because one peer is old."""
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.keys = AsyncMock(return_value=["cnsl:node:old"])
        fake_redis.mget = AsyncMock(return_value=["2026-07-24T00:00:00Z"])
        rs._redis = fake_redis
        result = _run(rs.get_cluster_nodes())
        assert result["old"]["ts"] == "2026-07-24T00:00:00Z"
        assert result["old"]["stats"] == {}

    def test_get_cluster_nodes_skips_expired_none_values(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.keys = AsyncMock(return_value=["cnsl:node:gone"])
        fake_redis.mget = AsyncMock(return_value=[None])
        rs._redis = fake_redis
        result = _run(rs.get_cluster_nodes())
        assert result == {}

    def test_get_cluster_nodes_no_keys_returns_empty(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.keys = AsyncMock(return_value=[])
        rs._redis = fake_redis
        result = _run(rs.get_cluster_nodes())
        assert result == {}

    def test_get_cluster_nodes_exception_degrades_to_self(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.keys = AsyncMock(side_effect=Exception("boom"))
        rs._redis = fake_redis
        result = _run(rs.get_cluster_nodes())
        assert set(result.keys()) == {"test-node"}

    def test_heartbeat_loop_stores_json_with_stats(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.setex = AsyncMock()
        rs._redis = fake_redis

        async def _one_tick():
            task = asyncio.ensure_future(
                rs.heartbeat_loop(stats_provider=lambda: {"blocks_active": 4})
            )
            await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(_one_tick())
        assert fake_redis.setex.called
        args = fake_redis.setex.call_args[0]
        stored = json.loads(args[2])
        assert stored["stats"] == {"blocks_active": 4}

    def test_heartbeat_loop_stats_provider_exception_does_not_crash_loop(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.setex = AsyncMock()
        rs._redis = fake_redis

        def _bad_provider():
            raise RuntimeError("stats broke")

        async def _one_tick():
            task = asyncio.ensure_future(rs.heartbeat_loop(stats_provider=_bad_provider))
            await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(_one_tick())  # must not raise
        assert fake_redis.setex.called
        args = fake_redis.setex.call_args[0]
        stored = json.loads(args[2])
        assert stored["stats"] == {}

    def test_heartbeat_loop_without_stats_provider_stores_empty_stats(self):
        rs = self._make_rs()
        rs._connected = True
        fake_redis = MagicMock()
        fake_redis.setex = AsyncMock()
        rs._redis = fake_redis

        async def _one_tick():
            task = asyncio.ensure_future(rs.heartbeat_loop())
            await asyncio.sleep(0.01)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        _run(_one_tick())
        args = fake_redis.setex.call_args[0]
        stored = json.loads(args[2])
        assert stored["stats"] == {}
        assert "ts" in stored


class TestDashboardHubWiring:
    def test_register_hub_routes_importable(self):
        from cnsl.dashboard_hub import register_hub_routes
        assert callable(register_hub_routes)

    def test_hub_route_present_in_source(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        src = (root / "dashboard.py").read_text(encoding="utf-8") + \
              (root / "dashboard_hub.py").read_text(encoding="utf-8")
        assert "/api/federation/hub" in src

    def test_dashboard_py_stays_under_line_budget(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000