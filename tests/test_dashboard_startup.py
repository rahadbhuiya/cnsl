"""
tests/test_dashboard_startup.py -- end-to-end regression tests for
cnsl.dashboard.start_dashboard() and the engine.py startup sequence.

Every other dashboard test in this suite checks start_dashboard()'s
*signature* (inspect.signature) but none actually called it -- which is
how two real, startup-crashing bugs shipped untested:

  1. dashboard.py referenced `_RateLimiter` without importing it (the
     class existed, orphaned and itself broken, in dashboard_html.py).
     start_dashboard() raised NameError on its very first line.
  2. GET /api/health called `redis_sync.connected` unguarded --
     AttributeError (500) whenever redis_sync is None, which is the
     default/common case (Redis disabled).

These tests actually start a real dashboard on a real port and make a
real HTTP request against it, specifically to prevent "the test suite
is green but the app doesn't start" from recurring.
"""

from __future__ import annotations

import asyncio

import pytest


def _run(coro):
    return asyncio.run(coro)


async def _start_and_probe(port: int, **extra_kwargs):
    """Start a real dashboard on 127.0.0.1:<port>, GET /api/health
    against it, then cancel and clean up. Returns (status, body)."""
    import aiohttp
    from cnsl.dashboard import start_dashboard
    from cnsl.detector import Detector
    from cnsl.blocker import Blocker
    from cnsl.store import Store
    from cnsl.metrics import Metrics
    from cnsl.logger import JsonLogger
    from cnsl.auth import AuthManager

    logger = JsonLogger("/dev/null", verbose=False)
    blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                       ipset_name="x", block_duration_sec=900,
                       allowlist=set(), logger=logger)
    cfg = {"auth": {"enabled": False}}
    store = Store(":memory:")
    await store.init()
    metrics = Metrics()
    auth = AuthManager(cfg)
    detector = Detector(cfg, blocker, logger)

    task = asyncio.ensure_future(
        start_dashboard("127.0.0.1", port, detector, blocker, store,
                         metrics, logger, auth=auth, **extra_kwargs)
    )
    try:
        # Give the server a moment to bind -- fail fast if start_dashboard
        # raises immediately (e.g. a NameError on its first line) instead
        # of hanging for the full timeout.
        for _ in range(50):
            if task.done():
                task.result()  # re-raise whatever crashed it
            await asyncio.sleep(0.05)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://127.0.0.1:{port}/api/health",
                        timeout=aiohttp.ClientTimeout(total=1),
                    ) as resp:
                        body = await resp.json()
                        return resp.status, body
            except aiohttp.ClientConnectorError:
                continue
        raise TimeoutError(f"dashboard never became reachable on port {port}")
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        await store.close()


async def _start_and_post(port: int, path: str, **extra_kwargs):
    """Same as _start_and_probe, but POSTs to an arbitrary path once the
    dashboard is reachable, instead of GETting /api/health."""
    import aiohttp
    from cnsl.dashboard import start_dashboard
    from cnsl.detector import Detector
    from cnsl.blocker import Blocker
    from cnsl.store import Store
    from cnsl.metrics import Metrics
    from cnsl.logger import JsonLogger
    from cnsl.auth import AuthManager

    logger = JsonLogger("/dev/null", verbose=False)
    blocker = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                       ipset_name="x", block_duration_sec=900,
                       allowlist=set(), logger=logger)
    cfg = {"auth": {"enabled": False}}
    store = Store(":memory:")
    await store.init()
    metrics = Metrics()
    auth = AuthManager(cfg)
    detector = Detector(cfg, blocker, logger)

    task = asyncio.ensure_future(
        start_dashboard("127.0.0.1", port, detector, blocker, store,
                         metrics, logger, auth=auth, **extra_kwargs)
    )
    try:
        for _ in range(50):
            if task.done():
                task.result()
            await asyncio.sleep(0.05)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"http://127.0.0.1:{port}{path}",
                        timeout=aiohttp.ClientTimeout(total=1),
                    ) as resp:
                        body = await resp.json()
                        return resp.status, body
            except aiohttp.ClientConnectorError:
                continue
        raise TimeoutError(f"dashboard never became reachable on port {port}")
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        await store.close()


class TestSiemTestEndpointDoesNotCrash:
    """Regression guard for the v3.4.18 fix: api_siem_test() called
    now() to timestamp its synthetic test event, but `now` was never
    imported in dashboard.py -- every POST to
    /api/siem/test/{name} raised NameError and returned a 500."""

    class _FakeConnector:
        def __init__(self, enabled: bool):
            self.enabled = enabled
            self.calls = []

        async def push(self, event):
            self.calls.append(event)
            return True

    class _FakeSiemRouter:
        def __init__(self):
            self.splunk   = TestSiemTestEndpointDoesNotCrash._FakeConnector(False)
            self.sentinel = TestSiemTestEndpointDoesNotCrash._FakeConnector(False)
            self.webhook  = TestSiemTestEndpointDoesNotCrash._FakeConnector(True)

    def test_siem_test_webhook_returns_200_not_500(self):
        siem_router = self._FakeSiemRouter()
        status, body = _run(_start_and_post(
            18907, "/api/siem/test/webhook", siem_router=siem_router,
        ))
        assert status == 200, f"expected 200, got {status}: {body}"
        assert body["ok"] is True
        assert body["connector"] == "webhook"
        assert len(siem_router.webhook.calls) == 1
        assert "ts" in siem_router.webhook.calls[0]


class TestDashboardActuallyStarts:
    """Regression guard for the _RateLimiter NameError: start_dashboard()
    must not raise on startup with only its required arguments."""

    def test_start_dashboard_binds_and_serves(self):
        status, body = _run(_start_and_probe(18901))
        assert status == 200
        assert body["status"] == "healthy"

    def test_start_dashboard_with_no_optional_components(self):
        """The minimal call -- no redis_sync, ml_detector, case_manager,
        etc. -- is exactly the configuration that crashed before both
        fixes (dashboard.py's `_RateLimiter` NameError happened
        regardless of these, but this also exercises every `is None`
        guard for the optional components at once)."""
        status, body = _run(_start_and_probe(18902))
        assert status == 200


class TestHealthEndpointHandlesMissingRedis:
    """Regression guard for GET /api/health's redis_sync.connected
    AttributeError when redis_sync is None (Redis disabled, the
    default/common case)."""

    def test_health_ok_with_redis_sync_none(self):
        status, body = _run(_start_and_probe(18903, redis_sync=None))
        assert status == 200
        assert body["checks"]["redis"]["status"] == "disabled"

    def test_health_reports_database_ok(self):
        status, body = _run(_start_and_probe(18904))
        assert body["checks"]["database"]["status"] == "ok"

    def test_health_reports_detector_ok(self):
        status, body = _run(_start_and_probe(18905))
        assert body["checks"]["detector"]["status"] == "ok"

    def test_health_includes_version(self):
        from cnsl import __version__
        status, body = _run(_start_and_probe(18906))
        assert body["version"] == __version__


class TestRateLimiterImportable:
    """Direct regression guard: _RateLimiter must be defined and usable
    from cnsl.dashboard itself (not silently missing, not orphaned in
    an unrelated module with its own missing imports)."""

    def test_rate_limiter_importable_from_dashboard(self):
        from cnsl.dashboard import _RateLimiter
        rl = _RateLimiter(max_calls=2, window_sec=60)
        assert rl.is_limited("key") is False
        assert rl.is_limited("key") is False
        assert rl.is_limited("key") is True  # 3rd call within window

    def test_rate_limiter_not_orphaned_in_dashboard_html(self):
        """dashboard_html.py is HTML/JS string constants only -- the
        rate limiter class doesn't belong there."""
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard_html.py").read_text(encoding="utf-8")
        assert "class _RateLimiter" not in src


class TestEngineStoreOrdering:
    """Regression guard for the UnboundLocalError where
    zero_trust.load_all(store) referenced `store` 16 lines before it
    was created in engine.py's startup sequence."""

    def test_store_created_before_zero_trust_load_all(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        store_idx = src.index("store    = Store(cfg)")
        zt_load_idx = src.index("zero_trust.load_all(store)")
        assert store_idx < zt_load_idx, (
            "zero_trust.load_all(store) appears before `store` is created "
            "in engine.py -- this is the exact ordering bug that crashed "
            "every CNSL startup with UnboundLocalError."
        )

    def test_zero_trust_load_all_runs_alongside_other_store_loads(self):
        """It should run in the same asyncio.gather() as kill_chain_tracker
        and pattern_learner's loads, all of which correctly run after
        store.init()."""
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        gather_start = src.index("await asyncio.gather(\n            kill_chain_tracker.load_all(store)")
        # Closing paren of the gather(...) call itself, not the first
        # nested load_all(store)'s own closing paren.
        gather_end = src.index("        )", gather_start)
        gather_block = src[gather_start:gather_end]
        assert "zero_trust.load_all(store)" in gather_block