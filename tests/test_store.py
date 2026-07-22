"""
tests/test_store.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_store.py -v
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


class TestStoreLowCount:
    """store.stats() must count LOW incidents, not hardcode 0."""

    def test_stats_counts_low(self):
        import asyncio, aiosqlite, tempfile, os
        from cnsl.store import Store

        async def _go():
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name
            try:
                store = Store(db_path)
                await store.init()

                async with aiosqlite.connect(db_path) as db:
                    await db.execute(
                        "INSERT INTO incidents "
                        "(src_ip, severity, reasons, fail_count, uniq_users, ts, time) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        ("1.2.3.4", "LOW", '["test"]', 1, 1, time.time(), "2026-01-01T00:00:00Z")
                    )
                    await db.commit()

                stats = await store.stats()
                assert stats.get("low", 0) == 1, f"LOW count was {stats.get('low')} — expected 1"
            finally:
                os.unlink(db_path)

        try:
            asyncio.run(_go())
        except ImportError:
            pytest.skip("aiosqlite not installed")

    def test_stats_all_severities(self):
        import asyncio, tempfile, os
        from cnsl.store import Store

        async def _go():
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                db_path = f.name
            try:
                store = Store(db_path)
                await store.init()

                import aiosqlite
                async with aiosqlite.connect(db_path) as db:
                    for sev in ["HIGH", "MEDIUM", "LOW"]:
                        await db.execute(
                            "INSERT INTO incidents "
                            "(src_ip, severity, reasons, fail_count, uniq_users, ts, time) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            ("1.2.3.4", sev, '["test"]', 1, 1, time.time(), "2026-01-01T00:00:00Z")
                        )
                    await db.commit()

                stats = await store.stats()
                assert stats["high"]   == 1
                assert stats["medium"] == 1
                assert stats["low"]    == 1
                assert stats["total"]  == 3
            finally:
                os.unlink(db_path)

        try:
            asyncio.run(_go())
        except ImportError:
            pytest.skip("aiosqlite not installed")


# v1.0.4 — FIM directory scanning fix

class TestStoreBackendConfig:
    """Store accepts full cfg dict and reads backend + db_path from it."""

    def test_store_accepts_cfg_dict(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "sqlite", "db_path": ":memory:"}})
        assert s._backend == "sqlite"
        assert s.db_path == ":memory:"

    def test_store_accepts_plain_path_string(self):
        from cnsl.store import Store
        s = Store(":memory:")
        assert s._backend == "sqlite"
        assert s.db_path == ":memory:"

    def test_store_postgresql_backend_detected(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "postgresql",
                             "dsn": "postgresql://user:pass@localhost/cnsl"}})
        assert s._backend == "postgresql"
        assert "postgresql" in s._pg_dsn

    def test_store_default_backend_is_sqlite(self):
        from cnsl.store import Store
        s = Store({})
        assert s._backend == "sqlite"

    def test_store_sqlite_init_works(self):
        from cnsl.store import Store
        s = Store(":memory:")
        result = _run(s.init())
        assert result is True
        assert s.available is True
        _run(s.close())

    def test_store_postgresql_graceful_fail_without_asyncpg(self):
        from cnsl.store import Store
        import sys
        # Temporarily hide asyncpg if installed
        asyncpg = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = None
        try:
            s = Store({"store": {"backend": "postgresql",
                                 "dsn": "postgresql://user:pass@localhost/cnsl"}})
            result = _run(s.init())
            # Should return False (asyncpg not available) without crashing
            assert result is False
        finally:
            if asyncpg is not None:
                sys.modules["asyncpg"] = asyncpg
            elif "asyncpg" in sys.modules:
                del sys.modules["asyncpg"]

    def test_store_close_both_backends_no_crash(self):
        from cnsl.store import Store
        s = Store(":memory:")
        _run(s.init())
        _run(s.close())  # must not raise

    def test_init_postgresql_requires_dsn(self):
        from cnsl.store import Store
        s = Store({"store": {"backend": "postgresql", "dsn": ""}})
        result = _run(s.init())
        assert result is False  # no DSN -> fail gracefully


# v3.4.2 -- compliance audit trail

class TestSQLiteWALMode:
    """store.py schema must include WAL and synchronous=NORMAL pragmas."""

    def _schema(self):
        from cnsl.store import _SCHEMA
        return _SCHEMA

    def test_wal_mode_pragma_present(self):
        assert "journal_mode=WAL" in self._schema()

    def test_synchronous_normal_pragma_present(self):
        assert "synchronous=NORMAL" in self._schema()

    def test_severity_index_present(self):
        assert "idx_incidents_sev" in self._schema()

    def test_ip_index_present(self):
        assert "idx_incidents_ip" in self._schema()

    def test_ts_index_present(self):
        assert "idx_incidents_ts" in self._schema()
