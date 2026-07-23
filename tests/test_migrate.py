"""
tests/test_migrate.py -- tests for cnsl/migrate.py (SQLite -> PostgreSQL
data migration). Since a real PostgreSQL server isn't available in CI,
these install a minimal fake `asyncpg` module into sys.modules that
records what would have been executed, instead of connecting anywhere.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import time

import pytest

from cnsl.migrate import migrate


class _FakeConn:
    def __init__(self):
        self.executed: list = []          # plain execute() calls (schema DDL, TRUNCATE)
        self.executemany_calls: list = []  # (sql, batch) pairs

    async def execute(self, sql, *args):
        self.executed.append(sql)

    async def executemany(self, sql, batch):
        self.executemany_calls.append((sql, list(batch)))


class _FakeAcquireCtx:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, conn):
        self._conn = conn

    def acquire(self):
        return _FakeAcquireCtx(self._conn)

    async def close(self):
        pass


class _FakeAsyncpg:
    """Stands in for the `asyncpg` module: exposes create_pool() like the
    real module does, backed by a single fake connection we can inspect."""

    def __init__(self):
        self.conn = _FakeConn()
        self.pool = _FakePool(self.conn)

    async def create_pool(self, dsn, **kwargs):
        return self.pool


@pytest.fixture
def fake_asyncpg():
    fake = _FakeAsyncpg()
    original = sys.modules.get("asyncpg")
    sys.modules["asyncpg"] = fake
    try:
        yield fake
    finally:
        if original is not None:
            sys.modules["asyncpg"] = original
        else:
            del sys.modules["asyncpg"]


@pytest.fixture
def sqlite_db(tmp_path):
    """A small SQLite DB with the incidents/blocks schema and some rows."""
    path = str(tmp_path / "state.db")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, time TEXT,
            src_ip TEXT, severity TEXT, reasons TEXT, fail_count INTEGER,
            uniq_users INTEGER, country TEXT, city TEXT, isp TEXT,
            flag TEXT, kind TEXT DEFAULT 'SSH_FAIL'
        )
    """)
    conn.execute("""
        CREATE TABLE blocks (
            ip TEXT PRIMARY KEY, blocked_at REAL, unblock_at REAL,
            reason TEXT, dry_run INTEGER DEFAULT 1
        )
    """)
    now = time.time()
    conn.execute(
        "INSERT INTO incidents (ts, time, src_ip, severity, reasons, fail_count, "
        "uniq_users, country, city, isp, flag, kind) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (now, "2026-07-21T00:00:00Z", "45.33.32.1", "HIGH", '["brute_force"]',
         5, 2, "US", "Ashburn", "AS-Example", "🇺🇸", "SSH_FAIL"),
    )
    conn.execute(
        "INSERT INTO incidents (ts, time, src_ip, severity, reasons, fail_count, "
        "uniq_users, country, city, isp, flag, kind) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (now, "2026-07-21T00:01:00Z", "91.108.4.88", "MEDIUM", '["scan"]',
         2, 1, "RU", "Moscow", "AS-Other", "🇷🇺", "WEB_SCAN"),
    )
    conn.execute(
        "INSERT INTO blocks (ip, blocked_at, unblock_at, reason, dry_run) VALUES (?,?,?,?,?)",
        ("45.33.32.1", now, now + 3600, "manual:admin", 0),
    )
    conn.commit()
    conn.close()
    return path


def _run(coro):
    return asyncio.run(coro)


class TestMigrateDryRun:
    def test_dry_run_reports_counts_without_writing(self, sqlite_db, fake_asyncpg):
        result = _run(migrate(sqlite_db, "postgresql://x/y", dry_run=True))
        assert result["dry_run"] is True
        assert result["incidents"]["source_count"] == 2
        assert result["blocks"]["source_count"] == 1
        assert result["incidents"]["migrated"] == 0
        assert result["blocks"]["migrated"] == 0
        # Nothing should have touched the (fake) PostgreSQL side.
        assert fake_asyncpg.conn.executemany_calls == []


class TestMigrateWrite:
    def test_migrates_all_rows(self, sqlite_db, fake_asyncpg):
        result = _run(migrate(sqlite_db, "postgresql://x/y", batch_size=1))
        assert result["incidents"]["migrated"] == 2
        assert result["blocks"]["migrated"] == 1

        # incidents: 2 rows, batch_size=1 -> 2 executemany calls of 1 row each
        incident_calls = [c for c in fake_asyncpg.conn.executemany_calls
                           if "INSERT INTO incidents" in c[0]]
        assert sum(len(batch) for _, batch in incident_calls) == 2

        block_calls = [c for c in fake_asyncpg.conn.executemany_calls
                        if "INSERT INTO blocks" in c[0]]
        assert sum(len(batch) for _, batch in block_calls) == 1

    def test_incidents_flag_column_not_migrated(self, sqlite_db, fake_asyncpg):
        _run(migrate(sqlite_db, "postgresql://x/y"))
        incident_calls = [c for c in fake_asyncpg.conn.executemany_calls
                           if "INSERT INTO incidents" in c[0]]
        sql = incident_calls[0][0]
        assert "flag" not in sql

    def test_blocks_dry_run_int_becomes_bool(self, sqlite_db, fake_asyncpg):
        _run(migrate(sqlite_db, "postgresql://x/y"))
        block_calls = [c for c in fake_asyncpg.conn.executemany_calls
                       if "INSERT INTO blocks" in c[0]]
        _, batch = block_calls[0]
        row = batch[0]
        dry_run_value = row[-1]  # dry_run is the last column
        assert isinstance(dry_run_value, bool)
        assert dry_run_value is False  # source had dry_run=0

    def test_blocks_upsert_on_conflict(self, sqlite_db, fake_asyncpg):
        _run(migrate(sqlite_db, "postgresql://x/y"))
        block_calls = [c for c in fake_asyncpg.conn.executemany_calls
                       if "INSERT INTO blocks" in c[0]]
        assert "ON CONFLICT" in block_calls[0][0]

    def test_truncate_target_issues_truncate(self, sqlite_db, fake_asyncpg):
        _run(migrate(sqlite_db, "postgresql://x/y", truncate_target=True))
        assert any("TRUNCATE" in sql for sql in fake_asyncpg.conn.executed)

    def test_no_truncate_by_default(self, sqlite_db, fake_asyncpg):
        _run(migrate(sqlite_db, "postgresql://x/y"))
        assert not any("TRUNCATE" in sql for sql in fake_asyncpg.conn.executed)

    def test_skipped_tables_reported(self, sqlite_db, fake_asyncpg):
        result = _run(migrate(sqlite_db, "postgresql://x/y"))
        assert any("cases" in s for s in result["skipped_tables"])
        assert any("audit_log" in s for s in result["skipped_tables"])


class TestMigrateErrors:
    def test_missing_sqlite_file_raises(self, tmp_path, fake_asyncpg):
        with pytest.raises(FileNotFoundError):
            _run(migrate(str(tmp_path / "nope.db"), "postgresql://x/y"))

    def test_empty_dsn_raises(self, sqlite_db, fake_asyncpg):
        with pytest.raises(ValueError):
            _run(migrate(sqlite_db, ""))

    def test_missing_asyncpg_raises_importerror(self, sqlite_db):
        original = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = None
        try:
            with pytest.raises(ImportError):
                _run(migrate(sqlite_db, "postgresql://x/y"))
        finally:
            if original is not None:
                sys.modules["asyncpg"] = original
            else:
                del sys.modules["asyncpg"]

    def test_dry_run_works_without_asyncpg_installed(self, sqlite_db):
        """A dry run only reports SQLite counts -- it must not require
        asyncpg (e.g. previewing before installing/setting up Postgres)."""
        original = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = None
        try:
            result = _run(migrate(sqlite_db, "postgresql://x/y", dry_run=True))
            assert result["dry_run"] is True
            assert result["incidents"]["source_count"] == 2
        finally:
            if original is not None:
                sys.modules["asyncpg"] = original
            else:
                del sys.modules["asyncpg"]