"""
cnsl/migrate.py — SQLite -> PostgreSQL data migration.

Copies existing data out of a SQLite-backed CNSL store into a
PostgreSQL database, creating the same schema Store._init_postgresql()
would (see cnsl.store._PG_SCHEMA). Run this once when switching
store.backend from "sqlite" to "postgresql" in config.json -- CNSL
itself doesn't migrate data automatically on backend switch.

Scope: `incidents` and `blocks` -- the only two tables the PostgreSQL
backend currently has a schema for. Cases, UEBA, kill-chain,
pattern-learner, zero-trust, and audit-log data live in SQLite-only
tables (Store's Postgres path has no schema for them yet), so they
are NOT migrated. This is called out in the CLI output rather than
silently dropped.

Default behavior is additive (safe to run against a fresh PostgreSQL
DB, or to resume an interrupted migration for `blocks`, which upserts
on its primary key). Re-running against `incidents` a second time will
duplicate rows, since SQLite's row ids don't carry over as a unique
constraint on the PostgreSQL side -- pass truncate_target=True for a
clean one-shot copy instead of appending.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from .store import _PG_SCHEMA


async def migrate(
    sqlite_path: str,
    pg_dsn: str,
    batch_size: int = 500,
    dry_run: bool = False,
    truncate_target: bool = False,
) -> Dict[str, Any]:
    """
    Migrate `incidents` and `blocks` from a SQLite DB file to a
    PostgreSQL database.

    Returns a summary dict:
      {
        "dry_run": bool,
        "incidents": {"source_count": int, "migrated": int},
        "blocks":    {"source_count": int, "migrated": int},
        "skipped_tables": [...],  # subsystems not covered by the PG schema
      }

    Raises FileNotFoundError if sqlite_path doesn't exist, ImportError
    if asyncpg isn't installed, and ValueError if pg_dsn is empty.
    """
    if not sqlite_path or not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"SQLite DB not found: {sqlite_path}")
    if not pg_dsn:
        raise ValueError("PostgreSQL DSN is required")

    try:
        import aiosqlite
    except ImportError as e:
        raise ImportError("aiosqlite is required to read the source SQLite DB "
                           "(pip install aiosqlite)") from e

    summary: Dict[str, Any] = {
        "dry_run": dry_run,
        "incidents": {"source_count": 0, "migrated": 0},
        "blocks": {"source_count": 0, "migrated": 0},
        "skipped_tables": [
            "cases (no PostgreSQL schema yet)",
            "ueba_profiles (no PostgreSQL schema yet)",
            "kill_chain (no PostgreSQL schema yet)",
            "pattern_learner (no PostgreSQL schema yet)",
            "zero_trust (no PostgreSQL schema yet)",
            "audit_log (no PostgreSQL schema yet)",
        ],
    }

    src = await aiosqlite.connect(sqlite_path)
    src.row_factory = aiosqlite.Row
    try:
        async with src.execute("SELECT COUNT(*) AS n FROM incidents") as cur:
            row = await cur.fetchone()
            summary["incidents"]["source_count"] = int(row["n"]) if row else 0

        async with src.execute("SELECT COUNT(*) AS n FROM blocks") as cur:
            row = await cur.fetchone()
            summary["blocks"]["source_count"] = int(row["n"]) if row else 0

        if dry_run:
            return summary

        # Only needed once we're actually about to write to PostgreSQL --
        # a dry run should work even without asyncpg installed.
        try:
            import asyncpg  # type: ignore
        except ImportError as e:
            raise ImportError("asyncpg is required to write to PostgreSQL "
                               "(pip install asyncpg)") from e

        pg = await asyncpg.create_pool(pg_dsn, min_size=1, max_size=5, command_timeout=60)
        try:
            async with pg.acquire() as conn:
                await conn.execute(_PG_SCHEMA)

                if truncate_target:
                    await conn.execute("TRUNCATE TABLE incidents RESTART IDENTITY")
                    await conn.execute("TRUNCATE TABLE blocks")

                summary["incidents"]["migrated"] = await _migrate_incidents(
                    src, conn, batch_size
                )
                summary["blocks"]["migrated"] = await _migrate_blocks(
                    src, conn, batch_size
                )
        finally:
            await pg.close()
    finally:
        await src.close()

    return summary


async def _migrate_incidents(src, pg_conn, batch_size: int) -> int:
    """Copy all rows from SQLite `incidents` into PostgreSQL `incidents`.

    SQLite's `flag` column has no PostgreSQL counterpart (dropped by
    design -- see _PG_SCHEMA) and is intentionally not migrated.
    """
    migrated = 0
    cols = ("ts", "time", "src_ip", "severity", "reasons",
            "fail_count", "uniq_users", "country", "city", "isp", "kind")
    col_list = ", ".join(cols)
    placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))
    insert_sql = f"INSERT INTO incidents ({col_list}) VALUES ({placeholders})"

    async with src.execute(
        f"SELECT {col_list} FROM incidents ORDER BY id"
    ) as cur:
        while True:
            rows = await cur.fetchmany(batch_size)
            if not rows:
                break
            batch = [tuple(row[c] for c in cols) for row in rows]
            await pg_conn.executemany(insert_sql, batch)
            migrated += len(batch)

    return migrated


async def _migrate_blocks(src, pg_conn, batch_size: int) -> int:
    """Copy all rows from SQLite `blocks` into PostgreSQL `blocks`,
    upserting on the `ip` primary key so a re-run is safe."""
    migrated = 0
    cols = ("ip", "blocked_at", "unblock_at", "reason", "dry_run")
    col_list = ", ".join(cols)
    placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))
    insert_sql = (
        f"INSERT INTO blocks ({col_list}) VALUES ({placeholders}) "
        f"ON CONFLICT (ip) DO UPDATE SET "
        f"blocked_at = EXCLUDED.blocked_at, unblock_at = EXCLUDED.unblock_at, "
        f"reason = EXCLUDED.reason, dry_run = EXCLUDED.dry_run"
    )

    async with src.execute(f"SELECT {col_list} FROM blocks") as cur:
        while True:
            rows = await cur.fetchmany(batch_size)
            if not rows:
                break
            batch = []
            for row in rows:
                values = list(row[c] for c in cols)
                # SQLite stores dry_run as 0/1 INTEGER; PG column is BOOLEAN.
                dry_run_idx = cols.index("dry_run")
                values[dry_run_idx] = bool(values[dry_run_idx])
                batch.append(tuple(values))
            await pg_conn.executemany(insert_sql, batch)
            migrated += len(batch)

    return migrated