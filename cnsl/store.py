"""
cnsl/store.py — SQLite-backed persistent state.

Stores:
  - incidents (full history, survives restarts)
  - active blocks (so blocks survive a restart)
  - blocked_ips view for the dashboard

Uses aiosqlite for non-blocking async access.
Falls back to in-memory if aiosqlite is not installed.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .models import Detection, iso_time
from .cases         import _CASE_SCHEMA
from .ueba          import UEBA_SCHEMA
from .kill_chain    import KC_SCHEMA
from .pattern_learner import PL_SCHEMA
from .zero_trust    import ZT_SCHEMA



# Schema


_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-8000;

CREATE TABLE IF NOT EXISTS incidents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    time        TEXT    NOT NULL,
    src_ip      TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    reasons     TEXT    NOT NULL,   -- JSON array
    fail_count  INTEGER NOT NULL,
    uniq_users  INTEGER NOT NULL,
    country     TEXT,
    city        TEXT,
    isp         TEXT,
    flag        TEXT,
    kind        TEXT    DEFAULT 'SSH_FAIL'
);

CREATE TABLE IF NOT EXISTS blocks (
    ip          TEXT    PRIMARY KEY,
    blocked_at  REAL    NOT NULL,
    unblock_at  REAL    NOT NULL,
    reason      TEXT,
    dry_run     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_incidents_ip  ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_ts  ON incidents(ts);
CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);
"""



# Store


class Store:
    """
    Async persistence store. Supports SQLite (default) and PostgreSQL.

    Backend selection via config:
      SQLite (default):
        "store": {"db_path": "/var/lib/cnsl/cnsl_state.db"}

      PostgreSQL (optional, requires asyncpg):
        "store": {"backend": "postgresql",
                  "dsn": "postgresql://user:pass@host:5432/cnsl"}

    Usage:
        store = Store(cfg)           # or Store("./path.db") for backward compat
        await store.init()
        await store.save_incident(detection, geo={...})
        rows = await store.recent_incidents(limit=50)
        await store.close()
    """

    def __init__(self, cfg_or_path):
        # Accept either a config dict or a plain path string (backward compat)
        if isinstance(cfg_or_path, dict):
            store_cfg = cfg_or_path.get("store", {})
            self.db_path  = store_cfg.get("db_path", "./cnsl_state.db")
            self._backend = store_cfg.get("backend", "sqlite").lower()
            self._pg_dsn  = store_cfg.get("dsn", "")
        else:
            self.db_path  = cfg_or_path
            self._backend = "sqlite"
            self._pg_dsn  = ""

        self._db        = None   # SQLite connection
        self._pg        = None   # PostgreSQL connection pool
        self._available = False

    async def init(self) -> bool:
        """
        Initialize the database backend.
        Returns True on success, False if required driver is not installed.
        """
        if self._backend == "postgresql":
            return await self._init_postgresql()
        return await self._init_sqlite()

    async def _init_sqlite(self) -> bool:
        """Initialize SQLite backend (default)."""
        try:
            import aiosqlite  # type: ignore
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
            await self._db.executescript(_SCHEMA)
            await self._db.executescript(_CASE_SCHEMA)
            await self._db.executescript(UEBA_SCHEMA)
            await self._db.executescript(KC_SCHEMA)
            await self._db.executescript(PL_SCHEMA)
            await self._db.executescript(ZT_SCHEMA)
            await self._db.commit()
            # Migration: add 'kind' column to existing DBs that don't have it
            try:
                await self._db.execute(
                    "ALTER TABLE incidents ADD COLUMN kind TEXT DEFAULT 'SSH_FAIL'"
                )
                await self._db.commit()
            except Exception:
                pass  # Column already exists -- normal on new installs
            self._available = True
            return True
        except ImportError:
            return False
        except Exception:
            return False

    async def _init_postgresql(self) -> bool:
        """
        Initialize PostgreSQL backend using asyncpg.

        Schema notes:
          - SQLite AUTOINCREMENT -> PostgreSQL SERIAL
          - SQLite INTEGER -> PostgreSQL INTEGER / BIGINT
          - SQLite TEXT -> PostgreSQL TEXT
          - PRAGMA statements are silently skipped (not applicable to PG)
          - asyncpg uses $1/$2 placeholders instead of SQLite ? or :name
        """
        if not self._pg_dsn:
            return False
        try:
            import asyncpg  # type: ignore
            self._pg = await asyncpg.create_pool(
                self._pg_dsn,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
            async with self._pg.acquire() as conn:
                # Create tables -- PostgreSQL-compatible schema
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS incidents (
                        id          SERIAL PRIMARY KEY,
                        ts          DOUBLE PRECISION NOT NULL,
                        time        TEXT NOT NULL,
                        src_ip      TEXT NOT NULL,
                        severity    TEXT NOT NULL,
                        reasons     TEXT NOT NULL,
                        fail_count  INTEGER NOT NULL,
                        uniq_users  INTEGER NOT NULL,
                        country     TEXT,
                        city        TEXT,
                        isp         TEXT,
                        kind        TEXT DEFAULT 'SSH_FAIL'
                    );
                    CREATE INDEX IF NOT EXISTS idx_incidents_ip  ON incidents(src_ip);
                    CREATE INDEX IF NOT EXISTS idx_incidents_ts  ON incidents(ts DESC);
                    CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);

                    CREATE TABLE IF NOT EXISTS blocks (
                        ip          TEXT PRIMARY KEY,
                        blocked_at  DOUBLE PRECISION,
                        unblock_at  DOUBLE PRECISION,
                        reason      TEXT,
                        dry_run     BOOLEAN
                    );
                """)
            self._available = True
            return True
        except ImportError:
            return False
        except Exception:
            return False

    @property
    def available(self) -> bool:
        return self._available

    #  Incidents 

    async def save_incident(
        self,
        d: Detection,
        geo: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self._available or self._db is None:
            return
        geo = geo or {}
        # Infer kind from reasons — credential_breach means SSH_SUCCESS (success after fails)
        kind = "SSH_FAIL"
        reasons_str = " ".join(d.reasons).lower()
        if "credential_breach" in reasons_str:
            kind = "SSH_SUCCESS"
        elif "web_exploit" in reasons_str or "web exploit" in reasons_str:
            kind = "WEB_EXPLOIT_ATTEMPT"
        elif "web_scan" in reasons_str or "web scan" in reasons_str:
            kind = "WEB_SCAN"
        elif "db_auth" in reasons_str or "database" in reasons_str:
            kind = "DB_AUTH_FAIL"
        elif "honeypot" in reasons_str:
            kind = "FW_HONEYPOT_PORT"
        elif "firewall" in reasons_str or "fw_block" in reasons_str:
            kind = "FW_BLOCK"
        elif "sudo" in reasons_str or "privilege" in reasons_str:
            kind = "SUDO_FAIL"

        await self._db.execute(
            """INSERT INTO incidents
               (ts, time, src_ip, severity, reasons,
                fail_count, uniq_users, country, city, isp, flag, kind)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(), iso_time(),
                d.src_ip, d.severity,
                json.dumps(d.reasons),
                d.fail_count, d.uniq_users,
                geo.get("country"), geo.get("city"),
                geo.get("isp"),    geo.get("flag"),
                kind,
            ),
        )
        await self._db.commit()

    async def recent_incidents(self, limit: int = 100) -> List[Dict]:
        if not self._available or self._db is None:
            return []
        async with self._db.execute(
            "SELECT * FROM incidents ORDER BY ts DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["reasons"] = json.loads(d["reasons"])
            result.append(d)
        return result

    async def top_attackers(self, limit: int = 20) -> List[Dict]:
        if not self._available or self._db is None:
            return []
        async with self._db.execute(
            """SELECT src_ip, flag, country, city, isp,
                      COUNT(*) as incident_count,
                      MAX(severity) as max_severity,
                      MAX(ts) as last_seen
               FROM incidents
               GROUP BY src_ip
               ORDER BY incident_count DESC
               LIMIT ?""",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def timeline_24h(self) -> List[Dict]:
        """Return incident counts per hour for the last 24 hours, grouped by severity."""
        if not self._available or self._db is None:
            return []
        cutoff = time.time() - 86400
        async with self._db.execute(
            """SELECT
                 CAST((ts - ?) / 3600 AS INTEGER) as hour_offset,
                 severity,
                 COUNT(*) as count
               FROM incidents
               WHERE ts >= ?
               GROUP BY hour_offset, severity
               ORDER BY hour_offset""",
            (cutoff, cutoff),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def stats(self) -> Dict[str, Any]:
        if not self._available or self._db is None:
            return {}
        async with self._db.execute(
            """SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN severity='HIGH'   THEN 1 ELSE 0 END) as high,
                 SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium,
                 SUM(CASE WHEN severity='LOW'    THEN 1 ELSE 0 END) as low,
                 COUNT(DISTINCT src_ip) as unique_ips
               FROM incidents"""
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else {}

    # Blocks 

    async def save_block(self, ip: str, unblock_at: float, reason: str, dry_run: bool) -> None:
        if not self._available or self._db is None:
            return
        await self._db.execute(
            """INSERT OR REPLACE INTO blocks
               (ip, blocked_at, unblock_at, reason, dry_run)
               VALUES (?,?,?,?,?)""",
            (ip, time.time(), unblock_at, reason, int(dry_run)),
        )
        await self._db.commit()

    async def remove_block(self, ip: str) -> None:
        if not self._available or self._db is None:
            return
        await self._db.execute("DELETE FROM blocks WHERE ip=?", (ip,))
        await self._db.commit()

    async def active_blocks(self) -> List[Dict]:
        if not self._available or self._db is None:
            return []
        async with self._db.execute(
            "SELECT * FROM blocks WHERE unblock_at > ? ORDER BY blocked_at DESC",
            (time.time(),),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    # Generic helpers (used by kill_chain, etc.)

    async def db_execute(self, sql: str, params: Any = None) -> None:
        """Execute a write query (INSERT/UPDATE/DELETE)."""
        if not self._available:
            return
        if self._pg is not None:
            # asyncpg uses $1/$2 placeholders; convert SQLite :name or ? style
            async with self._pg.acquire() as conn:
                if params is None:
                    await conn.execute(sql)
                elif isinstance(params, dict):
                    # Convert named params to positional for asyncpg
                    import re
                    keys = list(params.keys())
                    positional = [params[k] for k in keys]
                    for i, k in enumerate(keys, 1):
                        sql = sql.replace(f":{k}", f"${i}")
                    await conn.execute(sql, *positional)
                else:
                    await conn.execute(sql, *params)
            return
        # SQLite path
        if self._db is None:
            return
        if params is None:
            await self._db.execute(sql)
        else:
            await self._db.execute(sql, params)
        await self._db.commit()

    async def db_fetchall(self, sql: str, params: Any = None) -> List[Dict]:
        """Execute a read query and return all rows as dicts."""
        if not self._available:
            return []
        if self._pg is not None:
            async with self._pg.acquire() as conn:
                if params is None:
                    rows = await conn.fetch(sql)
                else:
                    rows = await conn.fetch(sql, *params)
            return [dict(r) for r in rows]
        # SQLite path
        if self._db is None:
            return []
        if params is None:
            async with self._db.execute(sql) as cur:
                rows = await cur.fetchall()
        else:
            async with self._db.execute(sql, params) as cur:
                rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def close(self) -> None:
        if self._pg is not None:
            await self._pg.close()
            self._pg = None
        if self._db is not None:
            await self._db.close()
            self._db = None