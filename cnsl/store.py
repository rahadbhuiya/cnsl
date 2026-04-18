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



# Schema


_SCHEMA = """
PRAGMA journal_mode=WAL;

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
    flag        TEXT
);

CREATE TABLE IF NOT EXISTS blocks (
    ip          TEXT    PRIMARY KEY,
    blocked_at  REAL    NOT NULL,
    unblock_at  REAL    NOT NULL,
    reason      TEXT,
    dry_run     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(ts);
"""



# Store


class Store:
    """
    Async SQLite store.

    Usage:
        store = Store("./cnsl_state.db")
        await store.init()
        await store.save_incident(detection, geo={...})
        rows = await store.recent_incidents(limit=50)
        await store.close()
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db = None
        self._available = False

    async def init(self) -> bool:
        """Initialize the database. Returns False if aiosqlite is not installed."""
        try:
            import aiosqlite  # type: ignore
            self._db = await aiosqlite.connect(self.db_path)
            self._db.row_factory = aiosqlite.Row
            await self._db.executescript(_SCHEMA)
            await self._db.commit()
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
        await self._db.execute(
            """INSERT INTO incidents
               (ts, time, src_ip, severity, reasons,
                fail_count, uniq_users, country, city, isp, flag)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(), iso_time(),
                d.src_ip, d.severity,
                json.dumps(d.reasons),
                d.fail_count, d.uniq_users,
                geo.get("country"), geo.get("city"),
                geo.get("isp"),    geo.get("flag"),
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

    async def stats(self) -> Dict[str, Any]:
        if not self._available or self._db is None:
            return {}
        async with self._db.execute(
            """SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN severity='HIGH'   THEN 1 ELSE 0 END) as high,
                 SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium,
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

    async def close(self) -> None:
        if self._db:
            await self._db.close()