"""
cnsl/audit.py — Compliance audit trail.

Tracks who did what, when: manual blocks/unblocks, secret rotation,
case status changes, and other administrative actions. Separate from
the noisy detection-event JSONL log (cnsl/logger.py) so it can be
queried and retained on its own for SOC2/ISO27001-style audits.

Design:
  - Append-only: entries are never edited or deleted via the API.
  - SQLite-backed via the shared Store connection (same convention as
    CaseManager, UEBA, KillChainTracker, PatternLearner).
  - Every entry has: actor, action, target, details (JSON), source IP,
    timestamp.

Usage:
    audit = AuditLog(store)
    await audit.init()
    await audit.record(actor="admin", action="block", target="45.33.32.1",
                        details={"reason": "manual"}, source_ip="10.0.0.5")
    rows = await audit.list(actor="admin", limit=50)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .models import iso_time

_AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    time        TEXT    NOT NULL,
    actor       TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    target      TEXT,
    details     TEXT    DEFAULT '{}',   -- JSON object
    source_ip   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
"""


class AuditLog:
    """
    Async audit-trail layer, sharing the Store's aiosqlite connection.
    """

    def __init__(self, store: Any):
        self._store = store

    @property
    def _db(self):
        return self._store._db

    @property
    def available(self) -> bool:
        return self._store.available

    async def init(self) -> None:
        """Run audit_log schema migration. Safe to call on an existing DB."""
        if not self.available or self._db is None:
            return
        await self._db.executescript(_AUDIT_SCHEMA)
        await self._db.commit()

    async def record(
        self,
        actor: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        source_ip: Optional[str] = None,
    ) -> Optional[int]:
        """
        Append an audit entry. Returns the new row id, or None if the
        store is unavailable (never raises — auditing must not break
        the action it's recording).
        """
        if not self.available or self._db is None:
            return None
        try:
            cur = await self._db.execute(
                """INSERT INTO audit_log (ts, time, actor, action, target, details, source_ip)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    time.time(), iso_time(),
                    actor, action, target,
                    json.dumps(details or {}),
                    source_ip,
                ),
            )
            await self._db.commit()
            return cur.lastrowid
        except Exception:
            # Swallow rather than raise -- see docstring: whatever action
            # triggered this (e.g. a manual block) must still succeed
            # even if the audit write itself fails.
            return None

    async def list(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        target: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return audit entries newest-first, optionally filtered."""
        if not self.available or self._db is None:
            return []
        limit = max(1, min(limit, 1000))  # clamp caller-supplied limit so the API can't force a huge scan

        clauses, params = [], []
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if target:
            clauses.append("target = ?")
            params.append(target)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])

        async with self._db.execute(
            f"""SELECT id, ts, time, actor, action, target, details, source_ip
                FROM audit_log {where}
                ORDER BY ts DESC LIMIT ? OFFSET ?""",
            params,
        ) as cur:
            rows = await cur.fetchall()

        out = []
        for r in rows:
            d = dict(r)
            try:
                d["details"] = json.loads(d.get("details") or "{}")
            except (TypeError, ValueError):
                d["details"] = {}
            out.append(d)
        return out

    async def count(
        self,
        actor: Optional[str] = None,
        action: Optional[str] = None,
    ) -> int:
        if not self.available or self._db is None:
            return 0
        clauses, params = [], []
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if action:
            clauses.append("action = ?")
            params.append(action)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        async with self._db.execute(
            f"SELECT COUNT(*) AS n FROM audit_log {where}", params
        ) as cur:
            row = await cur.fetchone()
        return int(row["n"]) if row else 0