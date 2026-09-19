"""
cnsl/retention.py -- time-based data retention for CNSL's persistent
store (cnsl/store.py) and audit log (cnsl/audit.py).

Problem: cnsl/store.py's `incidents` table (and, if audit logging is
enabled, cnsl/audit.py's `audit_log` table) accumulate rows forever --
neither module ever deletes a row on its own. On a long-running
deployment that means unbounded disk growth and, eventually, degraded
query performance on tables with no natural cap.

Scope: purges/archives `incidents` and, opt-in, `audit_log`. Does NOT
touch:
  - `cases` (cnsl/cases.py) -- an open investigation's age isn't a
    signal that it's safe to delete, and a case's own fields
    (severity, reasons, src_ip, ...) are stored denormalized rather
    than looked up from `incidents` at read time, so a case is
    unaffected by the incident it originated from being purged.
  - `blocks` (cnsl/store.py) -- already self-cleans when an IP is
    unblocked (see cnsl/blocker.py); never accumulates stale rows.
  - Kill chains, UEBA profiles, pattern-learner suggestions -- each
    already has its own size-based cap (kill_chain.max_chains,
    pattern_learning.max_suggestions, ...), a different (and already
    solved) problem from unbounded *time* growth.

Compliance note: if compliance reporting (cnsl/compliance.py --
SOC2/ISO27001/PCI-DSS) is in use, audit_log retention should meet or
exceed whatever your framework's minimum retention requirement is.
This module defaults audit_log_max_age_days to 0 (never purge)
specifically so turning on incident retention doesn't silently start
deleting audit records too -- audit log purging is a deliberate
separate opt-in.

Archival: before deleting, purged rows can optionally be exported to
a gzip-compressed JSONL file (one JSON object per line) under
archive_dir, named "<table>_<cutoff-date>_<row-count>.jsonl.gz". This
is a flat-file export for cold storage, not a restorable CNSL backup
-- see cnsl/backup.py for that.

Config:
  "retention": {
    "enabled":                 true,
    "run_interval_hours":      24,
    "incidents_max_age_days":  90,
    "audit_log_max_age_days":  0,
    "archive_before_delete":   true,
    "archive_dir":             "/var/lib/cnsl/archives"
  }
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import time
from typing import Any, Dict, List, Optional


class RetentionPolicy:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        r = cfg.get("retention", {}) or {}
        self.enabled                = bool(r.get("enabled", False))
        self.run_interval_hours     = int(r.get("run_interval_hours", 24))
        self.incidents_max_age_days = int(r.get("incidents_max_age_days", 90))
        self.audit_log_max_age_days = int(r.get("audit_log_max_age_days", 0))
        self.archive_before_delete  = bool(r.get("archive_before_delete", True))
        self.archive_dir            = r.get("archive_dir", "")

        self.last_run_at: Optional[float] = None
        self.last_result: Dict[str, Any] = {}

    def _cutoff(self, max_age_days: int) -> float:
        return time.time() - (max_age_days * 86400)

    def _archive_path(self, table: str, cutoff_ts: float, row_count: int) -> str:
        date_str = time.strftime("%Y%m%d", time.gmtime(cutoff_ts))
        os.makedirs(self.archive_dir, exist_ok=True)
        return os.path.join(self.archive_dir, f"{table}_{date_str}_{row_count}.jsonl.gz")

    def _archive_rows(self, table: str, rows: List[Dict[str, Any]], cutoff_ts: float) -> Optional[str]:
        if not rows:
            return None
        path = self._archive_path(table, cutoff_ts, len(rows))
        with gzip.open(path, "wt", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, default=str) + "\n")
        return path

    async def _purge_table(
        self, store: Any, table: str, ts_column: str, max_age_days: int,
    ) -> Dict[str, Any]:
        """
        Fetch and (optionally) archive rows older than the cutoff, then
        delete them. `cutoff_ts` is a value this module computes itself
        (never user input), so it's safe to interpolate directly into
        the SQL rather than route it through Store's generic
        db_execute/db_fetchall parameter binding -- which, for the
        PostgreSQL path, expects $-style placeholders that a plain "?"
        query wouldn't get, a pre-existing quirk of those generic
        helpers this sidesteps rather than depends on.
        """
        if max_age_days <= 0:
            return {"purged": 0, "archived_to": None, "skipped": "max_age_days <= 0 (disabled)"}

        cutoff_ts = self._cutoff(max_age_days)
        cutoff_literal = repr(float(cutoff_ts))

        rows: List[Dict[str, Any]] = []
        if self.archive_before_delete:
            rows = await store.db_fetchall(
                f"SELECT * FROM {table} WHERE {ts_column} < {cutoff_literal} ORDER BY {ts_column} ASC"
            )

        archived_to = None
        if self.archive_before_delete and rows:
            archived_to = self._archive_rows(table, rows, cutoff_ts)

        # Count rows to delete even when not archiving, so the caller
        # always gets an accurate purge count.
        if rows:
            purge_count = len(rows)
        else:
            count_result = await store.db_fetchall(
                f"SELECT COUNT(*) AS c FROM {table} WHERE {ts_column} < {cutoff_literal}"
            )
            purge_count = count_result[0]["c"] if count_result else 0

        if purge_count:
            await store.db_execute(f"DELETE FROM {table} WHERE {ts_column} < {cutoff_literal}")

        return {"purged": purge_count, "archived_to": archived_to}

    async def run_once(self, store: Any, audit_log: Any = None, logger: Any = None) -> Dict[str, Any]:
        """
        Run one retention pass. `store` must be available (Store.available()
        True) or this is a no-op. `audit_log` is optional -- pass the
        AuditLog instance (which shares Store's connection) to also
        consider audit_log_max_age_days.
        """
        if not self.enabled or store is None or not getattr(store, "available", False):
            result = {"ran": False, "reason": "retention disabled or store unavailable"}
            self.last_result = result
            return result

        result: Dict[str, Any] = {"ran": True, "started_at": time.time()}
        result["incidents"] = await self._purge_table(store, "incidents", "ts", self.incidents_max_age_days)

        if audit_log is not None and self.audit_log_max_age_days > 0:
            result["audit_log"] = await self._purge_table(store, "audit_log", "ts", self.audit_log_max_age_days)
        else:
            result["audit_log"] = {"purged": 0, "archived_to": None, "skipped": "not configured"}

        result["finished_at"] = time.time()
        self.last_run_at = result["finished_at"]
        self.last_result = result

        if logger is not None:
            await logger.log("retention_run", {
                "incidents_purged":  result["incidents"]["purged"],
                "incidents_archived_to": result["incidents"]["archived_to"],
                "audit_log_purged": result["audit_log"]["purged"],
                "audit_log_archived_to": result["audit_log"].get("archived_to"),
            })
        return result

    async def run_loop(self, store: Any, audit_log: Any, logger: Any) -> None:
        """Background task: run a retention pass on run_interval_hours, forever."""
        if not self.enabled:
            return
        while True:
            await asyncio.sleep(self.run_interval_hours * 3600)
            await self.run_once(store, audit_log, logger)

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":                self.enabled,
            "run_interval_hours":     self.run_interval_hours,
            "incidents_max_age_days": self.incidents_max_age_days,
            "audit_log_max_age_days": self.audit_log_max_age_days,
            "archive_before_delete":  self.archive_before_delete,
            "archive_dir":            self.archive_dir,
            "last_run_at":            self.last_run_at,
            "last_result":            self.last_result,
        }