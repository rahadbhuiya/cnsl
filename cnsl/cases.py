"""
cnsl/cases.py — Incident Case Management.

Tracks security incidents as actionable cases with status, assignment,
and timestamped analyst notes.

Case lifecycle:
  open  →  investigating  →  closed
                         →  false_positive

Features:
  - Auto-create case from HIGH severity incident
  - Manual case creation from any incident
  - Assign to analyst
  - Add timestamped notes
  - Status transitions with audit trail
  - SQLite-backed via the shared Store connection

Schema (added to store.py via migration):
  cases      — one row per case
  case_notes — timestamped analyst notes (append-only)

RBAC:
  viewer          — read cases, read notes
  analyst+        — create, update status, assign, add notes
  admin           — delete cases (rarely needed)
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .models import Detection, iso_time

# Valid statuses and allowed transitions
VALID_STATUSES = {"open", "investigating", "closed", "false_positive"}

# Statuses that are considered resolved
RESOLVED_STATUSES = {"closed", "false_positive"}

# Auto-create cases for these severities
AUTO_CREATE_SEVERITIES = {"HIGH"}

_CASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER,                    -- FK to incidents.id (nullable)
    title           TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'open',
    severity        TEXT    NOT NULL DEFAULT 'HIGH',
    src_ip          TEXT,
    assigned_to     TEXT,                       -- username or null
    created_at      REAL    NOT NULL,
    updated_at      REAL    NOT NULL,
    created_by      TEXT    DEFAULT 'system',
    country         TEXT,
    isp             TEXT,
    reasons         TEXT    DEFAULT '[]'        -- JSON array
);

CREATE TABLE IF NOT EXISTS case_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    author      TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    ts          REAL    NOT NULL,
    time        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_status   ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_ip       ON cases(src_ip);
CREATE INDEX IF NOT EXISTS idx_cases_updated  ON cases(updated_at);
CREATE INDEX IF NOT EXISTS idx_notes_case_id  ON case_notes(case_id);
"""


class CaseManager:
    """
    Async case management layer.

    Requires the Store to have been initialised first (share the same
    aiosqlite connection via store._db).

    Usage:
        cases = CaseManager(store)
        await cases.init()
        case_id = await cases.create_from_incident(detection, geo, incident_id=42)
        await cases.add_note(case_id, author="admin", body="Confirmed attacker")
        await cases.update_status(case_id, "investigating", actor="admin")
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
        """Run case schema migrations. Safe to call on existing DB."""
        if not self.available or self._db is None:
            return
        await self._db.executescript(_CASE_SCHEMA)
        await self._db.commit()

    #  Create 

    async def create_from_incident(
        self,
        detection: Detection,
        geo: Optional[Dict] = None,
        incident_id: Optional[int] = None,
        created_by: str = "system",
    ) -> Optional[int]:
        """
        Auto-create a case from a Detection.
        Returns the new case id, or None if store unavailable.
        """
        if not self.available or self._db is None:
            return None
        geo = geo or {}
        title = _auto_title(detection)
        now   = time.time()
        cur = await self._db.execute(
            """INSERT INTO cases
               (incident_id, title, status, severity, src_ip,
                assigned_to, created_at, updated_at, created_by,
                country, isp, reasons)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                incident_id,
                title,
                "open",
                detection.severity,
                detection.src_ip,
                None,
                now, now,
                created_by,
                geo.get("country"),
                geo.get("isp"),
                json.dumps(detection.reasons),
            ),
        )
        await self._db.commit()
        return cur.lastrowid

    async def create_manual(
        self,
        title: str,
        severity: str,
        src_ip: str = "",
        assigned_to: Optional[str] = None,
        created_by: str = "system",
        incident_id: Optional[int] = None,
        reasons: Optional[List[str]] = None,
        country: str = "",
        isp: str = "",
    ) -> Optional[int]:
        """Manually create a case (from dashboard)."""
        if not self.available or self._db is None:
            return None
        if severity not in {"LOW", "MEDIUM", "HIGH"}:
            severity = "MEDIUM"
        now = time.time()
        cur = await self._db.execute(
            """INSERT INTO cases
               (incident_id, title, status, severity, src_ip,
                assigned_to, created_at, updated_at, created_by,
                country, isp, reasons)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                incident_id, title, "open", severity, src_ip,
                assigned_to, now, now, created_by,
                country, isp, json.dumps(reasons or []),
            ),
        )
        await self._db.commit()
        return cur.lastrowid

    #  Read 

    async def get(self, case_id: int) -> Optional[Dict]:
        """Fetch a single case with its notes."""
        if not self.available or self._db is None:
            return None
        async with self._db.execute(
            "SELECT * FROM cases WHERE id=?", (case_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        case = _row_to_case(dict(row))
        case["notes"] = await self._get_notes(case_id)
        return case

    async def list_cases(
        self,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict]:
        """List cases with optional filters."""
        if not self.available or self._db is None:
            return []
        where, params = _build_filter(status, assigned_to, severity)
        params += [limit, offset]
        async with self._db.execute(
            f"SELECT * FROM cases {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params,
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_case(dict(r)) for r in rows]

    async def count(
        self,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> int:
        """Count cases matching optional filters."""
        if not self.available or self._db is None:
            return 0
        where, params = _build_filter(status, assigned_to, severity)
        async with self._db.execute(
            f"SELECT COUNT(*) FROM cases {where}", params
        ) as cur:
            row = await cur.fetchone()
        return row[0] if row else 0

    async def stats(self) -> Dict[str, Any]:
        """Return case counts by status and severity."""
        if not self.available or self._db is None:
            return {}
        async with self._db.execute(
            """SELECT
                 COUNT(*) as total,
                 SUM(CASE WHEN status='open'             THEN 1 ELSE 0 END) as open,
                 SUM(CASE WHEN status='investigating'    THEN 1 ELSE 0 END) as investigating,
                 SUM(CASE WHEN status='closed'           THEN 1 ELSE 0 END) as closed,
                 SUM(CASE WHEN status='false_positive'   THEN 1 ELSE 0 END) as false_positive,
                 SUM(CASE WHEN severity='HIGH'           THEN 1 ELSE 0 END) as high,
                 SUM(CASE WHEN severity='MEDIUM'         THEN 1 ELSE 0 END) as medium,
                 SUM(CASE WHEN severity='LOW'            THEN 1 ELSE 0 END) as low
               FROM cases"""
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else {}

    #  Update 

    async def update_status(
        self,
        case_id: int,
        new_status: str,
        actor: str = "system",
    ) -> Optional[str]:
        """
        Update case status. Returns None on success, error string on failure.
        Also appends a system note recording the transition.
        """
        if new_status not in VALID_STATUSES:
            return f"Invalid status '{new_status}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}"
        if not self.available or self._db is None:
            return "Store unavailable."
        case = await self.get(case_id)
        if not case:
            return f"Case #{case_id} not found."
        old_status = case["status"]
        if old_status == new_status:
            return None   # no-op
        now = time.time()
        await self._db.execute(
            "UPDATE cases SET status=?, updated_at=? WHERE id=?",
            (new_status, now, case_id),
        )
        # System note for audit trail
        await self._append_note(
            case_id,
            author=f"system ({actor})",
            body=f"Status changed: {old_status} → {new_status}",
        )
        await self._db.commit()
        return None

    async def assign(
        self,
        case_id: int,
        assignee: Optional[str],
        actor: str = "system",
    ) -> Optional[str]:
        """Assign (or unassign) a case. Returns None on success, error on failure."""
        if not self.available or self._db is None:
            return "Store unavailable."
        case = await self.get(case_id)
        if not case:
            return f"Case #{case_id} not found."
        old = case.get("assigned_to") or "unassigned"
        new = assignee or "unassigned"
        now = time.time()
        await self._db.execute(
            "UPDATE cases SET assigned_to=?, updated_at=? WHERE id=?",
            (assignee, now, case_id),
        )
        await self._append_note(
            case_id,
            author=f"system ({actor})",
            body=f"Assigned: {old} → {new}",
        )
        await self._db.commit()
        return None

    async def add_note(
        self, case_id: int, author: str, body: str
    ) -> Optional[str]:
        """Append an analyst note. Returns None on success, error on failure."""
        if not self.available or self._db is None:
            return "Store unavailable."
        if not body.strip():
            return "Note body cannot be empty."
        case = await self.get(case_id)
        if not case:
            return f"Case #{case_id} not found."
        await self._append_note(case_id, author=author, body=body.strip())
        await self._db.execute(
            "UPDATE cases SET updated_at=? WHERE id=?",
            (time.time(), case_id),
        )
        await self._db.commit()
        return None

    #  Delete 

    async def delete(self, case_id: int) -> Optional[str]:
        """Delete a case and all its notes (admin only). Returns None on success."""
        if not self.available or self._db is None:
            return "Store unavailable."
        await self._db.execute("DELETE FROM case_notes WHERE case_id=?", (case_id,))
        await self._db.execute("DELETE FROM cases WHERE id=?", (case_id,))
        await self._db.commit()
        return None

    #  Internal 

    async def _get_notes(self, case_id: int) -> List[Dict]:
        async with self._db.execute(
            "SELECT * FROM case_notes WHERE case_id=? ORDER BY ts ASC",
            (case_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def _append_note(self, case_id: int, author: str, body: str) -> None:
        now = time.time()
        await self._db.execute(
            "INSERT INTO case_notes (case_id, author, body, ts, time) VALUES (?,?,?,?,?)",
            (case_id, author, body, now, iso_time()),
        )


#  Helpers 


def _auto_title(d: Detection) -> str:
    """Generate a human-readable case title from a Detection."""
    reasons = d.reasons
    if not reasons:
        return f"{d.severity} alert from {d.src_ip}"
    primary = reasons[0]
    # Map detection reason prefix to readable label
    label_map = {
        "brute_force":          "SSH Brute-Force",
        "credential_stuffing":  "Credential Stuffing",
        "credential_breach":    "Credential Breach",
        "web_scan_flood":       "Web Scan Flood",
        "web_auth_flood":       "Web Auth Flood",
        "web_exploit":          "Web Exploit Attempt",
        "db_brute_force":       "Database Brute-Force",
        "honeypot_port":        "Honeypot Trigger",
        "country_block":        "Country-Blocked IP",
        "web_recon_then_ssh":   "Web Recon + SSH",
        "multi_service_brute":  "Multi-Service Attack",
        "privilege_escalation": "Privilege Escalation",
        "ml_anomaly":           "ML Anomaly",
    }
    for key, label in label_map.items():
        if key in primary.lower():
            return f"{label} — {d.src_ip}"
    return f"{d.severity} Alert — {d.src_ip}"


def _row_to_case(row: Dict) -> Dict:
    """Deserialise a cases table row."""
    row["reasons"] = json.loads(row.get("reasons") or "[]")
    return row


def _build_filter(
    status: Optional[str],
    assigned_to: Optional[str],
    severity: Optional[str],
) -> tuple:
    clauses, params = [], []
    if status:
        clauses.append("status=?")
        params.append(status)
    if assigned_to == "__unassigned__":
        clauses.append("assigned_to IS NULL")
    elif assigned_to:
        clauses.append("assigned_to=?")
        params.append(assigned_to)
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params