"""
cnsl/case_sla.py -- SLA tracking and escalation for incident cases.

cnsl/cases.py tracks a case's status, assignee, and notes, but nothing
watches how *long* a case has sat in a given state. A HIGH-severity
case auto-created at 2am and never picked up looks exactly like one
opened a minute ago -- there's no signal that it's overdue. This adds
per-severity time targets and flags cases that breach them.

Two independent clocks per case:
  - Response  -- time from creation until someone picks it up
    (assigned, or moved out of "open"). Answers "did anyone look at
    this?"
  - Resolution -- time from creation until the case reaches a resolved
    status (closed / false_positive). Answers "did anyone finish it?"

A case can breach response, resolution, or both. Both clocks stop when
the case resolves; a case closed within its resolution target never
breaches resolution even if it sat unassigned for a while first (that
still counts as a response breach -- the two are reported separately
rather than collapsed, because they mean different things about a
team's workflow).

Escalation, when enabled, does two things on a breach:
  1. Appends a system note to the case (visible in the case timeline,
     same as any status change) so the breach is on the record.
  2. Optionally bumps severity one step (MEDIUM -> HIGH). It never
     changes status or assignee -- a machine deciding a case is
     "investigating" because a timer expired would be a lie about who
     did what, and the whole point of an SLA breach is that nobody has.

Severity is bumped at most once per case (tracked by the escalation
note already being present), so a case sitting breached for a week
doesn't climb indefinitely or re-notify on every check.

This module only ever reads and annotates. It never closes, deletes,
or reassigns a case.

Config:
  "case_sla": {
    "enabled":            true,
    "check_interval_sec": 300,
    "targets": {
      "HIGH":   {"response_minutes": 30,  "resolution_minutes": 240},
      "MEDIUM": {"response_minutes": 240, "resolution_minutes": 1440},
      "LOW":    {"response_minutes": 1440, "resolution_minutes": 10080}
    },
    "escalate_on_breach":  true,
    "bump_severity":       true,
    "notify_on_breach":    false
  }
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from .cases import RESOLVED_STATUSES

# Severity bump ladder. HIGH is terminal -- there's nothing above it,
# and CNSL's Severity model only has three levels.
_SEVERITY_BUMP = {"LOW": "MEDIUM", "MEDIUM": "HIGH"}

_ESCALATION_NOTE_PREFIX = "[SLA BREACH]"

_DEFAULT_TARGETS: Dict[str, Dict[str, int]] = {
    "HIGH":   {"response_minutes": 30,   "resolution_minutes": 240},
    "MEDIUM": {"response_minutes": 240,  "resolution_minutes": 1440},
    "LOW":    {"response_minutes": 1440, "resolution_minutes": 10080},
}


class CaseSLA:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        s = cfg.get("case_sla", {}) or {}
        self.enabled            = bool(s.get("enabled", False))
        self.check_interval_sec = int(s.get("check_interval_sec", 300))
        self.escalate_on_breach = bool(s.get("escalate_on_breach", True))
        self.bump_severity      = bool(s.get("bump_severity", True))
        self.notify_on_breach   = bool(s.get("notify_on_breach", False))

        targets = s.get("targets") or {}
        self.targets: Dict[str, Dict[str, int]] = {}
        for sev, defaults in _DEFAULT_TARGETS.items():
            t = targets.get(sev, {}) or {}
            self.targets[sev] = {
                "response_minutes":   int(t.get("response_minutes",   defaults["response_minutes"])),
                "resolution_minutes": int(t.get("resolution_minutes", defaults["resolution_minutes"])),
            }

        self.last_check_at: Optional[float] = None
        self.last_result: Dict[str, Any] = {}

    #  Breach evaluation (pure -- no I/O, so it's directly testable)

    def target_for(self, severity: str) -> Dict[str, int]:
        return self.targets.get(severity, self.targets["MEDIUM"])

    def evaluate_case(self, case: Dict[str, Any], now_ts: Optional[float] = None) -> Dict[str, Any]:
        """
        Evaluate one case dict (as returned by CaseManager.get/list_cases)
        against its severity's targets. Pure function -- returns a
        breach report, changes nothing.
        """
        now_ts = now_ts if now_ts is not None else time.time()
        severity   = case.get("severity", "MEDIUM")
        status     = case.get("status", "open")
        created_at = case.get("created_at") or now_ts
        target     = self.target_for(severity)
        age_sec    = max(0.0, now_ts - created_at)

        resolved = status in RESOLVED_STATUSES
        # "Responded" means someone actually engaged: assigned it, or
        # moved it off the initial "open" state. A case that went
        # straight to closed counts as responded to.
        responded = bool(case.get("assigned_to")) or status != "open"

        response_breached = (not responded) and age_sec > target["response_minutes"] * 60
        resolution_breached = (not resolved) and age_sec > target["resolution_minutes"] * 60

        return {
            "case_id":             case.get("id"),
            "severity":            severity,
            "status":              status,
            "age_sec":             round(age_sec, 1),
            "response_target_sec":   target["response_minutes"] * 60,
            "resolution_target_sec": target["resolution_minutes"] * 60,
            "response_breached":   response_breached,
            "resolution_breached": resolution_breached,
            "breached":            response_breached or resolution_breached,
        }

    #  Escalation

    @staticmethod
    def _already_escalated(notes: List[Dict[str, Any]]) -> bool:
        return any(str(n.get("body", "")).startswith(_ESCALATION_NOTE_PREFIX) for n in notes)

    def _breach_note(self, report: Dict[str, Any]) -> str:
        parts = []
        if report["response_breached"]:
            mins = report["response_target_sec"] // 60
            parts.append(f"no response within {mins}m target")
        if report["resolution_breached"]:
            mins = report["resolution_target_sec"] // 60
            parts.append(f"not resolved within {mins}m target")
        age_min = int(report["age_sec"] // 60)
        return f"{_ESCALATION_NOTE_PREFIX} {'; '.join(parts)} (case is {age_min}m old)"

    async def _escalate(self, case_manager: Any, case: Dict[str, Any], report: Dict[str, Any]) -> Dict[str, Any]:
        """Annotate (and optionally bump severity on) one breached case."""
        case_id = case["id"]
        notes = case.get("notes") or []
        if self._already_escalated(notes):
            return {"case_id": case_id, "escalated": False, "reason": "already escalated"}

        await case_manager.add_note(case_id, author="system (sla)", body=self._breach_note(report))

        bumped_to = None
        if self.bump_severity:
            new_sev = _SEVERITY_BUMP.get(report["severity"])
            if new_sev:
                await case_manager.set_severity(case_id, new_sev, actor="sla")
                bumped_to = new_sev

        return {"case_id": case_id, "escalated": True, "bumped_to": bumped_to}

    #  Check pass

    async def check_once(
        self, case_manager: Any, logger: Any = None, notifier: Any = None,
    ) -> Dict[str, Any]:
        """
        Evaluate every unresolved case, escalating any that breach.
        Only open/investigating cases are fetched -- a resolved case's
        clocks have stopped, so there's nothing to check.
        """
        if not self.enabled or case_manager is None or not getattr(case_manager, "available", False):
            result = {"ran": False, "reason": "case SLA disabled or store unavailable"}
            self.last_result = result
            return result

        now_ts = time.time()
        breaches: List[Dict[str, Any]] = []
        escalations: List[Dict[str, Any]] = []

        open_cases: List[Dict[str, Any]] = []
        for status in ("open", "investigating"):
            open_cases.extend(await case_manager.list_cases(status=status, limit=1000))

        for case in open_cases:
            report = self.evaluate_case(case, now_ts)
            if not report["breached"]:
                continue
            breaches.append(report)
            if self.escalate_on_breach:
                full = await case_manager.get(case["id"])
                if full:
                    escalations.append(await self._escalate(case_manager, full, report))

        result = {
            "ran":            True,
            "checked":        len(open_cases),
            "breached":       len(breaches),
            "escalated":      sum(1 for e in escalations if e.get("escalated")),
            "breaches":       breaches,
            "checked_at":     now_ts,
        }
        self.last_check_at = now_ts
        self.last_result = result

        if logger is not None and breaches:
            await logger.log("case_sla_breach", {
                "checked":   result["checked"],
                "breached":  result["breached"],
                "escalated": result["escalated"],
                "case_ids":  [b["case_id"] for b in breaches],
            })
        return result

    async def run_loop(self, case_manager: Any, logger: Any, notifier: Any = None) -> None:
        """Background task: check SLAs on check_interval_sec, forever."""
        if not self.enabled:
            return
        while True:
            await asyncio.sleep(self.check_interval_sec)
            await self.check_once(case_manager, logger, notifier)

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":            self.enabled,
            "check_interval_sec": self.check_interval_sec,
            "targets":            self.targets,
            "escalate_on_breach": self.escalate_on_breach,
            "bump_severity":      self.bump_severity,
            "notify_on_breach":   self.notify_on_breach,
            "last_check_at":      self.last_check_at,
            "last_result":        self.last_result,
        }