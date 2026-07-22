"""
tests/test_audit.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_audit.py -v
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


class TestAuditLog:
    """AuditLog records who did what, when — separate from the noisy
    detection-event JSONL log, queryable for compliance review."""

    def _make_audit(self):
        from cnsl.store import Store
        from cnsl.audit import AuditLog
        store = Store(":memory:")
        _run(store.init())
        audit = AuditLog(store)
        _run(audit.init())
        return store, audit

    def test_record_and_list_round_trip(self):
        store, audit = self._make_audit()
        rid = _run(audit.record(actor="admin", action="block",
                                 target="45.33.32.1", details={"reason": "manual"},
                                 source_ip="10.0.0.5"))
        assert rid is not None

        entries = _run(audit.list())
        assert len(entries) == 1
        e = entries[0]
        assert e["actor"] == "admin"
        assert e["action"] == "block"
        assert e["target"] == "45.33.32.1"
        assert e["details"] == {"reason": "manual"}
        assert e["source_ip"] == "10.0.0.5"
        _run(store.close())

    def test_list_filters_by_actor_and_action(self):
        store, audit = self._make_audit()
        _run(audit.record(actor="admin", action="block", target="1.1.1.1"))
        _run(audit.record(actor="analyst1", action="unblock", target="1.1.1.1"))
        _run(audit.record(actor="admin", action="rotate_secret"))

        by_actor = _run(audit.list(actor="admin"))
        assert len(by_actor) == 2
        assert all(e["actor"] == "admin" for e in by_actor)

        by_action = _run(audit.list(action="unblock"))
        assert len(by_action) == 1
        assert by_action[0]["actor"] == "analyst1"
        _run(store.close())

    def test_list_newest_first(self):
        store, audit = self._make_audit()
        _run(audit.record(actor="admin", action="block", target="1.1.1.1"))
        _run(audit.record(actor="admin", action="block", target="2.2.2.2"))
        entries = _run(audit.list())
        assert entries[0]["target"] == "2.2.2.2"
        assert entries[1]["target"] == "1.1.1.1"
        _run(store.close())

    def test_count_matches_filters(self):
        store, audit = self._make_audit()
        _run(audit.record(actor="admin", action="block", target="1.1.1.1"))
        _run(audit.record(actor="admin", action="unblock", target="1.1.1.1"))
        assert _run(audit.count()) == 2
        assert _run(audit.count(action="block")) == 1

    def test_unavailable_store_never_raises(self):
        from cnsl.store import Store
        from cnsl.audit import AuditLog
        store = Store(":memory:")  # never initialized -> unavailable
        audit = AuditLog(store)
        _run(audit.init())  # no-op, must not raise
        assert _run(audit.record(actor="admin", action="block")) is None
        assert _run(audit.list()) == []
        assert _run(audit.count()) == 0

    def test_details_defaults_to_empty_dict(self):
        store, audit = self._make_audit()
        _run(audit.record(actor="admin", action="rotate_secret"))
        entries = _run(audit.list())
        assert entries[0]["details"] == {}
        _run(store.close())

class TestDashboardAuditEndpoint:
    """/api/audit param plumbing and RBAC gate."""

    def test_start_dashboard_accepts_audit_log_param(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "audit_log" in sig.parameters
        assert sig.parameters["audit_log"].default is None

    def test_logs_read_permission_exists_for_auditor(self):
        from cnsl.rbac import ROLE_PERMISSIONS, Perm
        assert Perm.LOGS_READ in ROLE_PERMISSIONS["auditor"]
        assert Perm.LOGS_READ not in ROLE_PERMISSIONS["analyst"]


# v3.3.0 -- comprehensive config validation
