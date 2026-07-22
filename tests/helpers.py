"""
tests/helpers.py -- shared fixtures/helper functions for the split test suite.
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

# Pre-import sklearn at module load time so individual tests don't timeout.
# If sklearn is not installed or broken, ML tests will be skipped gracefully.
try:
    import sklearn  # noqa: F401
    _SKLEARN_AVAILABLE = True
except Exception:
    _SKLEARN_AVAILABLE = False



# Helpers


def make_cfg(**overrides):
    import json
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    # Legacy: put overrides in thresholds (for correlator/baseline compat)
    for k, v in overrides.items():
        cfg["thresholds"][k] = v
    # Also propagate to rules engine so detector sees the new thresholds
    _THRESH_TO_RULE = {
        "fails_threshold":              ("ssh.brute_force",         "threshold"),
        "unique_users_threshold":       ("ssh.credential_stuffing", "threshold"),
        "success_after_fails_threshold":("ssh.credential_breach",   "threshold"),
        "web_scan_threshold":           ("web.scan_flood",           "threshold"),
        "web_auth_fail_threshold":      ("web.auth_flood",           "threshold"),
        "db_fail_threshold":            ("db.brute_force",           "threshold"),
    }
    if "rules" not in cfg:
        cfg["rules"] = {}
    for k, v in overrides.items():
        if k in _THRESH_TO_RULE:
            rule_id, field = _THRESH_TO_RULE[k]
            if rule_id not in cfg["rules"]:
                cfg["rules"][rule_id] = {}
            cfg["rules"][rule_id][field] = v
    return cfg


def make_detector(cfg=None, **th_overrides):
    if cfg is None:
        cfg = make_cfg(**th_overrides)
    logger = AsyncMock()
    logger.log = AsyncMock()
    blocker = AsyncMock()
    blocker.is_blocked = MagicMock(return_value=False)
    blocker.block_ip = AsyncMock(return_value=True)
    return Detector(cfg, logger, blocker)



# Parser tests




def _run(coro):
    """Run a coroutine in a fresh event loop."""
    return asyncio.run(coro)


import asyncio as _asyncio
import tempfile as _tempfile


async def _make_cm():
    """CaseManager backed by a fresh temp SQLite DB."""
    import aiosqlite
    from cnsl.cases import CaseManager

    class _Store:
        available = True
        _db = None

    store = _Store()
    tmp = _tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store._db = await aiosqlite.connect(tmp.name)
    store._db.row_factory = aiosqlite.Row
    cm = CaseManager(store)
    await cm.init()
    return cm


def _det(ip="1.2.3.4", sev="HIGH", reasons=None):
    from cnsl.models import Detection
    return Detection(src_ip=ip, severity=sev,
                     reasons=reasons or ["brute_force: test"],
                     fail_count=5, uniq_users=2, window_sec=60)