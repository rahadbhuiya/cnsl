"""
tests/test_normalizer_meta_cycle.py -- regression test for a reference
cycle in cnsl/normalizer.py that caused RecursionError on every single
event that went through the real engine loop.

Root cause: every _normalize_* constructor passed cnsl_meta=ev.meta (or
`meta = ev.meta or {}`) -- the SAME dict object as the source Event's
own .meta, not a copy. engine.py's main loop then does
`ev.meta["_ecs"] = norm.to_dict()`, and NormalizedEvent.to_dict() embeds
self.cnsl_meta (== ev.meta) back into that same dict -- creating a
genuine cycle: ev.meta["_ecs"][...]["meta"] is ev.meta. Any later
dataclasses.asdict(ev) (used by Event.to_dict(), called via
detector.py's `self.logger.log("event_auth", ev.to_dict())` on every
processed event) recursed until RecursionError.

This was invisible to every existing test because nothing exercised
the exact sequence: normalize -> stash result back into ev.meta ->
serialize ev again -- which is exactly what engine.py's real
_ingest_and_detect loop does but no test replicated.
"""

from __future__ import annotations

import dataclasses

import pytest

from cnsl.models import Event
from cnsl.normalizer import normalize


def _simulate_engine_loop_step(ev: Event) -> dict:
    """Mirrors engine.py's actual sequence exactly: normalize, stash
    the result into ev.meta, then serialize ev again (as detector.py's
    logging does for every event)."""
    norm = normalize(ev)
    ev.meta["_ecs"] = norm.to_dict()
    return ev.to_dict()


class TestNormalizedEventMetaNotAliased:
    def test_cnsl_meta_is_not_the_same_object_as_event_meta(self):
        ev = Event(ts=1000.0, source="auth", kind="SSH_FAIL",
                    src_ip="45.33.32.1", user="root", raw="x",
                    meta={"some": "value"})
        norm = normalize(ev)
        assert norm.cnsl_meta is not ev.meta

    def test_cnsl_meta_still_has_the_same_content(self):
        ev = Event(ts=1000.0, source="auth", kind="SSH_FAIL",
                    src_ip="45.33.32.1", user="root", raw="x",
                    meta={"some": "value"})
        norm = normalize(ev)
        assert norm.cnsl_meta == {"some": "value"}

    def test_mutating_event_meta_after_normalize_does_not_affect_norm(self):
        ev = Event(ts=1000.0, source="auth", kind="SSH_FAIL",
                    src_ip="45.33.32.1", user="root", raw="x", meta={})
        norm = normalize(ev)
        ev.meta["_ecs"] = {"anything": "at all"}
        assert "_ecs" not in norm.cnsl_meta


class TestNoRecursionOnRealEnginePattern:
    """Reproduces engine.py's exact real sequence for every event kind
    that has its own normalizer, and asserts ev.to_dict() succeeds
    without RecursionError -- this is the actual regression guard."""

    @pytest.mark.parametrize("kind,source", [
        ("SSH_FAIL", "auth"),
        ("SSH_SUCCESS", "auth"),
        ("WEB_SCAN", "nginx"),
        ("DB_FAIL", "mysql"),
        ("FW_HONEYPOT_PORT", "firewall"),
    ])
    def test_normalize_then_serialize_does_not_recurse(self, kind, source):
        ev = Event(ts=1000.0, source=source, kind=kind, src_ip="45.33.32.1",
                    user="root", raw="test line", meta={})
        try:
            d = _simulate_engine_loop_step(ev)
        except RecursionError:
            pytest.fail(
                f"RecursionError for kind={kind} -- the cnsl_meta/ev.meta "
                "reference cycle has regressed."
            )
        assert isinstance(d, dict)
        assert "_ecs" in d["meta"]

    def test_repeated_normalize_cycles_still_safe(self):
        """Simulates an event being normalized more than once (e.g. a
        retry path) -- must stay safe even with _ecs already present
        from a prior pass."""
        ev = Event(ts=1000.0, source="auth", kind="SSH_FAIL",
                    src_ip="45.33.32.1", user="root", raw="x", meta={})
        _simulate_engine_loop_step(ev)
        try:
            _simulate_engine_loop_step(ev)  # normalize again, _ecs already set
        except RecursionError:
            pytest.fail("RecursionError on second normalize pass")

    def test_event_to_dict_directly_after_ecs_stash(self):
        """The exact minimal repro: dataclasses.asdict must terminate."""
        ev = Event(ts=1000.0, source="auth", kind="SSH_FAIL",
                    src_ip="45.33.32.1", user="root", raw="x", meta={})
        norm = normalize(ev)
        ev.meta["_ecs"] = norm.to_dict()
        result = dataclasses.asdict(ev)
        assert result["src_ip"] == "45.33.32.1"