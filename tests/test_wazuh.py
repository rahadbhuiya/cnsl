"""
tests/test_wazuh.py -- tests for Wazuh/OSSEC integration:
- cnsl/wazuh.py (alert parsing)
- cnsl/detector.py's WAZUH_ALERT routing
- cnsl/rules.py's wazuh.alert rule registration
- cnsl/log_sources.py's file-tailing wiring
- cnsl/syslog_receiver.py wiring (parse_wazuh_alert as a registered parser)
- cnsl/engine.py's SyslogReceiver instantiation (fixes a pre-existing
  gap: SyslogReceiver was imported but never actually started)
"""

from __future__ import annotations

import asyncio
import json

import pytest

from cnsl.wazuh import parse_wazuh_alert, _level_to_severity, _extract_srcip


def _run(coro):
    return asyncio.run(coro)


def _alert(**overrides):
    base = {
        "rule":  {"level": 10, "description": "sshd: brute force", "id": "5712",
                  "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "web01", "ip": "10.0.0.5"},
        "data":  {"srcip": "45.33.32.1", "srcuser": "root"},
        "full_log": "Failed password for root from 45.33.32.1",
    }
    base.update(overrides)
    return base


class TestLevelToSeverity:
    def test_high_at_boundary(self):
        assert _level_to_severity(12) == "HIGH"

    def test_high_above_boundary(self):
        assert _level_to_severity(16) == "HIGH"

    def test_medium_at_boundary(self):
        assert _level_to_severity(7) == "MEDIUM"

    def test_medium_below_high(self):
        assert _level_to_severity(11) == "MEDIUM"

    def test_low_below_medium(self):
        assert _level_to_severity(6) == "LOW"

    def test_low_at_zero(self):
        assert _level_to_severity(0) == "LOW"

    def test_non_numeric_defaults_to_low(self):
        assert _level_to_severity("not-a-number") == "LOW"
        assert _level_to_severity(None) == "LOW"


class TestExtractSrcip:
    def test_srcip_field(self):
        assert _extract_srcip({"srcip": "1.2.3.4"}) == "1.2.3.4"

    def test_src_ip_field(self):
        assert _extract_srcip({"src_ip": "1.2.3.4"}) == "1.2.3.4"

    def test_sourceip_field(self):
        assert _extract_srcip({"sourceip": "1.2.3.4"}) == "1.2.3.4"

    def test_no_matching_field_returns_none(self):
        assert _extract_srcip({"unrelated": "x"}) is None

    def test_empty_dict_returns_none(self):
        assert _extract_srcip({}) is None

    def test_field_priority_srcip_first(self):
        assert _extract_srcip({"srcip": "1.1.1.1", "src_ip": "2.2.2.2"}) == "1.1.1.1"


class TestParseWazuhAlert:
    def test_parses_valid_alert(self):
        ev = parse_wazuh_alert(json.dumps(_alert()))
        assert ev is not None
        assert ev.kind == "WAZUH_ALERT"
        assert ev.source == "wazuh"
        assert ev.src_ip == "45.33.32.1"
        assert ev.user == "root"

    def test_meta_fields_populated(self):
        ev = parse_wazuh_alert(json.dumps(_alert()))
        assert ev.meta["rule_id"] == "5712"
        assert ev.meta["rule_level"] == 10
        assert ev.meta["rule_description"] == "sshd: brute force"
        assert ev.meta["agent_name"] == "web01"
        assert ev.meta["severity"] == "MEDIUM"

    def test_high_severity_alert(self):
        ev = parse_wazuh_alert(json.dumps(_alert(rule={"level": 14, "description": "critical", "id": "9"})))
        assert ev.meta["severity"] == "HIGH"

    def test_low_severity_alert(self):
        ev = parse_wazuh_alert(json.dumps(_alert(rule={"level": 2, "description": "info", "id": "1"})))
        assert ev.meta["severity"] == "LOW"

    def test_blank_line_returns_none(self):
        assert parse_wazuh_alert("") is None
        assert parse_wazuh_alert("   ") is None

    def test_malformed_json_returns_none(self):
        assert parse_wazuh_alert("not json at all") is None
        assert parse_wazuh_alert("{broken") is None

    def test_non_dict_json_returns_none(self):
        assert parse_wazuh_alert("[1, 2, 3]") is None
        assert parse_wazuh_alert('"just a string"') is None

    def test_missing_srcip_returns_none(self):
        alert = _alert(data={"srcuser": "root"})
        assert parse_wazuh_alert(json.dumps(alert)) is None

    def test_missing_data_block_returns_none(self):
        alert = _alert()
        del alert["data"]
        assert parse_wazuh_alert(json.dumps(alert)) is None

    def test_syslog_wrapped_json_is_parsed(self):
        """Defensive fallback path -- header stripping when a caller
        hands parse_wazuh_alert a still-wrapped line directly, rather
        than going through syslog_receiver's own header stripping."""
        payload = json.dumps(_alert())
        syslog_line = f"<134>Jan  1 00:00:00 wazuh-manager wazuh: {payload}"
        ev = parse_wazuh_alert(syslog_line)
        assert ev is not None
        assert ev.src_ip == "45.33.32.1"

    def test_alt_srcip_field_name(self):
        alert = _alert(data={"src_ip": "9.9.9.9"})
        ev = parse_wazuh_alert(json.dumps(alert))
        assert ev.src_ip == "9.9.9.9"

    def test_missing_rule_block_does_not_crash(self):
        alert = _alert()
        del alert["rule"]
        ev = parse_wazuh_alert(json.dumps(alert))
        assert ev is not None
        assert ev.meta["severity"] == "LOW"

    def test_missing_agent_block_does_not_crash(self):
        alert = _alert()
        del alert["agent"]
        ev = parse_wazuh_alert(json.dumps(alert))
        assert ev is not None
        assert ev.meta["agent_name"] is None

    def test_raw_preserves_original_line(self):
        line = json.dumps(_alert())
        ev = parse_wazuh_alert(line)
        assert ev.raw == line


class TestSyslogReceiverWazuhIntegration:
    """parse_wazuh_alert works correctly as a registered parser inside
    the generic syslog receiver's routing (cnsl/syslog_receiver.py),
    which strips the RFC 3164/5424 header before handing off the
    message body to each parser in turn."""

    def test_route_syslog_message_matches_wazuh_alert(self):
        from cnsl.syslog_receiver import parse_syslog_message, _route_syslog_message
        payload = json.dumps(_alert())
        raw = f"<134>1 2026-07-24T00:00:00Z wazuh-manager wazuh-alerts - - - {payload}"
        parsed = parse_syslog_message(raw)
        ev = _route_syslog_message(parsed, "10.0.0.9", [parse_wazuh_alert])
        assert ev is not None
        assert ev.src_ip == "45.33.32.1"
        assert ev.kind == "WAZUH_ALERT"

    def test_route_syslog_message_adds_syslog_meta(self):
        from cnsl.syslog_receiver import parse_syslog_message, _route_syslog_message
        payload = json.dumps(_alert())
        raw = f"<134>1 2026-07-24T00:00:00Z wazuh-manager wazuh-alerts - - - {payload}"
        parsed = parse_syslog_message(raw)
        ev = _route_syslog_message(parsed, "10.0.0.9", [parse_wazuh_alert])
        assert ev.meta["syslog_remote_ip"] == "10.0.0.9"

    def test_route_syslog_message_no_match_returns_none(self):
        from cnsl.syslog_receiver import parse_syslog_message, _route_syslog_message
        parsed = parse_syslog_message("<134>Jan  1 00:00:00 host app: not json")
        ev = _route_syslog_message(parsed, "10.0.0.9", [parse_wazuh_alert])
        assert ev is None

    def test_udp_roundtrip_through_syslog_receiver(self):
        """End-to-end: a UDP packet containing a syslog-wrapped Wazuh
        alert, received by the real SyslogReceiver, lands in the queue
        as a WAZUH_ALERT event."""
        async def go():
            from cnsl.syslog_receiver import SyslogReceiver
            from cnsl.logger import JsonLogger

            queue  = asyncio.Queue()
            logger = JsonLogger("/dev/null", verbose=False)
            cfg = {"syslog_receiver": {
                "enabled": True, "host": "127.0.0.1",
                "udp_port": 15518, "tcp_port": 15519,
                "udp_enabled": True, "tcp_enabled": False,
            }}
            receiver = SyslogReceiver(cfg, queue, [parse_wazuh_alert], logger)
            await receiver.start()
            try:
                payload = json.dumps(_alert())
                raw = f"<134>1 2026-07-24T00:00:00Z wazuh-manager wazuh-alerts - - - {payload}"

                loop = asyncio.get_event_loop()
                sock, _ = await loop.create_datagram_endpoint(
                    asyncio.DatagramProtocol, remote_addr=("127.0.0.1", 15518)
                )
                sock.sendto(raw.encode())
                ev = await asyncio.wait_for(queue.get(), timeout=2)
                assert ev.kind == "WAZUH_ALERT"
                assert ev.src_ip == "45.33.32.1"
                sock.close()
            finally:
                receiver.stop()
        _run(go())


class TestDetectorWazuhRouting:
    def _make_detector(self):
        from helpers import make_detector
        return make_detector()

    def test_wazuh_alert_routes_to_maybe_fire(self):
        det = self._make_detector()
        ev = parse_wazuh_alert(json.dumps(_alert(rule={"level": 13, "description": "x", "id": "1"})))

        calls = []
        orig = det._maybe_fire
        async def spy(*a, **kw):
            calls.append(a)
            return await orig(*a, **kw)
        det._maybe_fire = spy

        _run(det.handle(ev))
        assert len(calls) == 1
        assert calls[0][3] == "HIGH"  # severity arg

    def test_wazuh_alert_reason_includes_rule_description(self):
        det = self._make_detector()
        ev = parse_wazuh_alert(json.dumps(_alert(
            rule={"level": 10, "description": "Multiple auth failures", "id": "42"})))

        calls = []
        orig = det._maybe_fire
        async def spy(*a, **kw):
            calls.append(a)
            return await orig(*a, **kw)
        det._maybe_fire = spy

        _run(det.handle(ev))
        reasons = calls[0][4]
        assert any("Multiple auth failures" in r for r in reasons)

    def test_wazuh_kind_in_all_handled(self):
        from cnsl.detector import _ALL_HANDLED
        assert "WAZUH_ALERT" in _ALL_HANDLED

    def test_disabled_wazuh_rule_does_not_fire(self):
        det = self._make_detector()
        det.rules.disable("wazuh.alert")
        ev = parse_wazuh_alert(json.dumps(_alert()))

        calls = []
        orig = det._maybe_fire
        async def spy(*a, **kw):
            calls.append(a)
            return await orig(*a, **kw)
        det._maybe_fire = spy

        _run(det.handle(ev))
        # sev stays None when the rule is disabled, so _maybe_fire is
        # never even called (see _on_wazuh_event's `if sev is not None`).
        assert len(calls) == 0


class TestWazuhRuleRegistration:
    def test_wazuh_alert_rule_registered(self):
        from cnsl.rules import _BUILTIN_BY_ID
        assert "wazuh.alert" in _BUILTIN_BY_ID

    def test_wazuh_rule_tags(self):
        from cnsl.rules import _BUILTIN_BY_ID
        rule = _BUILTIN_BY_ID["wazuh.alert"]
        assert "wazuh" in rule.tags
        assert "hids" in rule.tags


class TestLogSourcesWazuhWiring:
    def test_wazuh_parser_registered_for_file_tailing(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "log_sources.py").read_text(encoding="utf-8")
        assert '"wazuh":  parse_wazuh_alert' in src or '"wazuh": parse_wazuh_alert' in src

    def test_get_log_tasks_creates_wazuh_file_tail_task(self):
        from cnsl.log_sources import get_log_tasks
        from cnsl.logger import JsonLogger

        async def go():
            cfg = {"log_sources": {"wazuh": "/tmp/nonexistent_alerts.json"}}
            queue = asyncio.Queue()
            logger = JsonLogger("/dev/null", verbose=False)
            tasks = get_log_tasks(cfg, queue, logger)
            names = [t.get_name() for t in tasks]
            assert "logsrc_wazuh" in names
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        _run(go())


class TestEngineSyslogReceiverWiring:
    """SyslogReceiver was previously imported in engine.py but never
    instantiated or started -- these guard against that regressing."""

    def test_syslog_receiver_imported_in_engine(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        assert "from .syslog_receiver import SyslogReceiver" in src

    def test_syslog_receiver_actually_instantiated_in_engine(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        assert "syslog_receiver = SyslogReceiver(" in src

    def test_syslog_receiver_started_in_engine(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        assert "await syslog_receiver.start()" in src

    def test_syslog_receiver_stopped_on_shutdown(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        assert "syslog_receiver.stop()" in src

    def test_parse_wazuh_alert_registered_as_syslog_parser(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py").read_text(encoding="utf-8")
        assert "parse_wazuh_alert" in src


class TestDefaultConfigNoStrayWazuhBlock:
    """The wazuh.syslog config block was removed in favor of the
    existing generic syslog_receiver config -- guard against it
    reappearing as dead/duplicate config surface."""

    def test_default_config_has_no_wazuh_key(self):
        from cnsl.config import DEFAULT_CONFIG
        assert "wazuh" not in DEFAULT_CONFIG