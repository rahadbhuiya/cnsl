"""
tests/test_parsers.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_parsers.py -v
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


class TestParseAuthEvent:
    def test_failed_password(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "1.2.3.4"

    def test_failed_password_invalid_user(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for invalid user admin from 5.6.7.8 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "5.6.7.8"
        assert ev.user == "admin"

    def test_accepted_password(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Accepted password for alice from 10.0.0.1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.src_ip == "10.0.0.1"
        assert ev.user == "alice"

    def test_accepted_publickey(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: Accepted publickey for bob from 192.168.1.1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.user == "bob"

    def test_non_sshd_line_ignored(self):
        line = "Apr 15 10:00:00 srv kernel: Something else happened"
        assert parse_auth_event(line) is None

    def test_empty_line(self):
        assert parse_auth_event("") is None

    def test_authentication_failure(self):
        line = "Apr 15 10:00:00 srv sshd[1234]: authentication failure; logname= uid=0 rhost=9.9.9.9"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "9.9.9.9"

    def test_ipv6_address(self):
        # ::ffff:1.2.3.4 is IPv6-mapped IPv4 — _clean_ip strips the prefix
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from ::ffff:1.2.3.4 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.src_ip == "1.2.3.4", f"Expected 1.2.3.4 got {ev.src_ip}"

    def test_ipv6_loopback(self):
        # Pure IPv6 like ::1 should stay as-is
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from ::1 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None
        assert ev.src_ip == "::1", f"Expected ::1 got {ev.src_ip}"

class TestParseTcpdumpHint:
    def test_arp_discovery(self):
        line = "10:00:00.000000 ARP, Request who-has 192.168.1.1 tell 192.168.1.2"
        ev = parse_tcpdump_hint(line)
        assert ev is not None
        assert ev.meta["hint"] == "DISCOVERY"

    def test_smb_enum_hint(self):
        line = "10:00:00.000000 IP 1.2.3.4.445 > 10.0.0.1.12345: Flags [S]"
        ev = parse_tcpdump_hint(line)
        assert ev is not None
        assert ev.meta["hint"] == "ENUM_HINT"

    def test_ntp_ignored(self):
        line = "10:00:00.000000 IP 10.0.0.1.123 > 8.8.8.8.123: NTPv4, Client"
        ev = parse_tcpdump_hint(line)
        assert ev is None

    def test_https_ignored(self):
        line = "10:00:00.000000 IP 10.0.0.1.54321 > 1.1.1.1.443: Flags [P]"
        ev = parse_tcpdump_hint(line)
        assert ev is None



# Config tests

class TestSshdSessionParser:
    """Modern OpenSSH uses sshd-session[PID] instead of sshd[PID].
    These tests verify the _SSHD_PREFIX regex matches both variants."""

    def test_sshd_session_fail(self):
        line = "2026-05-01T05:06:33-04:00 kali sshd-session[23017]: Failed password for oro from 1.2.3.4 port 43568 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session fail line not parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "1.2.3.4"

    def test_sshd_session_success(self):
        line = "2026-05-01T05:06:46-04:00 kali sshd-session[23135]: Accepted password for oro from 1.2.3.4 port 52710 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session success line not parsed"
        assert ev.kind == EventKind.SSH_SUCCESS
        assert ev.src_ip == "1.2.3.4"

    def test_sshd_session_invalid_user(self):
        line = "2026-05-01T09:00:00-04:00 kali sshd-session[9999]: Failed password for invalid user admin from 5.6.7.8 port 12345 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session invalid user line not parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.user == "admin"
        assert ev.src_ip == "5.6.7.8"

    def test_classic_sshd_still_works(self):
        """Original sshd[PID] format must still be matched."""
        line = "Apr 15 10:00:00 srv sshd[1234]: Failed password for root from 9.9.9.9 port 22 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "classic sshd line no longer parsed"
        assert ev.kind == EventKind.SSH_FAIL
        assert ev.src_ip == "9.9.9.9"

    def test_sshd_session_ipv6_loopback(self):
        """Kali localhost SSH uses ::1 — must be parsed correctly."""
        line = "2026-05-01T05:06:33-04:00 kali sshd-session[23017]: Failed password for oro from ::1 port 43568 ssh2"
        ev = parse_auth_event(line)
        assert ev is not None, "sshd-session ::1 line not parsed"
        assert ev.src_ip == "::1"


# v1.0.2 — Telegram escaping fix

class TestZeekTSVState:
    """TSV header parsing and row splitting."""

    def test_fields_header_parsed(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("ssh")
        line  = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tauth_success"
        assert state.update_from_header(line) is True
        assert state.fields == ["ts", "uid", "id.orig_h", "id.orig_p", "auth_success"]

    def test_comment_lines_skipped(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        assert state.update_from_header("#open\t2026-01-01") is True
        assert state.update_from_header("1.2.3.4\t22") is False

    def test_row_to_dict(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("ssh")
        state.fields = ["ts", "uid", "id.orig_h", "id.orig_p", "auth_success"]
        row = state.row_to_dict("1620000000.0\tabc\t1.2.3.4\t54321\tF")
        assert row["id.orig_h"] == "1.2.3.4"
        assert row["auth_success"] == "F"

    def test_empty_fields_excluded(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        state.fields = ["ts", "uid", "id.orig_h", "service"]
        row = state.row_to_dict("1620000000.0\tabc\t1.2.3.4\t-")
        assert "service" not in row   # "-" is treated as empty

    def test_hash_line_returns_none(self):
        from cnsl.zeek_parser import _TSVState
        state = _TSVState("conn")
        assert state.row_to_dict("#comment") is None

class TestZeekConnParser:
    """conn.log parsing."""

    def test_valid_conn_row(self):
        from cnsl.zeek_parser import parse_zeek_conn
        row = {"id.orig_h": "1.2.3.4", "id.resp_h": "5.6.7.8",
               "id.resp_p": "22", "proto": "tcp", "conn_state": "SF"}
        ev = parse_zeek_conn(row)
        assert ev is not None
        assert ev.kind == "NET_CONN"
        assert ev.src_ip == "1.2.3.4"
        assert ev.meta["dst_port"] == "22"

    def test_missing_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_conn
        assert parse_zeek_conn({"id.resp_h": "5.6.7.8"}) is None

    def test_empty_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_conn
        assert parse_zeek_conn({"id.orig_h": "-", "id.resp_h": "5.6.7.8"}) is None

class TestZeekSSHParser:
    """ssh.log parsing."""

    def test_ssh_fail(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        row = {"id.orig_h": "1.2.3.4", "id.resp_h": "10.0.0.1",
               "auth_success": "F", "auth_attempts": "3"}
        ev = parse_zeek_ssh(row)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"
        assert ev.src_ip == "1.2.3.4"

    def test_ssh_success(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        row = {"id.orig_h": "2.3.4.5", "id.resp_h": "10.0.0.1",
               "auth_success": "T", "auth_attempts": "1"}
        ev = parse_zeek_ssh(row)
        assert ev is not None
        assert ev.kind == "SSH_SUCCESS"

    def test_ssh_success_variants(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        for val in ("t", "true", "1", "T", "True"):
            row = {"id.orig_h": "1.1.1.1", "auth_success": val}
            assert parse_zeek_ssh(row).kind == "SSH_SUCCESS"

    def test_missing_src_ip_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_ssh
        assert parse_zeek_ssh({"auth_success": "F"}) is None

class TestZeekHTTPParser:
    """http.log parsing."""

    def test_exploit_path_detected(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "3.3.3.3", "uri": "/wp-login.php",
               "method": "POST", "status_code": "200", "user_agent": "Mozilla"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_EXPLOIT_ATTEMPT"

    def test_404_is_web_scan(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "4.4.4.4", "uri": "/random-path",
               "method": "GET", "status_code": "404", "user_agent": "Mozilla"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_SCAN"

    def test_401_is_web_auth_fail(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "5.5.5.5", "uri": "/admin",
               "method": "GET", "status_code": "401", "user_agent": "curl/7.0"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_AUTH_FAIL"

    def test_scanner_ua_detected(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "6.6.6.6", "uri": "/index.html",
               "method": "GET", "status_code": "200", "user_agent": "sqlmap/1.0"}
        ev = parse_zeek_http(row)
        assert ev is not None
        assert ev.kind == "WEB_SCAN"

    def test_normal_traffic_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_http
        row = {"id.orig_h": "7.7.7.7", "uri": "/index.html",
               "method": "GET", "status_code": "200", "user_agent": "Mozilla/5.0"}
        assert parse_zeek_http(row) is None

class TestZeekDNSParser:
    """dns.log entropy-based tunneling detection."""

    def test_high_entropy_query_flagged(self):
        from cnsl.zeek_parser import parse_zeek_dns, _shannon_entropy
        # Use a label with confirmed high entropy (>3.5)
        label = "x7Kq2mN9pR4wB6vZ"   # random alphanumeric — high entropy
        entropy = _shannon_entropy(label)
        assert entropy > 3.5, f"Test label entropy too low: {entropy:.2f}"
        row = {"id.orig_h": "8.8.8.8",
               "query": f"{label}.tunnel.example.com",
               "qtype_name": "TXT"}
        ev = parse_zeek_dns(row, entropy_threshold=3.5)
        assert ev is not None
        assert ev.kind == "DNS_QUERY"
        assert ev.meta["entropy"] > 3.5

    def test_normal_domain_not_flagged(self):
        from cnsl.zeek_parser import parse_zeek_dns
        row = {"id.orig_h": "8.8.8.8",
               "query": "www.google.com",
               "qtype_name": "A"}
        ev = parse_zeek_dns(row, entropy_threshold=3.5)
        assert ev is None

    def test_missing_query_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_dns
        assert parse_zeek_dns({"id.orig_h": "1.1.1.1"}) is None

class TestZeekNoticeWierd:
    """notice.log and weird.log parsing."""

    def test_notice_parsed(self):
        from cnsl.zeek_parser import parse_zeek_notice
        row = {"src": "1.2.3.4", "note": "Scan::Port_Scan",
               "msg": "1.2.3.4 scanned at least 15 unique ports"}
        ev = parse_zeek_notice(row)
        assert ev is not None
        assert ev.kind == "ZEEK_NOTICE"
        assert ev.meta["note"] == "Scan::Port_Scan"

    def test_notice_uses_id_orig_h_fallback(self):
        from cnsl.zeek_parser import parse_zeek_notice
        row = {"id.orig_h": "2.3.4.5", "note": "Test::Notice", "msg": "test"}
        ev = parse_zeek_notice(row)
        assert ev is not None
        assert ev.src_ip == "2.3.4.5"

    def test_weird_parsed(self):
        from cnsl.zeek_parser import parse_zeek_weird
        row = {"id.orig_h": "3.4.5.6", "name": "bad_TCP_checksum",
               "addl": "extra info"}
        ev = parse_zeek_weird(row)
        assert ev is not None
        assert ev.kind == "ZEEK_WEIRD"
        assert ev.meta["name"] == "bad_TCP_checksum"

    def test_weird_no_name_returns_none(self):
        from cnsl.zeek_parser import parse_zeek_weird
        assert parse_zeek_weird({"id.orig_h": "1.1.1.1"}) is None

class TestZeekLogParser:
    """ZeekLogParser stateful line-by-line parsing."""

    def test_tsv_full_flow_ssh(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="tsv")
        lines = [
            "#separator \\x09",
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tauth_success\tauth_attempts\tdirection\tclient\tserver\tcipher_alg\tmac_alg\tcompression_alg\tkex_alg\thost_key_alg\thost_key",
            "1620000000.0\tabc\t9.9.9.9\t54321\t10.0.0.1\t22\t2\tF\t3\tINBOUND\t-\t-\t-\t-\t-\t-\t-\t-",
        ]
        events = [parser.parse(l) for l in lines]
        events = [e for e in events if e]
        assert len(events) == 1
        assert events[0].kind == "SSH_FAIL"
        assert events[0].src_ip == "9.9.9.9"

    def test_json_ssh_fail(self):
        import json
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="json")
        line = json.dumps({
            "ts": 1620000000.0, "uid": "abc",
            "id.orig_h": "1.2.3.4", "id.orig_p": 54321,
            "id.resp_h": "10.0.0.1", "id.resp_p": 22,
            "auth_success": False, "auth_attempts": 5,
        })
        ev = parser.parse(line)
        assert ev is not None
        assert ev.kind == "SSH_FAIL"

    def test_header_lines_return_none(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("conn")
        assert parser.parse("#separator \\x09") is None
        assert parser.parse("#fields\tts\tuid") is None
        assert parser.parse("") is None

    def test_invalid_json_returns_none(self):
        from cnsl.zeek_parser import ZeekLogParser
        parser = ZeekLogParser("ssh", fmt="json")
        assert parser.parse("not-json-at-all") is None

class TestOTParserModbus:
    """parse_modbus() correctly classifies Modbus function codes."""

    def test_fc3_read_from_unknown_ip_is_scan(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 3 holding registers")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_SCAN
        assert ev.src_ip == "1.2.3.4"

    def test_fc3_read_from_trusted_ip_is_none(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 3 holding registers",
                          trusted_ips={"1.2.3.4"})
        assert ev is None

    def test_fc6_write_always_flagged(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 6 single register write",
                          trusted_ips={"1.2.3.4"})
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE

    def test_fc16_write_multiple_registers(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus src: 5.6.7.8 function_code: 16")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE
        assert ev.meta["function_code"] == 16

    def test_fc1_read_coils_from_trusted_is_none(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus from: 10.0.0.1 fc=1 read coils",
                          trusted_ips={"10.0.0.1"})
        assert ev is None

    def test_exception_line_returns_exception_kind(self):
        from cnsl.ot_parser import parse_modbus, OTEventKind
        ev = parse_modbus("modbus exception code 2 from 1.2.3.4 gateway error")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_EXCEPTION

    def test_empty_line_returns_none(self):
        from cnsl.ot_parser import parse_modbus
        assert parse_modbus("") is None
        assert parse_modbus("   ") is None

    def test_unrelated_line_returns_none(self):
        from cnsl.ot_parser import parse_modbus
        assert parse_modbus("nginx 200 GET /index.html") is None

    def test_meta_includes_protocol(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus src: 1.2.3.4 fc: 3 read")
        assert ev is not None
        assert ev.meta["protocol"] == "modbus"

    def test_source_is_modbus(self):
        from cnsl.ot_parser import parse_modbus
        ev = parse_modbus("modbus client: 1.2.3.4 fc: 6 write")
        assert ev is not None
        assert ev.source == "modbus"

class TestOTParserDNP3:
    """parse_dnp3() correctly classifies DNP3 events."""

    def test_unsolicited_from_unknown_ip(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp3 unsolicited response from 10.0.0.5")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_UNSOLICITED
        assert ev.src_ip == "10.0.0.5"

    def test_unsolicited_from_trusted_ip_is_none(self):
        from cnsl.ot_parser import parse_dnp3
        ev = parse_dnp3("dnp3 unsolicited response from 10.0.0.5",
                        trusted_ips={"10.0.0.5"})
        assert ev is None

    def test_auth_fail_detected(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp3 authentication failed from 10.0.0.9 bad mac")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_AUTH_FAIL

    def test_invalid_hmac_detected(self):
        from cnsl.ot_parser import parse_dnp3, OTEventKind
        ev = parse_dnp3("dnp security fail invalid hmac from 192.168.1.5")
        assert ev is not None
        assert ev.kind == OTEventKind.DNP3_AUTH_FAIL

    def test_unrelated_line_returns_none(self):
        from cnsl.ot_parser import parse_dnp3
        assert parse_dnp3("sshd failed password for root") is None

    def test_empty_line_returns_none(self):
        from cnsl.ot_parser import parse_dnp3
        assert parse_dnp3("") is None

class TestOTParserSCADA:
    """parse_scada() correctly classifies SCADA/HMI log events."""

    def test_unauthorized_from_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("unauthorized command from 192.168.50.99")
        assert ev is not None
        assert ev.kind == OTEventKind.UNAUTHORIZED_CMD

    def test_denied_from_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("access denied from ip 10.10.10.50 setpoint change")
        assert ev is not None
        assert ev.kind == OTEventKind.UNAUTHORIZED_CMD

    def test_alarm_with_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("alarm: high pressure trip from operator 192.168.1.10")
        assert ev is not None
        assert ev.kind == OTEventKind.SCADA_ALARM

    def test_alarm_without_ip(self):
        from cnsl.ot_parser import parse_scada, OTEventKind
        ev = parse_scada("CRITICAL: emergency shutdown ALARM triggered")
        assert ev is not None
        assert ev.kind == OTEventKind.SCADA_ALARM
        assert ev.src_ip is None

    def test_empty_returns_none(self):
        from cnsl.ot_parser import parse_scada
        assert parse_scada("") is None

class TestMakeOTParser:
    """make_ot_parser() factory returns correct parser per protocol."""

    def _cfg(self, trusted=None):
        return {"ot": {"enabled": True,
                       "trusted_ips": trusted or [],
                       "alert_on_any_write": True}}

    def test_modbus_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("modbus", self._cfg())
        assert p is not None
        assert callable(p)

    def test_dnp3_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("dnp3", self._cfg())
        assert p is not None

    def test_scada_parser_returned(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("scada", self._cfg())
        assert p is not None

    def test_unknown_protocol_returns_none(self):
        from cnsl.ot_parser import make_ot_parser
        assert make_ot_parser("profinet", self._cfg()) is None

    def test_trusted_ips_passed_to_parser(self):
        from cnsl.ot_parser import make_ot_parser
        p = make_ot_parser("modbus", self._cfg(trusted=["1.2.3.4"]))
        # FC3 read from trusted IP should return None
        assert p("modbus client: 1.2.3.4 fc: 3") is None

    def test_write_still_flagged_for_trusted_ip(self):
        from cnsl.ot_parser import make_ot_parser, OTEventKind
        p = make_ot_parser("modbus", self._cfg(trusted=["1.2.3.4"]))
        ev = p("modbus client: 1.2.3.4 fc: 6 write register")
        assert ev is not None
        assert ev.kind == OTEventKind.MODBUS_WRITE

class TestAWSCloudTrailParser:
    """_parse_events correctly maps CloudTrail events to Event objects."""

    def _make_connector(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        return AWSCloudTrailConnector({})

    def _make_raw_event(self, login_status="Failure", mfa_used="No",
                        event_id="EVT001", src_ip="1.2.3.4", user="alice"):
        import json
        ct = json.dumps({
            "sourceIPAddress":   src_ip,
            "userIdentity":      {"userName": user},
            "responseElements":  {"ConsoleLogin": login_status},
            "additionalEventData": {"MFAUsed": mfa_used},
        })
        return {"EventId": event_id, "EventName": "ConsoleLogin",
                "CloudTrailEvent": ct}

    def test_failure_maps_to_signin_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Failure")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.SIGNIN_FAIL

    def test_success_without_mfa_maps_to_mfa_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Success", mfa_used="No")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.MFA_FAIL

    def test_success_with_mfa_maps_to_signin_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Success", mfa_used="Yes")])
        assert len(evs) == 1
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_event_has_correct_source_and_ip(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(src_ip="5.6.7.8", user="bob")])
        assert evs[0].source == "aws_cloudtrail"
        assert evs[0].src_ip == "5.6.7.8"
        assert evs[0].user == "bob"

    def test_cursor_deduplication(self):
        c = self._make_connector()
        raw = self._make_raw_event(event_id="EVT001")
        evs1 = c._parse_events([raw])
        assert len(evs1) == 1
        # Same event_id now matches _last_event_id
        evs2 = c._parse_events([raw])
        assert len(evs2) == 0

    def test_unknown_login_status_skipped(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw_event(login_status="Pending")])
        assert len(evs) == 0

    def test_malformed_ct_json_skipped(self):
        c = self._make_connector()
        raw = {"EventId": "X", "EventName": "ConsoleLogin",
               "CloudTrailEvent": "not-json"}
        evs = c._parse_events([raw])
        assert len(evs) == 0

class TestAzureADParser:
    """_parse_events correctly maps Azure AD sign-in events to Event objects."""

    def _make_connector(self):
        from cnsl.cloud_identity import AzureADConnector
        return AzureADConnector({})

    def _make_raw(self, error_code=0, risk_state="none",
                  ip="1.2.3.4", user="alice@contoso.com"):
        return {
            "id":                 "SIGN001",
            "status":             {"errorCode": error_code},
            "riskState":          risk_state,
            "ipAddress":          ip,
            "userPrincipalName":  user,
            "authenticationRequirement": "singleFactorAuthentication",
        }

    def test_success_maps_to_signin_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=0, risk_state="none")])
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_nonzero_error_maps_to_signin_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=50053)])
        assert evs[0].kind == CloudEventKind.SIGNIN_FAIL

    def test_mfa_error_codes_map_to_mfa_fail(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        for code in (50074, 50079, 50076):
            evs = c._parse_events([self._make_raw(error_code=code)])
            assert evs[0].kind == CloudEventKind.MFA_FAIL, f"code {code} should map to MFA_FAIL"

    def test_risky_state_maps_to_risky_signin(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(risk_state="atRisk")])
        assert evs[0].kind == CloudEventKind.RISKY_SIGNIN

    def test_dismissed_risk_treated_as_success(self):
        from cnsl.cloud_identity import CloudEventKind
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(error_code=0, risk_state="dismissed")])
        assert evs[0].kind == CloudEventKind.SIGNIN_SUCCESS

    def test_event_has_correct_source_and_ip(self):
        c = self._make_connector()
        evs = c._parse_events([self._make_raw(ip="9.8.7.6", user="bob@corp.com")])
        assert evs[0].source == "azure_ad"
        assert evs[0].src_ip == "9.8.7.6"
        assert evs[0].user == "bob@corp.com"

class TestSigV4Signing:
    """AWS Signature Version 4 helper produces correct output shape."""

    def test_build_sigv4_headers_returns_required_keys(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            payload='{"test": 1}', target="CloudTrail.LookupEvents",
        )
        assert "Authorization" in hdrs
        assert "X-Amz-Date" in hdrs
        assert "X-Amz-Target" in hdrs
        assert "Content-Type" in hdrs

    def test_authorization_header_starts_with_aws4_hmac_sha256(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload="{}", target="CT.Lookup",
        )
        assert hdrs["Authorization"].startswith("AWS4-HMAC-SHA256 ")

    def test_different_payloads_produce_different_signatures(self):
        from cnsl.cloud_identity import build_sigv4_headers
        hdrs1 = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload='{"a": 1}', target="CT.Lookup",
        )
        hdrs2 = build_sigv4_headers(
            method="POST", host="cloudtrail.us-east-1.amazonaws.com",
            region="us-east-1", service="cloudtrail",
            access_key="AKID", secret_key="secret",
            payload='{"b": 2}', target="CT.Lookup",
        )
        assert hdrs1["Authorization"] != hdrs2["Authorization"]
