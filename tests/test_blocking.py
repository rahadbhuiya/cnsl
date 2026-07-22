"""
tests/test_blocking.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_blocking.py -v
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


class TestBlockerIPv6:
    """Blocker must route IPv6 addresses to ip6tables / a separate ipset,
    since iptables silently rejects (or mis-handles) IPv6 -s arguments."""

    def _make_blocker(self, backend="iptables"):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import Blocker
        logger = JsonLogger("/dev/null", verbose=False)
        return Blocker(dry_run=False, backend=backend, chain="INPUT",
                        ipset_name="cnsl_blocklist", block_duration_sec=10,
                        allowlist=set(), logger=logger)

    def test_iptables_bin_picks_ip6tables_for_ipv6(self):
        from cnsl.blocker import _iptables_bin
        assert _iptables_bin("2001:db8::1") == "ip6tables"
        assert _iptables_bin("45.33.32.1") == "iptables"

    def test_ipset_name_suffixes_v6(self):
        from cnsl.blocker import _ipset_name_for_ip
        assert _ipset_name_for_ip("cnsl_blocklist", "2001:db8::1") == "cnsl_blocklist_v6"
        assert _ipset_name_for_ip("cnsl_blocklist", "45.33.32.1") == "cnsl_blocklist"

    def test_execute_block_uses_ip6tables_for_ipv6(self, monkeypatch):
        blocker = self._make_blocker("iptables")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            class R: pass
            return R()

        import cnsl.blocker as blocker_mod
        monkeypatch.setattr(blocker_mod.subprocess, "run", fake_run)

        _run(
            blocker._execute_block("2001:db8::dead")
        )
        assert captured["cmd"][1] == "ip6tables"
        assert "2001:db8::dead" in captured["cmd"]

    def test_execute_block_uses_iptables_for_ipv4(self, monkeypatch):
        blocker = self._make_blocker("iptables")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            class R: pass
            return R()

        import cnsl.blocker as blocker_mod
        monkeypatch.setattr(blocker_mod.subprocess, "run", fake_run)

        _run(
            blocker._execute_block("45.33.32.1")
        )
        assert captured["cmd"][1] == "iptables"

    def test_execute_block_ipset_uses_v6_set_name(self, monkeypatch):
        blocker = self._make_blocker("ipset")
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            class R: pass
            return R()

        import cnsl.blocker as blocker_mod
        monkeypatch.setattr(blocker_mod.subprocess, "run", fake_run)

        _run(
            blocker._execute_block("2001:db8::dead")
        )
        assert "cnsl_blocklist_v6" in captured["cmd"]

    def test_ensure_ipset_creates_both_families(self, monkeypatch):
        from cnsl.logger import JsonLogger
        from cnsl.blocker import ensure_ipset
        import cnsl.blocker as blocker_mod

        commands = []

        def fake_run(cmd, **kwargs):
            commands.append(cmd)
            class R: pass
            return R()

        monkeypatch.setattr(blocker_mod.subprocess, "run", fake_run)
        logger = JsonLogger("/dev/null", verbose=False)

        ok = _run(
            ensure_ipset("cnsl_blocklist", logger)
        )
        assert ok is True
        joined = [" ".join(c) for c in commands]
        assert any("family inet " in c and "cnsl_blocklist" in c and "_v6" not in c
                    for c in joined)
        assert any("family inet6" in c and "cnsl_blocklist_v6" in c for c in joined)
        assert any(c.startswith("sudo ip6tables") for c in joined)

class TestHoneypotIPv6:
    """ActiveResponse honeypot actions must also be IPv6-aware."""

    def _make_response(self, honeypot_host="127.0.0.1"):
        from cnsl.honeypot import ActiveResponse
        from cnsl.logger import JsonLogger
        logger = JsonLogger("/dev/null", verbose=False)
        cfg = {"honeypot": {"honeypot_host": honeypot_host, "honeypot_port": 2222}}
        return ActiveResponse(cfg, logger)

    def test_drop_uses_ip6tables_for_ipv6(self, monkeypatch):
        ar = self._make_response()
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            class R: pass
            return R()

        import cnsl.honeypot as hp_mod
        monkeypatch.setattr(hp_mod.subprocess, "run", fake_run)

        _run(ar._drop("2001:db8::1"))
        assert captured["cmd"][1] == "ip6tables"

    def test_redirect_falls_back_to_drop_on_family_mismatch(self, monkeypatch):
        # honeypot_host is IPv4-only but attacker is IPv6 — DNAT can't cross
        # families, so this should fall back to a plain drop instead of
        # silently issuing a broken/no-op iptables command.
        ar = self._make_response(honeypot_host="127.0.0.1")
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            class R: pass
            return R()

        import cnsl.honeypot as hp_mod
        monkeypatch.setattr(hp_mod.subprocess, "run", fake_run)

        result = _run(
            ar._redirect_to_honeypot("2001:db8::dead")
        )
        assert result == "dropped"
        assert any(c[1] == "ip6tables" and "DROP" in c for c in captured)
        assert not any("DNAT" in c for c in captured)

    def test_redirect_uses_ip6tables_when_families_match(self, monkeypatch):
        ar = self._make_response(honeypot_host="2001:db8::abcd")
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            class R: pass
            return R()

        import cnsl.honeypot as hp_mod
        monkeypatch.setattr(hp_mod.subprocess, "run", fake_run)

        result = _run(
            ar._redirect_to_honeypot("2001:db8::dead")
        )
        assert result == "redirected"
        assert all(c[1] == "ip6tables" for c in captured)
