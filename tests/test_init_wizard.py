"""
tests/test_init_wizard.py -- the --init setup wizard's log-source
auto-detection, generated config validity, and fail-closed behavior
on a bad config (cnsl/engine.py: _run_init_wizard,
_detect_log_sources, _detect_authlog_path).

Run:
    pytest tests/test_init_wizard.py -v
"""

from __future__ import annotations

import io
import json
import sys
from unittest.mock import patch

from cnsl.engine import _detect_log_sources, _detect_authlog_path, _run_init_wizard
from cnsl.validator import validate_config


def _run_wizard_with_input(tmp_path, answers, config_name="cnsl.json", log_sources=None, authlog="/var/log/auth.log"):
    """Feed `answers` as sequential input() responses and return the written config dict, or None if nothing was written."""
    import pathlib
    out_path = str(tmp_path / config_name)
    full_answers = [out_path] + answers
    sys.stdin = io.StringIO("\n".join(full_answers) + "\n")
    try:
        with patch("cnsl.engine._detect_log_sources", return_value=log_sources or {}), \
             patch("cnsl.engine._detect_authlog_path", return_value=authlog):
            _run_init_wizard()
    finally:
        sys.stdin = sys.__stdin__
    p = pathlib.Path(out_path)
    if not p.exists():
        return None
    return json.loads(p.read_text())


class TestDetectLogSources:
    def test_no_common_paths_present_returns_empty(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: False)
        assert _detect_log_sources() == {}

    def test_detects_present_paths_only(self, monkeypatch):
        present = {"/var/log/nginx/access.log", "/var/log/ufw.log"}
        monkeypatch.setattr("os.path.exists", lambda p: p in present)
        found = _detect_log_sources()
        assert found == {"nginx": "/var/log/nginx/access.log", "ufw": "/var/log/ufw.log"}

    def test_first_matching_candidate_wins_per_source(self, monkeypatch):
        # apache has two candidate paths -- only the httpd one exists here.
        present = {"/var/log/httpd/access_log"}
        monkeypatch.setattr("os.path.exists", lambda p: p in present)
        found = _detect_log_sources()
        assert found == {"apache": "/var/log/httpd/access_log"}

    def test_all_common_sources_detected_when_all_present(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: True)
        found = _detect_log_sources()
        assert set(found.keys()) == {"nginx", "apache", "mysql", "ufw", "syslog"}


class TestDetectAuthlogPath:
    def test_prefers_debian_path_when_present(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: p == "/var/log/auth.log")
        assert _detect_authlog_path() == "/var/log/auth.log"

    def test_falls_back_to_rhel_path(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: p == "/var/log/secure")
        assert _detect_authlog_path() == "/var/log/secure"

    def test_debian_path_wins_when_both_present(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: True)
        assert _detect_authlog_path() == "/var/log/auth.log"

    def test_defaults_to_debian_path_when_neither_present(self, monkeypatch):
        monkeypatch.setattr("os.path.exists", lambda p: False)
        assert _detect_authlog_path() == "/var/log/auth.log"


class TestWizardEndToEnd:
    """
    Runs the real wizard function with input() fed via stdin -- these
    exercise the actual code path a user hits with `cnsl --init`, not
    just the detection helpers in isolation. Detection itself is
    mocked here (already covered above) so these focus on the
    answer-to-config-field wiring.
    """

    def test_minimal_answers_produce_a_valid_config(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""])
        assert cfg is not None
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert errors == []

    def test_generated_config_has_authlog_and_log_sources_keys(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""])
        assert cfg["authlog_path"] == "/var/log/auth.log"
        assert cfg["log_sources"] == {}

    def test_detected_sources_included_in_generated_config(self, tmp_path):
        cfg = _run_wizard_with_input(
            tmp_path, ["1.2.3.4", "", "", "", ""],
            log_sources={"nginx": "/var/log/nginx/access.log"},
        )
        assert cfg["log_sources"] == {"nginx": "/var/log/nginx/access.log"}

    def test_dry_run_no_disables_execute_false(self, tmp_path):
        """
        dry_run=false triggers validate_config()'s separate "must run
        as root" check (real iptables/ipset blocking needs it) -- mock
        geteuid so this test verifies the wizard wired the dry_run
        answer into the config correctly, independent of whether
        pytest itself happens to run as root.
        """
        from unittest.mock import patch
        with patch("os.geteuid", return_value=0, create=True):
            cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "n", "", "", ""])
        assert cfg is not None
        assert cfg["actions"]["dry_run"] is False

    def test_dashboard_declined_disables_auth(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "n", "", ""])
        assert cfg["auth"]["enabled"] is False

    def test_secret_key_is_random_and_long(self, tmp_path):
        cfg1 = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""], "a.json")
        cfg2 = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""], "b.json")
        assert len(cfg1["auth"]["secret_key"]) >= 32
        assert cfg1["auth"]["secret_key"] != cfg2["auth"]["secret_key"]

    def test_telegram_configured_when_token_and_chat_given(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "tok123", "chat456", ""])
        assert cfg["notifications"]["telegram"] == {
            "enabled": True, "bot_token": "tok123", "chat_id": "chat456",
        }

    def test_no_telegram_block_when_skipped(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""])
        assert "telegram" not in cfg["notifications"]

    def test_email_configured_when_smtp_host_given(self, tmp_path):
        answers = ["1.2.3.4", "", "", "", "smtp.example.com", "587", "user@example.com", "pw", "alert@example.com"]
        cfg = _run_wizard_with_input(tmp_path, answers)
        assert cfg["notifications"]["email"]["enabled"] is True
        assert cfg["notifications"]["email"]["smtp_host"] == "smtp.example.com"
        assert cfg["notifications"]["email"]["to"] == ["alert@example.com"]

    def test_allowlist_always_includes_localhost_and_own_ip(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["9.9.9.9", "", "", "", ""])
        assert "127.0.0.1" in cfg["allowlist"]
        assert "9.9.9.9" in cfg["allowlist"]

    def test_own_ip_defaults_to_localhost_when_blank(self, tmp_path):
        cfg = _run_wizard_with_input(tmp_path, ["", "", "", "", ""])
        assert cfg["allowlist"] == ["127.0.0.1", "127.0.0.1"]

    def test_config_not_written_when_validation_fails(self, tmp_path, capsys):
        """
        A forced validate_config() failure must prevent the file from
        being written -- tests the fail-closed guard around json.dump().
        """
        from cnsl.validator import ValidationError

        def _always_fails(cfg):
            return [ValidationError("fake.field", "forced failure for this test", level="error")]

        with patch("cnsl.validator.validate_config", _always_fails):
            cfg = _run_wizard_with_input(tmp_path, ["1.2.3.4", "", "", "", ""])
        assert cfg is None
        assert "was NOT written" in capsys.readouterr().out