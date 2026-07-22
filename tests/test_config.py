"""
tests/test_config.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_config.py -v
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


class TestConfig:
    def test_defaults_loaded(self):
        # DEFAULT_CONFIG always has the built-in defaults regardless of system config
        assert DEFAULT_CONFIG["thresholds"]["fails_threshold"] == 8
        assert DEFAULT_CONFIG["actions"]["dry_run"] is True
        assert "127.0.0.1" in DEFAULT_CONFIG["allowlist"]

    def test_safe_int(self):
        assert safe_int("8", 0) == 8
        assert safe_int("bad", 5) == 5
        assert safe_int(None, 3) == 3

    def test_load_config_merges_with_defaults(self):
        # load_config() may load /etc/cnsl/config.json if it exists —
        # verify it still returns a complete config with all required keys
        cfg = load_config(None)
        assert "thresholds" in cfg
        assert "fails_threshold" in cfg["thresholds"]
        assert "actions" in cfg
        assert "allowlist" in cfg


# Detector tests

class TestValidationErrorClass:
    """ValidationError dataclass has correct fields."""

    def test_has_path_message_level(self):
        from cnsl.validator import ValidationError
        e = ValidationError(path="auth.secret_key", message="required")
        assert e.path == "auth.secret_key"
        assert e.message == "required"
        assert e.level == "error"

    def test_warning_level(self):
        from cnsl.validator import ValidationError
        w = ValidationError(path="redis.host", message="needed", level="warning")
        assert w.level == "warning"

    def test_str_includes_path_and_message(self):
        from cnsl.validator import ValidationError
        e = ValidationError(path="auth.secret_key", message="too short")
        assert "auth.secret_key" in str(e)
        assert "too short" in str(e)

class TestValidateConfigClean:
    """A clean minimal config produces no errors."""

    def test_empty_config_no_errors(self):
        from cnsl.validator import validate_config
        # Empty config should have no errors (everything optional)
        errs = [e for e in validate_config({}) if e.level == "error"]
        assert errs == []

    def test_valid_minimal_config_clean(self):
        from cnsl.validator import validate_config
        cfg = {
            "authlog_path": "/var/log/auth.log",
            "actions": {"dry_run": True, "block_duration_sec": 900},
            "allowlist": ["127.0.0.1"],
        }
        errs = [e for e in validate_config(cfg) if e.level == "error"]
        assert errs == []

class TestValidateConfigAuth:
    """auth.secret_key validation."""

    def test_missing_secret_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_short_secret_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True, "secret_key": "tooshort"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_insecure_default_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True, "secret_key": "cnsl-secret"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" in paths

    def test_valid_secret_key_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": True,
                         "secret_key": "a" * 32}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" not in paths

    def test_auth_disabled_no_secret_required(self):
        from cnsl.validator import validate_config
        cfg = {"auth": {"enabled": False}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "auth.secret_key" not in paths

class TestValidateConfigAllowlist:
    """allowlist IP/CIDR validation."""

    def test_valid_ip_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": ["1.2.3.4", "10.0.0.0/8"]}
        errs = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("allowlist" in e.path for e in errs)

    def test_invalid_ip_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": ["not-an-ip"]}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("allowlist" in p for p in paths)

    def test_allowlist_not_list_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"allowlist": "1.2.3.4"}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "allowlist" in paths

class TestValidateConfigNotifications:
    """notifications block validation."""

    def test_telegram_missing_token_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"telegram": {"enabled": True, "chat_id": "123"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "notifications.telegram.bot_token" in paths

    def test_telegram_missing_chat_id_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"telegram": {"enabled": True,
                                               "bot_token": "abc"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "notifications.telegram.chat_id" in paths

    def test_invalid_severity_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {"min_severity": "CRITICAL"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("min_severity" in p for p in paths)

    def test_invalid_digest_hour_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"notifications": {
            "daily_digest": {"enabled": True, "hour": 25}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("hour" in p for p in paths)

class TestValidateConfigStore:
    """store.backend validation."""

    def test_invalid_backend_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "mongodb"}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("backend" in p for p in paths)

    def test_postgresql_without_dsn_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "postgresql", "dsn": ""}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "store.dsn" in paths

    def test_postgresql_with_valid_dsn_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "postgresql",
                          "dsn": "postgresql://user:pass@localhost/cnsl"}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("store.dsn" in e.path for e in errors)

    def test_sqlite_backend_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"store": {"backend": "sqlite", "db_path": "/tmp/test.db"}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("store" in e.path for e in errors)

class TestValidateConfigML:
    """ml block validation."""

    def test_invalid_contamination_too_high(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.9}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "ml.contamination" in paths

    def test_invalid_contamination_zero(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.0}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "ml.contamination" in paths

    def test_valid_contamination_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"ml": {"enabled": True, "contamination": 0.05}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("contamination" in e.path for e in errors)

class TestValidateConfigSIEM:
    """siem connectors block validation."""

    def test_splunk_missing_url_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"splunk": {"enabled": True, "token": "abc"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.splunk.hec_url" in paths

    def test_splunk_missing_token_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"splunk": {"enabled": True,
                                    "hec_url": "https://splunk.example.com"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.splunk.token" in paths

    def test_webhook_missing_url_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"siem": {"webhook": {"enabled": True}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "siem.webhook.url" in paths

class TestValidateConfigCloudIdentity:
    """cloud_identity block validation."""

    def test_aws_missing_key_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"cloud_identity": {"enabled": True,
                                   "aws": {"enabled": True,
                                           "secret_access_key": "secret"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "cloud_identity.aws.access_key_id" in paths

    def test_azure_missing_tenant_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"cloud_identity": {"enabled": True,
                                   "azure_ad": {"enabled": True,
                                                "client_id": "abc",
                                                "client_secret": "xyz"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "cloud_identity.azure_ad.tenant_id" in paths

class TestValidateConfigOT:
    """OT/IoT config block validation."""

    def test_invalid_protocol_is_warning(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "log_sources": {"profinet": "/var/log/profinet.log"}}}
        warns = [e for e in validate_config(cfg) if e.level == "warning"]
        assert any("profinet" in e.path for e in warns)

    def test_invalid_trusted_ip_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "trusted_ips": ["not-an-ip"]}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("trusted_ips" in p for p in paths)

    def test_valid_ot_config_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"ot": {"enabled": True,
                       "log_sources": {"modbus": "/var/log/modbus.log"},
                       "trusted_ips": ["192.168.100.10"]}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("ot" in e.path for e in errors)

class TestValidateConfigRules:
    """rules block override validation."""

    def test_invalid_severity_in_rule_override(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"severity": "CRITICAL"}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("severity" in p for p in paths)

    def test_invalid_threshold_in_rule_override(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"threshold": -1}}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert any("threshold" in p for p in paths)

    def test_valid_rule_override_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"rules": {"ssh.brute_force": {"threshold": 5, "severity": "HIGH"}}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("ssh.brute_force" in e.path for e in errors)

class TestValidateConfigDashboard:
    """dashboard host/port validation."""

    def test_invalid_port_is_error(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"port": 80}}
        paths = [e.path for e in validate_config(cfg) if e.level == "error"]
        assert "dashboard.port" in paths

    def test_open_host_is_warning(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"host": "0.0.0.0", "port": 8765}}
        warns = [e for e in validate_config(cfg) if e.level == "warning"]
        assert any("dashboard.host" in e.path for e in warns)

    def test_valid_port_no_error(self):
        from cnsl.validator import validate_config
        cfg = {"dashboard": {"port": 8765}}
        errors = [e for e in validate_config(cfg) if e.level == "error"]
        assert not any("dashboard.port" in e.path for e in errors)

class TestValidateAndPrint:
    """validate_and_print returns True on valid config, False on invalid."""

    def test_returns_true_on_clean_config(self):
        from cnsl.validator import validate_and_print
        result = validate_and_print({})
        assert result is True

    def test_returns_false_on_invalid_config(self):
        from cnsl.validator import validate_and_print
        result = validate_and_print({"auth": {"enabled": True,
                                               "secret_key": "short"}})
        assert result is False

class TestCLIValidateConfigFlag:
    """--validate-config flag is registered in engine.py."""

    def test_flag_present_in_engine(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "--validate-config" in src
        assert "validate_and_print" in src

# v3.4.0 -- health check endpoint

class TestEmailNotifyConfig:
    """Email notification config section is present in DEFAULT_CONFIG and notify.py."""

    def test_default_config_has_notifications(self):
        from cnsl.config import DEFAULT_CONFIG
        n = DEFAULT_CONFIG.get("notifications", {})
        assert "telegram" in n
        assert "discord" in n
        assert "slack" in n

    def test_notifier_email_skipped_when_disabled(self):
        """Notifier.send must not crash when email is configured but disabled."""
        import asyncio
        from cnsl.notify import Notifier
        from cnsl.models import Detection

        cfg = {
            "notifications": {
                "min_severity": "LOW",
                "email": {
                    "enabled": False,
                    "smtp_host": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "u",
                    "password": "p",
                    "to": ["admin@example.com"],
                },
            }
        }
        notifier = Notifier(cfg)
        d = Detection(src_ip="1.2.3.4", severity="HIGH",
                      reasons=["test"], fail_count=1,
                      uniq_users=1, window_sec=60)
        # Must not raise
        asyncio.run(notifier.send(d, None))

    def test_smtp_send_swallows_connection_errors(self):
        """_smtp_send must not raise even if the SMTP server is unreachable."""
        from cnsl.notify import _smtp_send
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "test"
        msg["From"] = "a@example.com"
        msg["To"] = "b@example.com"

        # 127.0.0.1:1 — nothing listening, ConnectionRefusedError expected internally
        _smtp_send(
            host="127.0.0.1", port=1,
            username="", password="",
            from_addr="a@example.com",
            to_addrs=["b@example.com"],
            msg=msg,
            use_tls=False, use_ssl=False,
        )
        # If we reach here the function swallowed the error correctly


# v1.3.0 — TOTP 2FA

class TestNoDuplicateFunctions:
    """log_sources.py must have exactly one definition of each function."""

    def _src(self):
        from pathlib import Path
        return (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
                ).read_text(encoding="utf-8")

    def test_parse_mysql_defined_once(self):
        assert self._src().count("def parse_mysql(") == 1

    def test_parse_ufw_defined_once(self):
        assert self._src().count("def parse_ufw(") == 1

    def test_parse_syslog_defined_once(self):
        assert self._src().count("def parse_syslog(") == 1

    def test_tail_log_file_defined_once(self):
        assert self._src().count("async def tail_log_file(") == 1

    def test_get_log_tasks_defined_once(self):
        assert self._src().count("def get_log_tasks(") == 1
