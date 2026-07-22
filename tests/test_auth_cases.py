"""
tests/test_auth_cases.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_auth_cases.py -v
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
import asyncio as _asyncio


class TestTOTPHelpers:
    """Low-level TOTP helper functions."""

    def test_generate_secret_is_base32(self):
        from cnsl.auth import generate_totp_secret
        import base64
        secret = generate_totp_secret()
        # Should not raise — valid base32
        base64.b32decode(secret)
        assert len(secret) >= 16

    def test_verify_totp_correct_code(self):
        import pyotp
        from cnsl.auth import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        code   = pyotp.TOTP(secret).now()
        assert verify_totp(secret, code)

    def test_verify_totp_wrong_code(self):
        from cnsl.auth import generate_totp_secret, verify_totp
        secret = generate_totp_secret()
        assert not verify_totp(secret, "000000")

    def test_verify_totp_empty_inputs(self):
        from cnsl.auth import verify_totp
        assert not verify_totp("", "123456")
        assert not verify_totp("SECRET", "")

    def test_get_totp_uri_format(self):
        from cnsl.auth import generate_totp_secret, get_totp_uri
        secret = generate_totp_secret()
        uri    = get_totp_uri(secret, "admin")
        assert uri.startswith("otpauth://totp/CNSL")
        assert "admin" in uri
        assert secret in uri

class TestBackupCodes:
    """Backup code generation and verification."""

    def test_generates_eight_codes(self):
        from cnsl.auth import generate_backup_codes
        plain, hashed = generate_backup_codes()
        assert len(plain) == 8
        assert len(hashed) == 8

    def test_codes_formatted_with_dash(self):
        from cnsl.auth import generate_backup_codes
        plain, _ = generate_backup_codes()
        for code in plain:
            assert "-" in code
            assert len(code) == 9   # XXXX-XXXX

    def test_backup_code_matches(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        matched, remaining = verify_backup_code(plain[3], hashed)
        assert matched
        assert len(remaining) == 7

    def test_backup_code_single_use(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        _, remaining = verify_backup_code(plain[0], hashed)
        matched2, _ = verify_backup_code(plain[0], remaining)
        assert not matched2

    def test_invalid_code_no_match(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        _, hashed = generate_backup_codes()
        matched, remaining = verify_backup_code("0000-0000", hashed)
        assert not matched
        assert len(remaining) == 8   # unchanged

    def test_case_insensitive_match(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        matched, _ = verify_backup_code(plain[0].lower(), hashed)
        assert matched

    def test_dash_optional(self):
        from cnsl.auth import generate_backup_codes, verify_backup_code
        plain, hashed = generate_backup_codes()
        no_dash = plain[0].replace("-", "")
        matched, _ = verify_backup_code(no_dash, hashed)
        assert matched

class TestAuthManager2FA:
    """AuthManager 2FA setup, confirm, verify, and disable flows."""

    def _make_auth(self):
        import bcrypt
        from cnsl.auth import AuthManager
        pw_hash = bcrypt.hashpw(b"testpass", bcrypt.gensalt()).decode()
        cfg = {"auth": {"enabled": True,
                        "secret_key": "testsecret_padded_to_32bytes_ok!",
                        "users": {"testuser": {"password_hash": pw_hash, "role": "admin"}}}}
        return AuthManager(cfg)

    def test_login_no_2fa_returns_three_tuple(self):
        auth = self._make_auth()
        token, err, needs_2fa = auth.login("testuser", "testpass")
        assert token is not None
        assert err is None
        assert needs_2fa is False

    def test_setup_confirm_full_flow(self):
        import pyotp
        auth = self._make_auth()
        # Setup
        uri, err = auth.setup_2fa("testuser")
        assert err is None
        assert "otpauth" in uri
        # Extract secret from URI and generate valid code
        secret = uri.split("secret=")[1].split("&")[0]
        code   = pyotp.TOTP(secret).now()
        # Confirm
        backup_codes, err = auth.confirm_2fa("testuser", code)
        assert err is None
        assert len(backup_codes) == 8

    def test_login_with_2fa_enabled_returns_partial(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        # Login should now require 2FA
        token, err, needs_2fa = auth.login("testuser", "testpass")
        assert needs_2fa is True
        assert err is None

    def test_verify_2fa_with_valid_otp(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        code  = pyotp.TOTP(secret).now()
        full_token, err = auth.verify_2fa(partial, code)
        assert err is None
        assert full_token is not None

    def test_verify_2fa_wrong_code_fails(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        _, err = auth.verify_2fa(partial, "000000")
        assert err is not None

    def test_verify_2fa_with_backup_code(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        backup_codes, _ = auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        full_token, err = auth.verify_2fa(partial, backup_codes[0])
        assert err is None
        assert full_token is not None

    def test_partial_token_rejected_by_verify_token(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        partial, _, _ = auth.login("testuser", "testpass")
        payload, err = auth.verify_token(partial)
        assert payload is None
        assert "2FA" in err or "partial" in err.lower()

    def test_disable_2fa_requires_correct_password(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        err = auth.disable_2fa("testuser", "wrongpass")
        assert err is not None

    def test_disable_2fa_success(self):
        import pyotp
        auth = self._make_auth()
        uri, _ = auth.setup_2fa("testuser")
        secret = uri.split("secret=")[1].split("&")[0]
        auth.confirm_2fa("testuser", pyotp.TOTP(secret).now())
        err = auth.disable_2fa("testuser", "testpass")
        assert err is None
        status = auth.get_2fa_status("testuser")
        assert status["enabled"] is False

    def test_get_2fa_status(self):
        auth = self._make_auth()
        status = auth.get_2fa_status("testuser")
        assert status["enabled"] is False
        assert status["backup_codes_left"] == 0
        assert status["pyotp_available"] is True



# v1.4.0 — Case Management

class TestCaseManagerCreate:
    def test_auto_title_brute_force(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(reasons=["brute_force: 9 fails"]))
        assert "Brute" in title and "1.2.3.4" in title

    def test_auto_title_country_block(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(ip="5.6.7.8", reasons=["country_block: China (CN)"]))
        assert "Country" in title

    def test_auto_title_fallback(self):
        from cnsl.cases import _auto_title
        title = _auto_title(_det(ip="9.9.9.9", reasons=["unknown_xyz"]))
        assert "9.9.9.9" in title

    def test_create_from_incident(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(
                _det(), geo={"country": "US", "isp": "Linode"})
            assert case_id is not None
            case = await cm.get(case_id)
            assert case["src_ip"] == "1.2.3.4"
            assert case["status"] == "open"
            assert case["severity"] == "HIGH"
            assert case["country"] == "US"
        _asyncio.run(_run())

    def test_create_manual(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_manual(
                title="Test case", severity="MEDIUM",
                src_ip="2.2.2.2", created_by="admin")
            case = await cm.get(case_id)
            assert case["title"] == "Test case"
            assert case["created_by"] == "admin"
        _asyncio.run(_run())

class TestCaseManagerStatus:
    def test_valid_status_update(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.update_status(case_id, "investigating", actor="alice")
            assert err is None
            assert (await cm.get(case_id))["status"] == "investigating"
        _asyncio.run(_run())

    def test_invalid_status_returns_error(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.update_status(case_id, "invalid_status")
            assert err is not None
        _asyncio.run(_run())

    def test_status_change_creates_system_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            await cm.update_status(case_id, "closed", actor="bob")
            notes = (await cm.get(case_id))["notes"]
            assert any("closed" in n["body"] for n in notes)
        _asyncio.run(_run())

    def test_all_valid_statuses_accepted(self):
        from cnsl.cases import VALID_STATUSES
        assert {"open", "investigating", "closed", "false_positive"} == VALID_STATUSES

class TestCaseManagerNotes:
    def test_add_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="3.3.3.3"))
            err = await cm.add_note(case_id, author="alice", body="Confirmed attacker")
            assert err is None
            notes = (await cm.get(case_id))["notes"]
            analyst = [n for n in notes if n["author"] == "alice"]
            assert len(analyst) == 1
            assert analyst[0]["body"] == "Confirmed attacker"
        _asyncio.run(_run())

    def test_empty_note_returns_error(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det())
            err = await cm.add_note(case_id, author="alice", body="   ")
            assert err is not None
        _asyncio.run(_run())

    def test_note_nonexistent_case(self):
        async def _run():
            cm = await _make_cm()
            err = await cm.add_note(99999, author="alice", body="test")
            assert err is not None
        _asyncio.run(_run())

class TestCaseManagerAssign:
    def test_assign_creates_note(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="4.4.4.4"))
            err = await cm.assign(case_id, "alice", actor="admin")
            assert err is None
            case = await cm.get(case_id)
            assert case["assigned_to"] == "alice"
            assert any("alice" in n["body"] for n in case["notes"])
        _asyncio.run(_run())

    def test_unassign(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="4.4.4.4"))
            await cm.assign(case_id, "alice")
            err = await cm.assign(case_id, None, actor="admin")
            assert err is None
            assert (await cm.get(case_id))["assigned_to"] is None
        _asyncio.run(_run())

class TestCaseManagerList:
    def test_list_all_cases(self):
        async def _run():
            cm = await _make_cm()
            for i in range(3):
                await cm.create_from_incident(_det(ip=f"1.2.3.{i}"))
            assert len(await cm.list_cases()) == 3
        _asyncio.run(_run())

    def test_filter_by_status(self):
        async def _run():
            cm = await _make_cm()
            for i in range(3):
                case_id = await cm.create_from_incident(_det(ip=f"5.5.5.{i}"))
                if i == 0:
                    await cm.update_status(case_id, "closed")
            assert len(await cm.list_cases(status="open")) == 2
        _asyncio.run(_run())

    def test_stats(self):
        async def _run():
            cm = await _make_cm()
            await cm.create_from_incident(_det(ip="6.6.6.6"))
            s = await cm.stats()
            assert s["total"] == 1
            assert s["open"] == 1
            assert s["high"] == 1
        _asyncio.run(_run())

class TestCaseManagerDelete:
    def test_delete_removes_case_and_notes(self):
        async def _run():
            cm = await _make_cm()
            case_id = await cm.create_from_incident(_det(ip="7.7.7.7"))
            await cm.add_note(case_id, "admin", "some note")
            err = await cm.delete(case_id)
            assert err is None
            assert await cm.get(case_id) is None
        _asyncio.run(_run())

class TestCaseRBAC:
    def test_viewer_has_cases_read(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("viewer", Perm.CASES_READ)

    def test_viewer_cannot_write_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert not RBAC().can("viewer", Perm.CASES_WRITE)

    def test_analyst_can_write_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("analyst", Perm.CASES_WRITE)

    def test_analyst_cannot_delete_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert not RBAC().can("analyst", Perm.CASES_DELETE)

    def test_admin_can_delete_cases(self):
        from cnsl.rbac import RBAC, Perm
        assert RBAC().can("admin", Perm.CASES_DELETE)


# v1.5.0 — Alert Rule Engine
