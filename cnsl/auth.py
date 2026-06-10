"""
cnsl/auth.py — JWT-based authentication for the dashboard.

Features:
  - Login with username/password (bcrypt hashed, stored in config)
  - JWT access token (default: 8h expiry)
  - Refresh token (default: 7d expiry)
  - Token blacklist (logout support)
  - Brute-force protection on login endpoint (5 attempts / 60s)
  - Default credentials: admin / cnsl-change-me  (forced change on first login)
  - TOTP 2FA (Google Authenticator / Authy compatible)
    - Per-user enable/disable
    - 8 single-use backup codes
    - QR code URI for authenticator app setup

Config example:
  "auth": {
    "enabled": true,
    "secret_key": "change-this-to-a-random-64-char-string",
    "access_token_expire_hours": 8,
    "refresh_token_expire_days": 7,
    "users": {
      "admin": {
        "password_hash": "$2b$12$...",   <- bcrypt hash
        "role": "admin",
        "must_change_password": false,
        "totp_secret": null,             <- set by 2FA setup flow
        "totp_enabled": false,
        "totp_backup_codes": []          <- hashed backup codes
      }
    }
  }

Generate a password hash:
  python -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple
import re

# TOTP (pyotp optional — graceful degradation if not installed)
try:
    import pyotp as _pyotp
    _HAS_PYOTP = True
except ImportError:
    _HAS_PYOTP = False


# Lightweight JWT (no external dependency beyond stdlib)
# Falls back to PyJWT if available for better compatibility


try:
    import jwt as _pyjwt
    _HAS_PYJWT = True
except ImportError:
    _HAS_PYJWT = False

import base64


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def _sign_jwt(payload: Dict, secret: str) -> str:
    """Create a signed JWT token (HS256)."""
    if _HAS_PYJWT:
        return _pyjwt.encode(payload, secret, algorithm="HS256")

    header  = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body    = _b64url_encode(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()
    sig     = hmac.new(secret.encode(), message, hashlib.sha256).digest()
    return f"{header}.{body}.{_b64url_encode(sig)}"


def _verify_jwt(token: str, secret: str) -> Optional[Dict]:
    """Verify and decode a JWT. Returns payload or None."""
    try:
        if _HAS_PYJWT:
            return _pyjwt.decode(token, secret, algorithms=["HS256"])

        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        message  = f"{header}.{body}".encode()
        expected = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None



# Password hashing (bcrypt preferred, fallback to PBKDF2)


try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False


def hash_password(password: str) -> str:
    if _HAS_BCRYPT:
        return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:{salt}:{h.hex()}"




BCRYPT_REGEX = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")

def verify_password(password: str, hashed: str) -> bool:
    try:
        if hashed.startswith("$2"):
            if not _HAS_BCRYPT:
                return False

            #  critical fix: validate 
            if not BCRYPT_REGEX.match(hashed):
                return False

            return _bcrypt.checkpw(password.encode(), hashed.encode())

        if hashed.startswith("pbkdf2:"):
            parts = hashed.split(":", 2)
            if len(parts) != 3:
                return False
            _, salt, stored = parts
            h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
            return hmac.compare_digest(h.hex(), stored)

    except Exception:
        return False

    return False


#  TOTP / 2FA helpers 

TOTP_ISSUER       = "CNSL"
BACKUP_CODE_COUNT = 8


def totp_available() -> bool:
    """True if pyotp is installed."""
    return _HAS_PYOTP


def generate_totp_secret() -> str:
    """Generate a new random TOTP secret (base32)."""
    if not _HAS_PYOTP:
        raise RuntimeError("pyotp is not installed. Run: pip install pyotp")
    return _pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    """Return an otpauth:// URI for QR code generation."""
    if not _HAS_PYOTP:
        raise RuntimeError("pyotp is not installed.")
    totp = _pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=TOTP_ISSUER)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows ±1 window (30s drift tolerance)."""
    if not _HAS_PYOTP or not secret or not code:
        return False
    try:
        totp = _pyotp.TOTP(secret)
        return totp.verify(code.strip(), valid_window=1)
    except Exception:
        return False


def generate_backup_codes() -> Tuple[List[str], List[str]]:
    """
    Generate 8 single-use backup codes.
    Returns (plaintext_codes, hashed_codes).
    plaintext_codes shown to the user once, never stored.
    hashed_codes stored in the user record.
    """
    codes     = [secrets.token_hex(4).upper() for _ in range(BACKUP_CODE_COUNT)]
    formatted = [f"{c[:4]}-{c[4:]}" for c in codes]   # e.g. "A1B2-C3D4"
    hashed    = [_hash_backup_code(c) for c in formatted]
    return formatted, hashed


def _hash_backup_code(code: str) -> str:
    """SHA-256 hash of backup code (normalised — dashes/spaces stripped, uppercase)."""
    normalised = code.replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalised.encode()).hexdigest()


def verify_backup_code(code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if code matches any stored hash.
    Returns (matched, remaining_hashes_with_used_one_removed).
    Backup codes are single-use — matched hash is removed.
    """
    normalised = code.replace("-", "").replace(" ", "").upper()
    candidate  = hashlib.sha256(normalised.encode()).hexdigest()
    remaining  = list(hashed_codes)
    for h in hashed_codes:
        if hmac.compare_digest(candidate, h):
            remaining.remove(h)
            return True, remaining
    return False, hashed_codes



# Default admin password (used when no users configured)


DEFAULT_ADMIN_USER     = "admin"
DEFAULT_ADMIN_PASSWORD = "cnsl-change-me"
_DEFAULT_HASH          = hash_password(DEFAULT_ADMIN_PASSWORD)



# Auth manager


class AuthManager:
    """
    Handles login, token issuance, validation, and logout.

    Usage:
        auth = AuthManager(cfg)
        token, err = auth.login("admin", "password")
        payload, err = auth.verify_token(token)
        auth.logout(token)
    """

    def __init__(self, cfg: Dict[str, Any]):
        auth_cfg = cfg.get("auth", {})

        self.enabled = bool(auth_cfg.get("enabled", False))
        self.secret  = auth_cfg.get("secret_key") or secrets.token_hex(32)
        self.access_expire_hours  = int(auth_cfg.get("access_token_expire_hours", 8))
        self.refresh_expire_days  = int(auth_cfg.get("refresh_token_expire_days", 7))

        # Load users from config
        self._users: Dict[str, Dict] = {}
        for username, udata in auth_cfg.get("users", {}).items():
            self._users[username] = udata

        # Default admin if no users configured
        if not self._users:
            self._users[DEFAULT_ADMIN_USER] = {
                "password_hash":       _DEFAULT_HASH,
                "role":                "admin",
                "must_change_password": True,
            }

        # Token blacklist (logged-out tokens)
        self._blacklist: Set[str] = set()

        # Login rate limiting: ip -> [(timestamp), ...]
        self._login_attempts: Dict[str, list] = defaultdict(list)
        self._max_attempts = 5
        self._lockout_sec  = 60

    #  Login 

    def login(
        self, username: str, password: str, client_ip: str = "unknown"
    ) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Attempt login. Returns (token_or_partial, error, needs_2fa).

        Outcomes:
          - Password wrong  → (None, error_msg, False)
          - 2FA enabled     → (partial_token, None, True)
          - 2FA not enabled → (full_access_token, None, False)
        """
        if self._is_rate_limited(client_ip):
            return None, "Too many login attempts. Try again in 60 seconds.", False

        self._record_attempt(client_ip)

        user = self._users.get(username)
        if not user:
            return None, "Invalid credentials.", False

        if not verify_password(password, user["password_hash"]):
            return None, "Invalid credentials.", False

        self._login_attempts.pop(client_ip, None)

        totp_enabled = bool(user.get("totp_enabled") and user.get("totp_secret"))

        if totp_enabled:
            partial = {
                "sub":     username,
                "role":    user.get("role", "viewer"),
                "mcp":     user.get("must_change_password", False),
                "partial": True,
                "iat":     int(time.time()),
                "exp":     int(time.time()) + 300,
                "jti":     secrets.token_hex(8),
            }
            return _sign_jwt(partial, self.secret), None, True

        return self._issue_full_token(username, user), None, False

    def verify_2fa(
        self, partial_token: str, code: str, client_ip: str = "unknown"
    ) -> Tuple[Optional[str], Optional[str]]:
        """Complete 2FA. Accepts TOTP or backup code. Returns (token, error)."""
        payload = _verify_jwt(partial_token, self.secret)
        if payload is None or not payload.get("partial"):
            return None, "Invalid or expired 2FA session."
        username = payload.get("sub", "")
        user     = self._users.get(username)
        if not user:
            return None, "User not found."
        secret = user.get("totp_secret", "")
        if verify_totp(secret, code):
            return self._issue_full_token(username, user), None
        backup_hashes = user.get("totp_backup_codes", [])
        matched, remaining = verify_backup_code(code, backup_hashes)
        if matched:
            user["totp_backup_codes"] = remaining
            return self._issue_full_token(username, user), None
        return None, "Invalid authentication code."

    def setup_2fa(self, username: str) -> Tuple[Optional[str], Optional[str]]:
        """Generate pending TOTP secret. Returns (otpauth_uri, error)."""
        if not _HAS_PYOTP:
            return None, "pyotp not installed. Run: pip install pyotp"
        user = self._users.get(username)
        if not user:
            return None, "User not found."
        secret = generate_totp_secret()
        user["totp_secret_pending"] = secret
        return get_totp_uri(secret, username), None

    def confirm_2fa(
        self, username: str, code: str
    ) -> Tuple[Optional[List[str]], Optional[str]]:
        """Confirm setup with first OTP. Returns (backup_codes, error)."""
        user = self._users.get(username)
        if not user:
            return None, "User not found."
        pending = user.get("totp_secret_pending")
        if not pending:
            return None, "No pending 2FA setup. Call setup_2fa first."
        if not verify_totp(pending, code):
            return None, "Invalid code. Check your authenticator app and try again."
        plain_codes, hashed_codes = generate_backup_codes()
        user["totp_secret"]       = pending
        user["totp_enabled"]      = True
        user["totp_backup_codes"] = hashed_codes
        user.pop("totp_secret_pending", None)
        return plain_codes, None

    def disable_2fa(self, username: str, password: str) -> Optional[str]:
        """Disable 2FA. Requires password re-confirmation. Returns None on success."""
        user = self._users.get(username)
        if not user:
            return "User not found."
        if not verify_password(password, user["password_hash"]):
            return "Incorrect password."
        user["totp_enabled"]      = False
        user["totp_secret"]       = None
        user["totp_backup_codes"] = []
        user.pop("totp_secret_pending", None)
        return None

    def get_2fa_status(self, username: str) -> Dict:
        """Return 2FA status for a user."""
        user         = self._users.get(username, {})
        enabled      = bool(user.get("totp_enabled") and user.get("totp_secret"))
        backup_count = len(user.get("totp_backup_codes", []))
        return {
            "enabled":           enabled,
            "backup_codes_left": backup_count,
            "pyotp_available":   _HAS_PYOTP,
        }

    def _issue_full_token(self, username: str, user: Dict) -> str:
        payload = {
            "sub":  username,
            "role": user.get("role", "viewer"),
            "mcp":  user.get("must_change_password", False),
            "iat":  int(time.time()),
            "exp":  int(time.time()) + self.access_expire_hours * 3600,
            "jti":  secrets.token_hex(8),
        }
        return _sign_jwt(payload, self.secret)

    #  Verify 

    def verify_token(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Returns (payload, None) or (None, error). Rejects partial tokens."""
        if not token:
            return None, "No token provided."
        if token in self._blacklist:
            return None, "Token has been revoked."
        payload = _verify_jwt(token, self.secret)
        if payload is None:
            return None, "Invalid or expired token."
        if payload.get("partial"):
            return None, "2FA not completed."
        return payload, None

    #  Logout 

    def logout(self, token: str) -> None:
        self._blacklist.add(token)
        if len(self._blacklist) > 10000:
            self._blacklist = set(list(self._blacklist)[-5000:])

    #  Rate limiting 

    def _is_rate_limited(self, ip: str) -> bool:
        cutoff = time.time() - self._lockout_sec
        recent = [t for t in self._login_attempts[ip] if t > cutoff]
        self._login_attempts[ip] = recent
        return len(recent) >= self._max_attempts

    def _record_attempt(self, ip: str) -> None:
        self._login_attempts[ip].append(time.time())

    #  Helpers 

    def is_default_password(self) -> bool:
        """True if still using the default admin password."""
        user = self._users.get(DEFAULT_ADMIN_USER, {})
        return verify_password(DEFAULT_ADMIN_PASSWORD, user.get("password_hash", ""))

    def extract_token(self, request_headers: Dict) -> Optional[str]:
        """Extract Bearer token from Authorization header."""
        auth_header = request_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:]
        return None