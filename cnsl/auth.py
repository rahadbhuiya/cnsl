"""
cnsl/auth.py — JWT-based authentication for the dashboard.

Features:
  - Login with username/password (bcrypt hashed, stored in config)
  - JWT access token (default: 8h expiry)
  - Refresh token (default: 7d expiry)
  - Token blacklist (logout support)
  - Brute-force protection on login endpoint (5 attempts / 60s)
  - Default credentials: admin / cnsl-change-me  (forced change on first login)

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
        "must_change_password": false
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
from typing import Any, Dict, Optional, Set, Tuple
import re


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

    # ── Login ─────────────────────────────────────────────────────────────────

    def login(
        self, username: str, password: str, client_ip: str = "unknown"
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Attempt login. Returns (access_token, None) on success,
        or (None, error_message) on failure.
        """
        # Rate limit check
        if self._is_rate_limited(client_ip):
            return None, "Too many login attempts. Try again in 60 seconds."

        self._record_attempt(client_ip)

        user = self._users.get(username)
        if not user:
            return None, "Invalid credentials."

        if not verify_password(password, user["password_hash"]):
            return None, "Invalid credentials."

        # Success — clear attempts
        self._login_attempts.pop(client_ip, None)

        payload = {
            "sub":  username,
            "role": user.get("role", "viewer"),
            "mcp":  user.get("must_change_password", False),
            "iat":  int(time.time()),
            "exp":  int(time.time()) + self.access_expire_hours * 3600,
            "jti":  secrets.token_hex(8),
        }
        token = _sign_jwt(payload, self.secret)
        return token, None

    # ── Verify ────────────────────────────────────────────────────────────────

    def verify_token(self, token: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Returns (payload, None) or (None, error)."""
        if not token:
            return None, "No token provided."
        if token in self._blacklist:
            return None, "Token has been revoked."
        payload = _verify_jwt(token, self.secret)
        if payload is None:
            return None, "Invalid or expired token."
        return payload, None

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(self, token: str) -> None:
        self._blacklist.add(token)
        # Trim blacklist periodically (keep it bounded)
        if len(self._blacklist) > 10000:
            self._blacklist = set(list(self._blacklist)[-5000:])

    # ── Rate limiting ─────────────────────────────────────────────────────────

    def _is_rate_limited(self, ip: str) -> bool:
        cutoff = time.time() - self._lockout_sec
        recent = [t for t in self._login_attempts[ip] if t > cutoff]
        self._login_attempts[ip] = recent
        return len(recent) >= self._max_attempts

    def _record_attempt(self, ip: str) -> None:
        self._login_attempts[ip].append(time.time())

    # ── Helpers ───────────────────────────────────────────────────────────────

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
