"""
cnsl/oidc.py -- OIDC single sign-on for the dashboard (Authorization
Code flow + PKCE).

Scope: OIDC only, not SAML. SAML is XML-based and needs XML digital
signature verification (XML canonicalization, XXE-safe parsing, and a
much larger attack surface) to implement safely -- that's a
substantially different and riskier undertaking than an OIDC client,
and every mainstream identity provider (Okta, Azure AD/Entra ID,
Google Workspace, Auth0, Keycloak, OneLogin, ...) supports OIDC, so
SAML support is left out rather than rushed.

How it fits into CNSL's existing auth (cnsl/auth.py): OIDC
authenticates the user against the identity provider, but CNSL still
issues its own session JWT via AuthManager -- the dashboard and its
API never see or trust the IdP's tokens after login. This means every
existing piece of role-based logic (page auth checks, per-endpoint
role requirements) keeps working unchanged for SSO users; OIDC is
purely a second way to arrive at a normal CNSL session.

Flow:
  1. GET /auth/oidc/login   -- build_authorization_url() redirects the
     browser to the IdP with a random `state` and a PKCE
     code_challenge (S256). The matching code_verifier is held
     server-side, keyed by state, with a short TTL -- never sent to
     the browser.
  2. IdP authenticates the user, redirects back to
     /auth/oidc/callback?code=...&state=...
  3. exchange_code() validates state (single-use, TTL-bound), POSTs
     the authorization code + code_verifier to the IdP's token
     endpoint, and gets back an id_token (a JWT signed by the IdP).
  4. verify_id_token() validates that JWT's signature against the
     IdP's published JWKS (fetched from the discovery document,
     cached, refreshed on an unrecognized `kid`), plus standard
     iss/aud/exp checks.
  5. map_role() turns the verified claims into a CNSL role
     (admin/analyst/viewer) via a configurable claim + value mapping.
  6. The dashboard's AuthManager mints a normal CNSL session JWT for
     that (username, role) -- see AuthManager.issue_token_for_sso_user
     in cnsl/auth.py.

Requires PyJWT with its "crypto" extra for RS256 signature
verification (`pip install "pyjwt[crypto]"`) -- the same dependency
already used by the GCP cloud-identity connector (cnsl/cloud_identity.py)
for the same reason: RSA verification isn't something to hand-roll.
Degrades to a clear status()/error rather than crashing if it's
missing.

Config example:
  "oidc": {
    "enabled":       true,
    "issuer":        "https://your-tenant.okta.com",
    "client_id":     "...",
    "client_secret": "...",
    "redirect_uri":  "https://cnsl.example.com/auth/oidc/callback",
    "scopes":        "openid email profile groups",
    "role_claim":    "groups",
    "role_mapping": {
      "cnsl-admins":   "admin",
      "cnsl-analysts": "analyst"
    },
    "default_role":  "viewer"
  }
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode


_STATE_TTL_SEC   = 600   # 10 minutes to complete the IdP round trip
_DISCOVERY_TTL   = 3600  # re-fetch the discovery document hourly
_JWKS_TTL        = 3600  # re-fetch the JWKS hourly (or on kid miss)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_pkce_pair() -> Tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge


class OIDCError(Exception):
    """Raised for any OIDC flow failure -- caught at the route layer and turned into a login error."""


class OIDCManager:
    NAME = "oidc"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        oidc_cfg = cfg.get("oidc", {}) or {}
        self.enabled       = bool(oidc_cfg.get("enabled", False))
        self.issuer        = (oidc_cfg.get("issuer") or "").rstrip("/")
        self.client_id     = oidc_cfg.get("client_id", "")
        self.client_secret = oidc_cfg.get("client_secret", "")
        self.redirect_uri  = oidc_cfg.get("redirect_uri", "")
        self.scopes        = oidc_cfg.get("scopes", "openid email profile")
        self.role_claim    = oidc_cfg.get("role_claim", "groups")
        self.role_mapping  = dict(oidc_cfg.get("role_mapping", {}) or {})
        self.default_role  = oidc_cfg.get("default_role", "viewer")

        self._discovery: Optional[Dict[str, Any]] = None
        self._discovery_fetched_at: float = 0.0
        self._jwks: Optional[Dict[str, Any]] = None
        self._jwks_fetched_at: float = 0.0

        # state -> {"code_verifier": str, "created_at": float}
        self._pending_states: Dict[str, Dict[str, Any]] = {}

    #  Discovery / JWKS 

    async def _get_session(self):
        try:
            import aiohttp
            return aiohttp.ClientSession()
        except ImportError:
            return None

    async def _discovery_document(self) -> Dict[str, Any]:
        if self._discovery and (time.time() - self._discovery_fetched_at) < _DISCOVERY_TTL:
            return self._discovery
        session = await self._get_session()
        if session is None:
            raise OIDCError("aiohttp not installed -- required for OIDC discovery")
        url = f"{self.issuer}/.well-known/openid-configuration"
        try:
            async with session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        raise OIDCError(f"OIDC discovery failed: HTTP {resp.status} from {url}")
                    doc = await resp.json(content_type=None)
        except OIDCError:
            raise
        except Exception as e:
            raise OIDCError(f"OIDC discovery request failed: {e}")
        self._discovery = doc
        self._discovery_fetched_at = time.time()
        return doc

    async def _jwks_document(self, force_refresh: bool = False) -> Dict[str, Any]:
        if self._jwks and not force_refresh and (time.time() - self._jwks_fetched_at) < _JWKS_TTL:
            return self._jwks
        doc = await self._discovery_document()
        jwks_uri = doc.get("jwks_uri")
        if not jwks_uri:
            raise OIDCError("Discovery document has no jwks_uri")
        session = await self._get_session()
        if session is None:
            raise OIDCError("aiohttp not installed -- required to fetch JWKS")
        try:
            async with session:
                async with session.get(jwks_uri) as resp:
                    if resp.status != 200:
                        raise OIDCError(f"JWKS fetch failed: HTTP {resp.status}")
                    jwks = await resp.json(content_type=None)
        except OIDCError:
            raise
        except Exception as e:
            raise OIDCError(f"JWKS fetch request failed: {e}")
        self._jwks = jwks
        self._jwks_fetched_at = time.time()
        return jwks

    #  Authorization URL (step 1) 

    async def build_authorization_url(self) -> str:
        """Build the IdP redirect URL, generating and stashing state+PKCE server-side."""
        if not self.enabled:
            raise OIDCError("OIDC is not enabled")
        if not (self.issuer and self.client_id and self.redirect_uri):
            raise OIDCError("OIDC is missing required config (issuer/client_id/redirect_uri)")

        doc = await self._discovery_document()
        auth_endpoint = doc.get("authorization_endpoint")
        if not auth_endpoint:
            raise OIDCError("Discovery document has no authorization_endpoint")

        self._prune_expired_states()
        state = secrets.token_urlsafe(24)
        verifier, challenge = _make_pkce_pair()
        self._pending_states[state] = {"code_verifier": verifier, "created_at": time.time()}

        params = {
            "response_type":         "code",
            "client_id":             self.client_id,
            "redirect_uri":          self.redirect_uri,
            "scope":                 self.scopes,
            "state":                 state,
            "code_challenge":        challenge,
            "code_challenge_method": "S256",
        }
        return f"{auth_endpoint}?{urlencode(params)}"

    def _prune_expired_states(self) -> None:
        cutoff = time.time() - _STATE_TTL_SEC
        expired = [s for s, v in self._pending_states.items() if v["created_at"] < cutoff]
        for s in expired:
            self._pending_states.pop(s, None)

    #  Callback (steps 2-5) 

    async def exchange_code(self, code: str, state: str) -> Dict[str, Any]:
        """
        Validate state, exchange the authorization code for tokens, and
        return the verified ID token claims. Raises OIDCError on any
        failure (unknown/expired state, IdP error, bad signature, ...).
        """
        self._prune_expired_states()
        pending = self._pending_states.pop(state, None)
        if pending is None:
            raise OIDCError("Unknown or expired OIDC state -- possible CSRF or a stale login link, please try again")

        doc = await self._discovery_document()
        token_endpoint = doc.get("token_endpoint")
        if not token_endpoint:
            raise OIDCError("Discovery document has no token_endpoint")

        session = await self._get_session()
        if session is None:
            raise OIDCError("aiohttp not installed -- required for OIDC token exchange")

        data = {
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  self.redirect_uri,
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "code_verifier": pending["code_verifier"],
        }
        try:
            async with session:
                async with session.post(token_endpoint, data=data) as resp:
                    body = await resp.json(content_type=None)
                    if resp.status != 200:
                        err = body.get("error_description") or body.get("error") or f"HTTP {resp.status}"
                        raise OIDCError(f"Token exchange failed: {err}")
        except OIDCError:
            raise
        except Exception as e:
            raise OIDCError(f"Token exchange request failed: {e}")

        id_token = body.get("id_token")
        if not id_token:
            raise OIDCError("IdP token response had no id_token")

        return await self.verify_id_token(id_token)

    async def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """Verify an ID token's signature (RS256, via the IdP's JWKS) and standard claims."""
        try:
            import jwt as _pyjwt
        except ImportError:
            raise OIDCError("PyJWT not installed -- required for OIDC")

        try:
            header = _pyjwt.get_unverified_header(id_token)
        except Exception as e:
            raise OIDCError(f"Malformed ID token: {e}")
        kid = header.get("kid")

        jwks = await self._jwks_document()
        key = self._find_jwk(jwks, kid)
        if key is None:
            # kid not found -- the IdP may have rotated keys; refresh once and retry.
            jwks = await self._jwks_document(force_refresh=True)
            key = self._find_jwk(jwks, kid)
        if key is None:
            raise OIDCError(f"No matching signing key (kid={kid!r}) found in IdP JWKS")

        try:
            from jwt.algorithms import RSAAlgorithm
            public_key = RSAAlgorithm.from_jwk(json.dumps(key))
        except Exception as e:
            raise OIDCError(f"Failed to load IdP signing key: {e}")

        try:
            claims = _pyjwt.decode(
                id_token, key=public_key, algorithms=["RS256"],
                audience=self.client_id, issuer=self._expected_issuer(),
            )
        except Exception as e:
            raise OIDCError(f"ID token verification failed: {e}")

        return claims

    def _expected_issuer(self) -> Any:
        """
        PyJWT's issuer check is an exact string match; some IdPs' actual
        `iss` claim differs from the configured discovery URL only by a
        trailing slash. Accept either form rather than fail on that
        cosmetic difference.
        """
        return [self.issuer, self.issuer + "/"]

    @staticmethod
    def _find_jwk(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
        for key in jwks.get("keys", []):
            if kid is None or key.get("kid") == kid:
                return key
        return None

    #  Role mapping (step 5) 

    def map_role(self, claims: Dict[str, Any]) -> str:
        """
        Turn verified ID token claims into a CNSL role, via role_claim +
        role_mapping. If the claim's value is a list (e.g. group
        membership), the first configured mapping matching any entry
        wins the priority order role_mapping was declared in (dict
        insertion order); falls back to default_role.
        """
        value = claims.get(self.role_claim)
        if value is None:
            return self.default_role
        candidates: List[str] = value if isinstance(value, list) else [value]
        for mapped_value, role in self.role_mapping.items():
            if mapped_value in candidates:
                return role
        return self.default_role

    def username_from_claims(self, claims: Dict[str, Any]) -> str:
        """Prefer email, then preferred_username, then sub -- whichever the IdP actually sent."""
        return claims.get("email") or claims.get("preferred_username") or claims.get("sub", "")

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":     self.enabled,
            "issuer":      self.issuer,
            "configured":  bool(self.issuer and self.client_id and self.redirect_uri),
        }