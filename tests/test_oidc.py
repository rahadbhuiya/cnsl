"""
tests/test_oidc.py -- OIDC SSO (cnsl/oidc.py).

Run:
    pytest tests/test_oidc.py -v
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

import pytest

from cnsl.oidc import OIDCManager, OIDCError, _make_pkce_pair


#  Fake aiohttp session -- request URL -> canned (status, json) response


class _FakeResponse:
    def __init__(self, status: int, data: Dict[str, Any]):
        self.status = status
        self._data = data

    async def json(self, content_type=None):
        return self._data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """
    Maps a URL (get) or (url, endpoint-kind) to a canned response.
    `posts` records every POST body for assertions.
    """

    def __init__(self, gets: Dict[str, Any], post_response: Any = None):
        self._gets = gets
        self._post_response = post_response
        self.posts = []

    def get(self, url, **kwargs):
        if url not in self._gets:
            raise AssertionError(f"unexpected GET {url}")
        status, data = self._gets[url]
        return _FakeResponse(status, data)

    def post(self, url, data=None, **kwargs):
        self.posts.append({"url": url, "data": data})
        status, resp = self._post_response
        return _FakeResponse(status, resp)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


#  Real RSA keypair + JWKS + signed id_token, generated once per test module


def _make_idp(issuer="https://idp.example.com", client_id="my-client-id"):
    """Returns (jwks_dict, sign_fn) where sign_fn(claims_overrides) -> id_token string."""
    pytest.importorskip("cryptography", reason="RS256 support requires PyJWT's crypto extra: pip install \"pyjwt[crypto]\"")
    from jwt.algorithms import RSAAlgorithm
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt as _pyjwt

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = "test-kid"
    jwks = {"keys": [jwk]}

    def sign(overrides: Dict[str, Any] = None, kid="test-kid"):
        now = int(time.time())
        claims = {
            "iss": issuer, "aud": client_id, "sub": "user123",
            "email": "alice@example.com", "iat": now, "exp": now + 300,
        }
        claims.update(overrides or {})
        return _pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})

    return jwks, sign


DISCOVERY_DOC = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint":         "https://idp.example.com/token",
    "jwks_uri":                "https://idp.example.com/jwks",
}


def _make_manager(**overrides) -> OIDCManager:
    cfg = {"oidc": {
        "enabled": True,
        "issuer": "https://idp.example.com",
        "client_id": "my-client-id",
        "client_secret": "shh",
        "redirect_uri": "https://cnsl.example.com/auth/oidc/callback",
        **overrides,
    }}
    return OIDCManager(cfg)


def _run(coro):
    return asyncio.run(coro)


#  Config / status


class TestConfig:
    def test_disabled_by_default(self):
        m = OIDCManager({})
        assert m.enabled is False
        assert m.status()["enabled"] is False

    def test_reads_config(self):
        m = _make_manager()
        assert m.enabled is True
        assert m.issuer == "https://idp.example.com"
        assert m.client_id == "my-client-id"

    def test_issuer_trailing_slash_stripped(self):
        m = _make_manager(issuer="https://idp.example.com/")
        assert m.issuer == "https://idp.example.com"

    def test_status_reports_configured(self):
        m = _make_manager()
        assert m.status()["configured"] is True

    def test_status_reports_not_configured_when_missing_fields(self):
        m = OIDCManager({"oidc": {"enabled": True}})
        assert m.status()["configured"] is False


#  PKCE


class TestPKCE:
    def test_verifier_and_challenge_differ(self):
        verifier, challenge = _make_pkce_pair()
        assert verifier != challenge
        assert len(verifier) > 20

    def test_challenge_is_deterministic_sha256_of_verifier(self):
        import hashlib, base64
        verifier, challenge = _make_pkce_pair()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        assert challenge == expected

    def test_each_call_is_unique(self):
        pairs = {_make_pkce_pair()[0] for _ in range(20)}
        assert len(pairs) == 20


#  Authorization URL


class TestBuildAuthorizationUrl:
    def test_raises_when_disabled(self):
        m = OIDCManager({})
        with pytest.raises(OIDCError, match="not enabled"):
            _run(m.build_authorization_url())

    def test_raises_when_missing_required_config(self):
        m = OIDCManager({"oidc": {"enabled": True}})
        with pytest.raises(OIDCError, match="missing required config"):
            _run(m.build_authorization_url())

    def test_builds_url_with_pkce_and_state(self, monkeypatch):
        m = _make_manager()
        session = _FakeSession(gets={
            "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
        })
        m._get_session = lambda: _async_return(session)

        url = _run(m.build_authorization_url())
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)

        assert parsed.scheme + "://" + parsed.netloc + parsed.path == "https://idp.example.com/authorize"
        assert qs["response_type"] == ["code"]
        assert qs["client_id"] == ["my-client-id"]
        assert qs["code_challenge_method"] == ["S256"]
        assert "state" in qs and "code_challenge" in qs
        # The state must be tracked server-side with its PKCE verifier.
        assert qs["state"][0] in m._pending_states

    def test_discovery_failure_raises(self):
        m = _make_manager()
        session = _FakeSession(gets={
            "https://idp.example.com/.well-known/openid-configuration": (500, {}),
        })
        m._get_session = lambda: _async_return(session)
        with pytest.raises(OIDCError, match="discovery failed"):
            _run(m.build_authorization_url())


async def _async_return(value):
    return value


#  Full callback flow (exchange_code -> verify_id_token)


class TestExchangeCodeAndVerify:
    def _setup(self, jwks, token_response):
        m = _make_manager()
        session = _FakeSession(
            gets={
                "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
                "https://idp.example.com/jwks": (200, jwks),
            },
            post_response=(200, token_response),
        )
        m._get_session = lambda: _async_return(session)
        return m, session

    def test_unknown_state_rejected(self):
        m, _ = self._setup({"keys": []}, {})
        with pytest.raises(OIDCError, match="Unknown or expired"):
            _run(m.exchange_code("some-code", "never-issued-state"))

    def test_expired_state_rejected(self):
        m, _ = self._setup({"keys": []}, {})
        m._pending_states["st1"] = {"code_verifier": "v", "created_at": time.time() - 99999}
        with pytest.raises(OIDCError, match="Unknown or expired"):
            _run(m.exchange_code("some-code", "st1"))

    def test_state_is_single_use(self):
        jwks, sign = _make_idp()
        id_token = sign()
        m, _ = self._setup(jwks, {"id_token": id_token})
        m._pending_states["st1"] = {"code_verifier": "v", "created_at": time.time()}
        _run(m.exchange_code("code1", "st1"))
        with pytest.raises(OIDCError, match="Unknown or expired"):
            _run(m.exchange_code("code1", "st1"))

    def test_successful_exchange_returns_verified_claims(self):
        jwks, sign = _make_idp()
        id_token = sign({"email": "bob@example.com"})
        m, session = self._setup(jwks, {"id_token": id_token})
        m._pending_states["st1"] = {"code_verifier": "the-verifier", "created_at": time.time()}

        claims = _run(m.exchange_code("code1", "st1"))
        assert claims["email"] == "bob@example.com"
        # code_verifier must be forwarded to the token endpoint (PKCE).
        assert session.posts[0]["data"]["code_verifier"] == "the-verifier"
        assert session.posts[0]["data"]["code"] == "code1"

    def test_idp_error_response_surfaced(self):
        m, _ = self._setup({"keys": []}, {"error": "invalid_grant", "error_description": "code expired"})
        m._pending_states["st1"] = {"code_verifier": "v", "created_at": time.time()}
        # override post_response status to non-200
        m._get_session = lambda: _async_return(_FakeSession(
            gets={
                "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
            },
            post_response=(400, {"error": "invalid_grant", "error_description": "code expired"}),
        ))
        with pytest.raises(OIDCError, match="code expired"):
            _run(m.exchange_code("code1", "st1"))

    def test_missing_id_token_in_response_raises(self):
        m, _ = self._setup({"keys": []}, {"access_token": "abc"})  # no id_token
        m._pending_states["st1"] = {"code_verifier": "v", "created_at": time.time()}
        with pytest.raises(OIDCError, match="no id_token"):
            _run(m.exchange_code("code1", "st1"))


class TestVerifyIdToken:
    def test_valid_token_verifies(self):
        jwks, sign = _make_idp()
        m = _make_manager()
        m._jwks = jwks
        m._jwks_fetched_at = time.time()
        token = sign({"email": "carol@example.com"})
        claims = _run(m.verify_id_token(token))
        assert claims["email"] == "carol@example.com"

    def test_wrong_audience_rejected(self):
        jwks, sign = _make_idp(client_id="someone-elses-client")
        m = _make_manager()  # expects client_id "my-client-id"
        m._jwks = jwks
        m._jwks_fetched_at = time.time()
        token = sign()
        with pytest.raises(OIDCError, match="verification failed"):
            _run(m.verify_id_token(token))

    def test_wrong_issuer_rejected(self):
        jwks, sign = _make_idp(issuer="https://evil.example.com")
        m = _make_manager()  # expects issuer idp.example.com
        m._jwks = jwks
        m._jwks_fetched_at = time.time()
        token = sign()
        with pytest.raises(OIDCError, match="verification failed"):
            _run(m.verify_id_token(token))

    def test_expired_token_rejected(self):
        jwks, sign = _make_idp()
        m = _make_manager()
        m._jwks = jwks
        m._jwks_fetched_at = time.time()
        token = sign({"iat": int(time.time()) - 1000, "exp": int(time.time()) - 100})
        with pytest.raises(OIDCError, match="verification failed"):
            _run(m.verify_id_token(token))

    def test_tampered_signature_rejected(self):
        jwks, sign = _make_idp()
        m = _make_manager()
        m._jwks = jwks
        m._jwks_fetched_at = time.time()
        token = sign()
        tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
        with pytest.raises(OIDCError):
            _run(m.verify_id_token(tampered))

    def test_unknown_kid_refreshes_jwks_once(self):
        jwks, sign = _make_idp()
        m = _make_manager()
        # Start with an empty JWKS cache (simulating a key rotation the
        # cache doesn't know about yet) -- verify_id_token must refetch.
        m._jwks = {"keys": []}
        m._jwks_fetched_at = time.time()
        session = _FakeSession(gets={
            "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
            "https://idp.example.com/jwks": (200, jwks),
        })
        m._get_session = lambda: _async_return(session)
        token = sign()
        claims = _run(m.verify_id_token(token))
        assert claims["sub"] == "user123"

    def test_no_matching_key_after_refresh_raises(self):
        m = _make_manager()
        m._jwks = {"keys": []}
        m._jwks_fetched_at = time.time()
        session = _FakeSession(gets={
            "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
            "https://idp.example.com/jwks": (200, {"keys": []}),
        })
        m._get_session = lambda: _async_return(session)
        _, sign = _make_idp()
        token = sign()
        with pytest.raises(OIDCError, match="No matching signing key"):
            _run(m.verify_id_token(token))

    def test_pyjwt_missing_raises_clear_error(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "jwt":
                raise ImportError("no jwt")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        m = _make_manager()
        with pytest.raises(OIDCError, match="PyJWT not installed"):
            _run(m.verify_id_token("whatever"))


#  Role mapping


class TestRoleMapping:
    def test_list_claim_matches_mapping(self):
        m = _make_manager(role_claim="groups", role_mapping={"cnsl-admins": "admin"})
        assert m.map_role({"groups": ["other-group", "cnsl-admins"]}) == "admin"

    def test_scalar_claim_matches_mapping(self):
        m = _make_manager(role_claim="department", role_mapping={"security": "admin"})
        assert m.map_role({"department": "security"}) == "admin"

    def test_no_match_falls_back_to_default_role(self):
        m = _make_manager(role_claim="groups", role_mapping={"cnsl-admins": "admin"}, default_role="viewer")
        assert m.map_role({"groups": ["unrelated"]}) == "viewer"

    def test_missing_claim_falls_back_to_default_role(self):
        m = _make_manager(role_claim="groups", default_role="viewer")
        assert m.map_role({}) == "viewer"

    def test_first_matching_mapping_wins_by_declared_order(self):
        m = _make_manager(role_claim="groups", role_mapping={"cnsl-viewers": "viewer", "cnsl-admins": "admin"})
        assert m.map_role({"groups": ["cnsl-admins", "cnsl-viewers"]}) == "viewer"  # declared first


class TestUsernameFromClaims:
    def test_prefers_email(self):
        m = _make_manager()
        assert m.username_from_claims({"email": "a@x.com", "sub": "123"}) == "a@x.com"

    def test_falls_back_to_preferred_username(self):
        m = _make_manager()
        assert m.username_from_claims({"preferred_username": "alice", "sub": "123"}) == "alice"

    def test_falls_back_to_sub(self):
        m = _make_manager()
        assert m.username_from_claims({"sub": "123"}) == "123"


class TestOidcDashboardWiring:
    async def _client(self, auth=None, oidc=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_oidc import register_oidc_routes
        from unittest.mock import AsyncMock

        logger = AsyncMock()
        logger.log = AsyncMock()

        def _get_client_ip(req):
            return "1.2.3.4"

        router = web.RouteTableDef()
        register_oidc_routes(router, auth, oidc, logger, _get_client_ip)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client, logger

    def test_status_reports_disabled_when_oidc_not_wired(self):
        async def go():
            client, _ = await self._client(auth=None, oidc=None)
            r = await client.get("/api/oidc/status")
            data = await r.json()
            assert data == {"enabled": False, "configured": False}
            await client.close()
        asyncio.run(go())

    def test_status_reflects_oidc_manager(self):
        async def go():
            oidc = _make_manager()
            client, _ = await self._client(auth=None, oidc=oidc)
            r = await client.get("/api/oidc/status")
            data = await r.json()
            assert data["enabled"] is True
            assert data["configured"] is True
            await client.close()
        asyncio.run(go())

    def test_login_redirects_to_idp(self):
        async def go():
            oidc = _make_manager()
            session = _FakeSession(gets={
                "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
            })
            oidc._get_session = lambda: _async_return(session)
            client, _ = await self._client(auth=None, oidc=oidc)
            r = await client.get("/auth/oidc/login", allow_redirects=False)
            assert r.status in (302, 303, 307)
            assert r.headers["Location"].startswith("https://idp.example.com/authorize")
            await client.close()
        asyncio.run(go())

    def test_login_returns_error_when_oidc_disabled(self):
        async def go():
            client, _ = await self._client(auth=None, oidc=None)
            r = await client.get("/auth/oidc/login")
            assert r.status == 400
            await client.close()
        asyncio.run(go())

    def test_callback_surfaces_idp_error(self):
        async def go():
            oidc = _make_manager()
            client, logger = await self._client(auth=None, oidc=oidc)
            r = await client.get("/auth/oidc/callback?error=access_denied&error_description=user+cancelled")
            assert r.status == 400
            text = await r.text()
            assert "user cancelled" in text
            logger.log.assert_any_call("oidc_callback_error", {"ip": "1.2.3.4", "error": "user cancelled"})
            await client.close()
        asyncio.run(go())

    def test_callback_missing_params_rejected(self):
        async def go():
            oidc = _make_manager()
            client, _ = await self._client(auth=None, oidc=oidc)
            r = await client.get("/auth/oidc/callback")
            assert r.status == 400
            await client.close()
        asyncio.run(go())

    def test_callback_success_issues_token_via_auth_manager(self):
        async def go():
            from unittest.mock import MagicMock
            jwks, sign = _make_idp()
            id_token = sign({"email": "dave@example.com", "groups": ["cnsl-admins"]})
            oidc = _make_manager(role_claim="groups", role_mapping={"cnsl-admins": "admin"})
            oidc._pending_states["st1"] = {"code_verifier": "v", "created_at": time.time()}
            session = _FakeSession(
                gets={
                    "https://idp.example.com/.well-known/openid-configuration": (200, DISCOVERY_DOC),
                    "https://idp.example.com/jwks": (200, jwks),
                },
                post_response=(200, {"id_token": id_token}),
            )
            oidc._get_session = lambda: _async_return(session)

            auth = MagicMock()
            auth.issue_token_for_sso_user.return_value = "cnsl-session-token"

            client, logger = await self._client(auth=auth, oidc=oidc)
            r = await client.get("/auth/oidc/callback?code=abc&state=st1")
            assert r.status == 200
            body = await r.text()
            assert "cnsl-session-token" in body
            auth.issue_token_for_sso_user.assert_called_once_with("dave@example.com", "admin")
            logger.log.assert_any_call("oidc_login_ok", {"ip": "1.2.3.4", "username": "dave@example.com", "role": "admin"})
            await client.close()
        asyncio.run(go())