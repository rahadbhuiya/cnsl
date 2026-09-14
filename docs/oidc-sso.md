# OIDC Single Sign-On

CNSL supports logging into the dashboard via an external identity
provider using OIDC (OpenID Connect), Authorization Code flow with
PKCE. This is in addition to, not a replacement for, the existing
local username/password + TOTP login (`docs/` -- see `cnsl/auth.py`);
both can be enabled at once, and the local admin account remains
available as a fallback.

**Scope: OIDC only, not SAML.** SAML is XML-based and needs XML
digital signature verification -- canonicalization, XXE-safe parsing,
a meaningfully larger and riskier attack surface than an OIDC client.
Every mainstream identity provider (Okta, Azure AD/Entra ID, Google
Workspace, Auth0, Keycloak, OneLogin, ...) supports OIDC, so SAML
support is left out rather than implemented in a rush.

## How it works

CNSL never trusts the identity provider's tokens beyond the login
moment. The flow:

1. User clicks **Login with SSO** on the login page -> browser goes to
   `GET /auth/oidc/login`.
2. CNSL fetches the IdP's discovery document, generates a random
   `state` and a PKCE `code_verifier`/`code_challenge` pair, and
   redirects the browser to the IdP's authorization endpoint. The
   `code_verifier` is held server-side only, keyed by `state`, with a
   10-minute expiry -- it's never sent to the browser.
3. The IdP authenticates the user and redirects back to
   `GET /auth/oidc/callback?code=...&state=...`.
4. CNSL validates `state` (single-use), exchanges the code + PKCE
   verifier for tokens at the IdP's token endpoint, and gets an
   `id_token` (a JWT signed by the IdP).
5. CNSL verifies that JWT's signature against the IdP's published JWKS
   (fetched from the discovery document, cached, auto-refreshed on an
   unrecognized `kid` in case the IdP rotated keys), plus the standard
   `iss`/`aud`/`exp` checks.
6. The verified claims are turned into a CNSL role via a configurable
   claim + value mapping (see below).
7. **From here on, CNSL issues its own ordinary session JWT** --
   exactly the same kind a password login produces. The dashboard and
   its API never see or store the IdP's tokens after this point, so
   every existing role-based permission check keeps working unchanged
   for SSO users.

## Config

```json
{
  "oidc": {
    "enabled":       true,
    "issuer":        "https://your-tenant.okta.com",
    "client_id":     "0oa1b2c3d4e5f6g7h8i9",
    "client_secret": "your-client-secret",
    "redirect_uri":  "https://cnsl.example.com/auth/oidc/callback",
    "scopes":        "openid email profile groups",
    "role_claim":    "groups",
    "role_mapping": {
      "cnsl-admins":   "admin",
      "cnsl-analysts": "analyst"
    },
    "default_role":  "viewer"
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable the SSO login button and callback routes |
| `issuer` | | The IdP's issuer URL. CNSL fetches `{issuer}/.well-known/openid-configuration` |
| `client_id` | | OIDC client ID registered with the IdP |
| `client_secret` | | OIDC client secret |
| `redirect_uri` | | Must exactly match what's registered with the IdP -- `https://your-cnsl-host/auth/oidc/callback` |
| `scopes` | `"openid email profile"` | Space-separated scope list requested from the IdP |
| `role_claim` | `"groups"` | Which ID token claim to read for role mapping (scalar or list) |
| `role_mapping` | `{}` | Claim value -> CNSL role (`admin`/`analyst`/`viewer`). Checked in the order declared; first match wins |
| `default_role` | `"viewer"` | Role assigned when nothing in `role_mapping` matches |

Requires PyJWT with its `crypto` extra (RS256 signature verification):
```bash
pip install "PyJWT[crypto]"
```
(the same dependency already used by the GCP cloud identity connector,
for the same reason -- RSA verification isn't something to hand-roll).

## Provider setup examples

Register CNSL as an OIDC application in your IdP with:
- **Redirect URI**: `https://your-cnsl-host/auth/oidc/callback`
- **Grant type**: Authorization Code (with PKCE if the IdP requires
  choosing it explicitly)
- **Scopes**: `openid email profile`, plus a groups/roles scope if your
  IdP puts group membership behind one (Okta and Azure AD both do)

**Okta**: Applications -> Create App Integration -> OIDC -> Web
Application. Add a "groups" claim to the ID token under
Sign On -> OpenID Connect ID Token if you want `role_claim: "groups"`
to work.

**Azure AD / Entra ID**: App registrations -> New registration ->
Web platform, redirect URI as above. Group membership needs the
`GroupMember.Read.All` claim configured under Token configuration ->
Add groups claim.

**Google Workspace**: Google Cloud Console -> APIs & Services ->
Credentials -> OAuth client ID -> Web application. Google's ID tokens
don't include group membership by default -- use `role_claim: "email"`
or `"hd"` (hosted domain) with a mapping, or omit role mapping and
rely on `default_role`.

**Keycloak**: Clients -> Create client -> OpenID Connect, standard
flow enabled. Group membership needs a "group" mapper added to the
client scope.

## Security notes

- `redirect_uri` and `issuer` should both be `https://` -- the
  validator (`cnsl/validator.py`) warns (not errors) if either is
  plain `http`, since most IdPs refuse non-HTTPS redirects anyway.
- `state` is single-use and expires after 10 minutes -- a replayed or
  stale callback link fails with "Unknown or expired OIDC state."
- ID token signature verification always happens against the IdP's own
  published keys (JWKS), never a locally-stored key -- if the IdP
  rotates its signing key, CNSL detects the unrecognized `kid` and
  refetches the JWKS automatically.
- SSO users are auto-provisioned on first login (no separate
  "register" step) and their role is **re-derived from the IdP on
  every login** -- if you remove someone from the `cnsl-admins` group
  in your IdP, their next login reflects that; CNSL doesn't cache a
  stale role.

## Troubleshooting

| Symptom | Likely cause |
|:---|:---|
| "OIDC login could not start" | `issuer`/`client_id`/`redirect_uri` missing from config, or the IdP's discovery document couldn't be fetched (check network egress and the issuer URL) |
| "Unknown or expired OIDC state" | Took longer than 10 minutes to complete the IdP login, or the callback URL was reused/bookmarked |
| "ID token verification failed" | `client_id` doesn't match the token's `aud`, `issuer` doesn't match the token's `iss` (trailing-slash differences are tolerated), or the token expired |
| "No matching signing key" | The IdP rotated keys faster than expected, or `jwks_uri` in the discovery document is unreachable |
| Login succeeds but role is always `viewer` | Check `role_claim` matches what the IdP actually sends (inspect the ID token at [jwt.io](https://jwt.io) during setup), and that `role_mapping` keys match the claim's values exactly |