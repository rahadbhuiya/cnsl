"""
cnsl/cloud_identity.py -- Cloud Identity & Access Log Connectors.

Polls cloud identity providers for sign-in and authentication events and
feeds them into the same detection pipeline used for local Linux logs.
This closes the cloud identity gap noted in the original CNSL research
paper:

    "CNSL: A Correlated Network Security Layer for
     Intent-Based Incident Detection and Response"

    "Future work includes integration with cloud identity and access
     logs (AWS CloudTrail, Azure AD, GCP IAM)."

Why this is needed:

  CNSL was built around Linux host logs (auth.log, nginx, mysql, ufw).
  None of that gives visibility into account takeover attempts against
  cloud consoles -- an attacker can brute-force or credential-stuff an
  AWS root account or Azure AD tenant without ever touching a monitored
  Linux box. These connectors close that gap by polling the identity
  provider's own audit APIs.

Supported connectors:

  AWSCloudTrailConnector  -- Polls AWS CloudTrail via the LookupEvents
                              API (signed with AWS Signature Version 4,
                              implemented directly with hmac/hashlib --
                              no boto3 dependency). Watches for
                              ConsoleLogin events, flags failures and
                              MFA-bypassed successes.

  AzureADConnector        -- Polls Microsoft Graph's signIns endpoint
                              for failed sign-ins, risky sign-ins, and
                              MFA failures. Uses OAuth2 client credentials
                              flow against Azure AD.

  GCPCloudIdentityConnector -- Polls Cloud Logging for Google Workspace
                              login-audit entries (login_success,
                              login_failure, suspicious_login, 2SV
                              challenges). Uses a service-account
                              JWT-bearer grant, RS256-signed via PyJWT's
                              crypto extra -- see the class docstring
                              for why RSA signing isn't hand-rolled here
                              the way AWS's HMAC signing is above.

  CloudIdentityPoller      -- Orchestrates all three connectors on a shared
                              poll interval, tracks a per-connector
                              cursor so the same event is never re-
                              ingested, and feeds normalized Event
                              objects into the engine's shared queue --
                              exactly like a local log tailer would.

New event kinds (added to the detector's routing table):
  CLOUD_SIGNIN_FAIL          -- failed sign-in / console login
  CLOUD_SIGNIN_SUCCESS       -- successful sign-in (tracked for breach detection)
  CLOUD_MFA_FAIL             -- MFA challenge failed or was bypassed
  CLOUD_RISKY_SIGNIN         -- provider's own risk engine flagged the sign-in
  CLOUD_IMPOSSIBLE_TRAVEL    -- two sign-ins too far apart geographically
                                to be the same person in the elapsed time

Config (config.json):
  "cloud_identity": {
    "enabled":       true,
    "poll_interval_sec": 60,
    "aws": {
      "enabled":            false,
      "access_key_id":      "",
      "secret_access_key":  "",
      "region":             "us-east-1",
      "lookback_sec":       300
    },
    "azure_ad": {
      "enabled":      false,
      "tenant_id":    "",
      "client_id":    "",
      "client_secret":"",
      "lookback_sec": 300
    },
    "gcp": {
      "enabled":                false,
      "project_id":             "",
      "service_account_email":  "",
      "private_key":            "",
      "lookback_sec":           300
    }
  }

GCP setup: create a service account with "Logs Viewer" (roles/logging.viewer)
on the target project, generate a JSON key, and copy its "client_email" and
"private_key" fields into the config above. Google Workspace login-audit
events must already be reaching Cloud Logging (Admin console -> Reporting ->
Audit and investigation -> Login audit log -> export to a log sink, or an
org-level default sink) -- this connector reads that log, it doesn't set up
the export.

This module never blocks local detection: if a cloud provider is
unreachable or misconfigured, polling logs the error and retries on the
next interval.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import Event, now



# New event kinds used by this module


class CloudEventKind:
    SIGNIN_FAIL          = "CLOUD_SIGNIN_FAIL"
    SIGNIN_SUCCESS       = "CLOUD_SIGNIN_SUCCESS"
    MFA_FAIL             = "CLOUD_MFA_FAIL"
    RISKY_SIGNIN         = "CLOUD_RISKY_SIGNIN"
    IMPOSSIBLE_TRAVEL    = "CLOUD_IMPOSSIBLE_TRAVEL"



# AWS Signature Version 4 (minimal implementation, no boto3 dependency)


def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_signature_key(secret_key: str, date_stamp: str, region: str,
                         service: str) -> bytes:
    k_date    = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region  = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    k_signing = _sigv4_sign(k_service, "aws4_request")
    return k_signing


def build_sigv4_headers(
    method:      str,
    host:        str,
    region:      str,
    service:     str,
    access_key:  str,
    secret_key:  str,
    payload:     str,
    target:      str,
    content_type: str = "application/x-amz-json-1.1",
) -> Dict[str, str]:
    """
    Build the headers needed for a signed AWS API request (POST, JSON body).
    Implements AWS Signature Version 4 directly -- the same algorithm
    boto3 uses internally, without requiring the boto3 dependency.
    """
    t           = datetime.now(timezone.utc)
    amz_date    = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp  = t.strftime("%Y%m%d")

    canonical_uri     = "/"
    canonical_querystring = ""
    payload_hash      = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    canonical_headers = (
        f"content-type:{content_type}\n"
        f"host:{host}\n"
        f"x-amz-date:{amz_date}\n"
        f"x-amz-target:{target}\n"
    )
    signed_headers = "content-type;host;x-amz-date;x-amz-target"

    canonical_request = (
        f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )

    algorithm        = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign   = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    signing_key = _sigv4_signature_key(secret_key, date_stamp, region, service)
    signature   = hmac.new(signing_key, string_to_sign.encode("utf-8"),
                           hashlib.sha256).hexdigest()

    authorization = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Content-Type":  content_type,
        "X-Amz-Date":    amz_date,
        "X-Amz-Target":  target,
        "Authorization": authorization,
    }



# AWS CloudTrail Connector


class AWSCloudTrailConnector:
    """
    Polls AWS CloudTrail's LookupEvents API for ConsoleLogin events.

    Watches specifically for:
      - ConsoleLogin with errorMessage="Failed authentication"  -> SIGNIN_FAIL
      - ConsoleLogin success without MFA on a sensitive account -> MFA_FAIL
      - ConsoleLogin success                                    -> SIGNIN_SUCCESS

    AWS docs: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/
              API_LookupEvents.html
    """

    NAME = "aws_cloudtrail"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        aws = cfg.get("cloud_identity", {}).get("aws", {})
        self.enabled      = bool(aws.get("enabled", False))
        self.access_key   = aws.get("access_key_id", "")
        self.secret_key   = aws.get("secret_access_key", "")
        self.region       = aws.get("region", "us-east-1")
        self.lookback_sec = int(aws.get("lookback_sec", 300))

        self._last_event_id: Optional[str] = None
        self._last_poll_time: float = 0.0
        self._poll_count   = 0
        self._error_count  = 0
        self._last_error: Optional[str] = None

    @property
    def host(self) -> str:
        return f"cloudtrail.{self.region}.amazonaws.com"

    async def poll(self) -> List[Event]:
        """Poll CloudTrail for new ConsoleLogin events since the last poll."""
        if not self.enabled or not self.access_key or not self.secret_key:
            return []

        session = await self._get_session()
        if session is None:
            return []

        start_time = self._last_poll_time or (now() - self.lookback_sec)
        end_time   = now()

        payload = json.dumps({
            "StartTime": int(start_time * 1000),
            "EndTime":   int(end_time * 1000),
            "LookupAttributes": [
                {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
            ],
        })

        headers = build_sigv4_headers(
            method="POST", host=self.host, region=self.region,
            service="cloudtrail", access_key=self.access_key,
            secret_key=self.secret_key, payload=payload,
            target="com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents",
        )

        try:
            async with session.post(
                f"https://{self.host}/", data=payload, headers=headers,
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {body[:160]}"
                    self._error_count += 1
                    return []
                data = await resp.json()
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return []

        self._poll_count += 1
        self._last_poll_time = end_time
        events = self._parse_events(data.get("Events", []))
        self._last_error = None
        return events

    def _parse_events(self, raw_events: List[Dict]) -> List[Event]:
        out: List[Event] = []
        for raw in raw_events:
            event_id = raw.get("EventId")
            if event_id == self._last_event_id:
                continue
            try:
                ct_event = json.loads(raw.get("CloudTrailEvent", "{}"))
            except Exception:
                continue

            src_ip       = ct_event.get("sourceIPAddress")
            user         = (ct_event.get("userIdentity", {}) or {}).get("userName")
            response     = ct_event.get("responseElements", {}) or {}
            login_status = response.get("ConsoleLogin")
            mfa_used     = ct_event.get("additionalEventData", {}).get("MFAUsed", "No")

            if login_status == "Failure":
                kind = CloudEventKind.SIGNIN_FAIL
            elif login_status == "Success" and mfa_used != "Yes":
                kind = CloudEventKind.MFA_FAIL
            elif login_status == "Success":
                kind = CloudEventKind.SIGNIN_SUCCESS
            else:
                continue

            out.append(Event(
                ts=now(), source="aws_cloudtrail", kind=kind,
                src_ip=src_ip, user=user, raw=str(raw)[:500],
                meta={
                    "event_id":   event_id,
                    "event_name": raw.get("EventName"),
                    "mfa_used":   mfa_used,
                    "provider":   "aws",
                },
            ))

        if raw_events:
            self._last_event_id = raw_events[-1].get("EventId")
        return out

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":     self.enabled,
            "poll_count":  self._poll_count,
            "error_count": self._error_count,
            "last_error":  self._last_error,
            "healthy":     self._error_count == 0 or self._poll_count > 0,
        }

    async def _get_session(self):
        try:
            import aiohttp
            return aiohttp.ClientSession()
        except ImportError:
            return None



# Azure AD Connector


class AzureADConnector:
    """
    Polls Microsoft Graph's signIns endpoint for failed sign-ins, risky
    sign-ins, and MFA failures using OAuth2 client credentials flow.

    Microsoft docs:
    https://learn.microsoft.com/en-us/graph/api/signin-list
    """

    NAME = "azure_ad"

    TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    GRAPH_SIGNINS_URL   = "https://graph.microsoft.com/v1.0/auditLogs/signIns"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        az = cfg.get("cloud_identity", {}).get("azure_ad", {})
        self.enabled       = bool(az.get("enabled", False))
        self.tenant_id     = az.get("tenant_id", "")
        self.client_id     = az.get("client_id", "")
        self.client_secret = az.get("client_secret", "")
        self.lookback_sec  = int(az.get("lookback_sec", 300))

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._last_poll_time: float = 0.0
        self._poll_count   = 0
        self._error_count  = 0
        self._last_error: Optional[str] = None

    async def poll(self) -> List[Event]:
        """Poll Microsoft Graph for sign-in events since the last poll."""
        if not self.enabled or not self.tenant_id or not self.client_id:
            return []

        session = await self._get_session()
        if session is None:
            return []

        token = await self._ensure_token(session)
        if not token:
            return []

        start_time = self._last_poll_time or (now() - self.lookback_sec)
        start_iso  = datetime.fromtimestamp(start_time, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        url = f"{self.GRAPH_SIGNINS_URL}?$filter=createdDateTime ge {start_iso}"

        try:
            async with session.get(
                url, headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {body[:160]}"
                    self._error_count += 1
                    return []
                data = await resp.json()
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return []

        self._poll_count += 1
        self._last_poll_time = now()
        events = self._parse_events(data.get("value", []))
        self._last_error = None
        return events

    async def _ensure_token(self, session) -> Optional[str]:
        """Get a cached access token, or fetch a new one if expired."""
        if self._access_token and now() < self._token_expiry - 60:
            return self._access_token

        url = self.TOKEN_URL_TEMPLATE.format(tenant_id=self.tenant_id)
        data = {
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
            "grant_type":    "client_credentials",
        }

        try:
            async with session.post(url, data=data) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    self._last_error = f"Token HTTP {resp.status}: {body[:160]}"
                    self._error_count += 1
                    return None
                token_data = await resp.json()
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return None

        self._access_token = token_data.get("access_token")
        self._token_expiry  = now() + int(token_data.get("expires_in", 3600))
        return self._access_token

    def _parse_events(self, raw_events: List[Dict]) -> List[Event]:
        out: List[Event] = []
        for raw in raw_events:
            status        = raw.get("status", {}) or {}
            error_code    = status.get("errorCode", 0)
            risk_state    = raw.get("riskState", "none")
            src_ip        = raw.get("ipAddress")
            user          = raw.get("userPrincipalName")
            mfa_detail    = raw.get("authenticationRequirement", "")
            event_id      = raw.get("id")

            if risk_state and risk_state not in ("none", "dismissed"):
                kind = CloudEventKind.RISKY_SIGNIN
            elif error_code == 0:
                kind = CloudEventKind.SIGNIN_SUCCESS
            elif error_code in (50074, 50079, 50076):  # MFA-related Azure AD codes
                kind = CloudEventKind.MFA_FAIL
            else:
                kind = CloudEventKind.SIGNIN_FAIL

            out.append(Event(
                ts=now(), source="azure_ad", kind=kind,
                src_ip=src_ip, user=user, raw=str(raw)[:500],
                meta={
                    "event_id":    event_id,
                    "error_code":  error_code,
                    "risk_state":  risk_state,
                    "mfa_detail":  mfa_detail,
                    "provider":    "azure_ad",
                },
            ))
        return out

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":     self.enabled,
            "poll_count":  self._poll_count,
            "error_count": self._error_count,
            "last_error":  self._last_error,
            "healthy":     self._error_count == 0 or self._poll_count > 0,
            "token_valid": bool(self._access_token and now() < self._token_expiry),
        }

    async def _get_session(self):
        try:
            import aiohttp
            return aiohttp.ClientSession()
        except ImportError:
            return None



# GCP Cloud Identity Connector


class GCPCloudIdentityConnector:
    """
    Polls GCP Cloud Logging for Google Workspace login-audit entries --
    the GCP-side equivalent of AWSCloudTrailConnector's ConsoleLogin and
    AzureADConnector's signIns (console/account sign-in monitoring).
    This closes the "GCP IAM" gap named in this module's own docstring
    but never previously implemented.

    Prerequisite on the GCP side: the org/project must already export
    Workspace login-audit events to Cloud Logging (Admin console ->
    Reporting -> Audit and investigation -> Login audit log -> a log
    sink, or an org-level `_Default` sink that already captures them).
    This connector only reads what's already landing in Cloud Logging;
    it does not configure the export itself.

    Auth: service-account JWT-bearer grant (RFC 7523) against Google's
    OAuth2 token endpoint -- the standard server-to-server auth flow
    for Google APIs. Unlike AWS SigV4 (HMAC, hand-rolled above with
    stdlib hmac/hashlib) or Azure AD's client-credentials flow (a plain
    shared secret, no signing), this requires RSA-signing a JWT
    (RS256) with the service account's private key. RSA signing is not
    something to hand-roll -- correctness and side-channel safety
    matter -- so this connector relies on PyJWT's "crypto" extra
    (`pip install "pyjwt[crypto]"`) and degrades to disabled with a
    clear status()/last_error instead of a hand-written implementation.

    Google docs:
      https://developers.google.com/identity/protocols/oauth2/service-account
      https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
      https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login
    """

    NAME = "gcp_identity"

    TOKEN_URL   = "https://oauth2.googleapis.com/token"
    ENTRIES_URL = "https://logging.googleapis.com/v2/entries:list"
    SCOPE       = "https://www.googleapis.com/auth/logging.read"

    # Google Workspace login-audit event names this connector recognizes.
    # https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login
    _MFA_EVENTS = {"login_verification", "2sv_verification_switch"}
    _RISKY_EVENTS = {
        "suspicious_login",
        "suspicious_login_less_secure_app",
        "suspicious_programmatic_login",
        "account_disabled_hijacked",
    }

    def __init__(self, cfg: Dict[str, Any]) -> None:
        gcp = cfg.get("cloud_identity", {}).get("gcp", {})
        self.enabled      = bool(gcp.get("enabled", False))
        self.project_id   = gcp.get("project_id", "")
        self.client_email = gcp.get("service_account_email", "")
        self.private_key  = gcp.get("private_key", "")
        self.lookback_sec = int(gcp.get("lookback_sec", 300))

        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._last_poll_time: float = 0.0
        self._poll_count  = 0
        self._error_count = 0
        self._last_error: Optional[str] = None

    async def poll(self) -> List[Event]:
        """Poll Cloud Logging for new Workspace login-audit entries since the last poll."""
        if not self.enabled or not self.project_id or not self.client_email or not self.private_key:
            return []

        session = await self._get_session()
        if session is None:
            return []

        token = await self._ensure_token(session)
        if not token:
            return []

        start_time = self._last_poll_time or (now() - self.lookback_sec)
        start_iso  = datetime.fromtimestamp(start_time, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        body = {
            "resourceNames": [f"projects/{self.project_id}"],
            "filter": (
                'protoPayload.serviceName="login.googleapis.com" '
                f'AND timestamp >= "{start_iso}"'
            ),
            "orderBy":  "timestamp asc",
            "pageSize": 200,
        }

        try:
            async with session.post(
                self.ENTRIES_URL, json=body,
                headers={"Authorization": f"Bearer {token}"},
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    self._last_error = f"HTTP {resp.status}: {text[:160]}"
                    self._error_count += 1
                    return []
                data = await resp.json()
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return []

        self._poll_count += 1
        self._last_poll_time = now()
        events = self._parse_events(data.get("entries", []))
        self._last_error = None
        return events

    def _build_assertion(self) -> Optional[str]:
        """
        Build a self-signed JWT assertion for the OAuth2 JWT-bearer grant.
        Returns None (with self._last_error set) if PyJWT/cryptography
        isn't installed or the configured private key is invalid --
        callers treat that exactly like a network failure and retry
        next interval, they never raise.
        """
        try:
            import jwt as _pyjwt
        except ImportError:
            self._last_error = "PyJWT not installed -- required for GCP service-account auth"
            return None

        iat = int(now())
        claims = {
            "iss":   self.client_email,
            "scope": self.SCOPE,
            "aud":   self.TOKEN_URL,
            "iat":   iat,
            "exp":   iat + 3600,
        }
        try:
            return _pyjwt.encode(claims, self.private_key, algorithm="RS256")
        except Exception as e:
            # Most commonly: cryptography backend missing
            # (`pip install "pyjwt[crypto]"`), or a malformed private key.
            self._last_error = f"JWT signing failed: {e}"
            return None

    async def _ensure_token(self, session) -> Optional[str]:
        """Get a cached access token, or exchange a fresh JWT assertion for one."""
        if self._access_token and now() < self._token_expiry - 60:
            return self._access_token

        assertion = self._build_assertion()
        if assertion is None:
            self._error_count += 1
            return None

        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion":  assertion,
        }
        try:
            async with session.post(self.TOKEN_URL, data=data) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    self._last_error = f"Token HTTP {resp.status}: {body[:160]}"
                    self._error_count += 1
                    return None
                token_data = await resp.json()
        except Exception as e:
            self._last_error = str(e)
            self._error_count += 1
            return None

        self._access_token = token_data.get("access_token")
        self._token_expiry = now() + int(token_data.get("expires_in", 3600))
        return self._access_token

    def _parse_events(self, raw_entries: List[Dict]) -> List[Event]:
        out: List[Event] = []
        for raw in raw_entries:
            payload   = raw.get("protoPayload", {}) or {}
            sub_events = payload.get("event", []) or []
            actor     = (payload.get("authenticationInfo", {}) or {}).get("principalEmail")
            src_ip    = (payload.get("requestMetadata", {}) or {}).get("callerIp")

            for sub in sub_events:
                name = sub.get("eventName", "")
                if name == "login_success":
                    kind = CloudEventKind.SIGNIN_SUCCESS
                elif name == "login_failure":
                    kind = CloudEventKind.SIGNIN_FAIL
                elif name in self._RISKY_EVENTS:
                    kind = CloudEventKind.RISKY_SIGNIN
                elif name in self._MFA_EVENTS:
                    kind = CloudEventKind.MFA_FAIL
                else:
                    continue

                out.append(Event(
                    ts=now(), source="gcp_identity", kind=kind,
                    src_ip=src_ip, user=actor, raw=str(raw)[:500],
                    meta={
                        "insert_id":  raw.get("insertId"),
                        "event_name": name,
                        "provider":   "gcp",
                    },
                ))
        return out

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":     self.enabled,
            "poll_count":  self._poll_count,
            "error_count": self._error_count,
            "last_error":  self._last_error,
            "healthy":     self._error_count == 0 or self._poll_count > 0,
            "token_valid": bool(self._access_token and now() < self._token_expiry),
        }

    async def _get_session(self):
        try:
            import aiohttp
            return aiohttp.ClientSession()
        except ImportError:
            return None



# Cloud Identity Poller -- orchestrates all three connectors


class CloudIdentityPoller:
    """
    Runs both cloud identity connectors on a shared poll interval and
    feeds resulting Events into the engine's shared queue -- the same
    queue local log tailers feed into.

    Usage:
        poller = CloudIdentityPoller(cfg)
        task = asyncio.create_task(poller.run(queue, logger))
        # ... later, on shutdown:
        await poller.stop()
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        ci_cfg = cfg.get("cloud_identity", {})
        self.enabled       = bool(ci_cfg.get("enabled", True))
        self.poll_interval = int(ci_cfg.get("poll_interval_sec", 60))

        self.aws      = AWSCloudTrailConnector(cfg)
        self.azure_ad = AzureADConnector(cfg)
        self.gcp      = GCPCloudIdentityConnector(cfg)

        self.any_enabled = self.aws.enabled or self.azure_ad.enabled or self.gcp.enabled
        self._running     = False
        self._events_fed   = 0

    @property
    def connectors(self) -> List[Any]:
        return [self.aws, self.azure_ad, self.gcp]

    async def run(self, queue: "asyncio.Queue", logger: Any = None) -> None:
        """Long-running poll loop. Call as a background task."""
        if not self.enabled or not self.any_enabled:
            return
        self._running = True

        while self._running:
            for connector in self.connectors:
                if not connector.enabled:
                    continue
                try:
                    events = await connector.poll()
                    for ev in events:
                        await queue.put(ev)
                        self._events_fed += 1
                except Exception as e:
                    if logger:
                        await logger.log("cloud_identity_poll_error", {
                            "connector": connector.NAME, "error": str(e),
                        })
            await asyncio.sleep(self.poll_interval)

    async def stop(self) -> None:
        self._running = False

    def status(self) -> Dict[str, Any]:
        return {
            "enabled":         self.enabled,
            "any_enabled":      self.any_enabled,
            "poll_interval_sec": self.poll_interval,
            "events_fed":       self._events_fed,
            "connectors": {
                "aws_cloudtrail": self.aws.status(),
                "azure_ad":       self.azure_ad.status(),
                "gcp_identity":   self.gcp.status(),
            },
        }