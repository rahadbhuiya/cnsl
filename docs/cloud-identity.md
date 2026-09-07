# Cloud Identity Log Connectors

CNSL polls AWS CloudTrail, Azure AD, and GCP Cloud Logging for sign-in and
authentication events and feeds them into the same detection pipeline used
for local Linux logs.

This closes the cloud identity gap from the original CNSL research paper:

> "Future work includes integration with cloud identity and access logs
>  (AWS CloudTrail, Azure AD, GCP IAM)."


## Why cloud identity logs?

CNSL was built around Linux host logs. None of that gives visibility into
account takeover attempts against cloud consoles -- an attacker can
brute-force an AWS root account or credential-stuff an Azure AD tenant
without ever touching a monitored Linux box.

These connectors close that gap by polling the identity provider's own
audit APIs on a configurable interval and feeding the results into the
detection pipeline as first-class events.


## How it works

1. `CloudIdentityPoller` runs as a background task in the same process
   as the main detection engine.

2. On each poll cycle (default every 60 seconds), it calls each enabled
   connector's `poll()` method.

3. Each connector fetches events from the provider API, normalizes them
   into `Event` objects with a cloud-specific `kind`, and returns them.

4. The poller puts these events into the engine's shared `asyncio.Queue`
   -- the same queue local log tailers use. They flow through the
   standard pipeline: `detector.handle()` -> `_on_cloud_event()` ->
   rule evaluation -> alert / block.

5. A per-event cursor (EventId for CloudTrail, createdDateTime for
   Azure AD, insertId/timestamp for GCP Cloud Logging) prevents the same
   event from being re-ingested.


## Event kinds

| Kind | Source | What it means |
|:---|:---|:---|
| `CLOUD_SIGNIN_FAIL` | All | Sign-in / console login failed |
| `CLOUD_SIGNIN_SUCCESS` | All | Sign-in succeeded (tracked for breach detection) |
| `CLOUD_MFA_FAIL` | All | MFA / 2-Step-Verification challenge failed or was bypassed |
| `CLOUD_RISKY_SIGNIN` | Azure AD, GCP | Provider's risk engine flagged the sign-in, or GCP reported a suspicious login |
| `CLOUD_IMPOSSIBLE_TRAVEL` | Azure AD | Two sign-ins too far apart geographically |


## Detection rules

Five new rules are added to the rule engine:

| Rule ID | Severity | Threshold | Window | Trigger |
|:---|:---|:---|:---|:---|
| `cloud.signin_brute_force` | MEDIUM | 5 failures | 300s | Repeated sign-in failures from one IP |
| `cloud.mfa_failure` | HIGH | 1 | -- | Any MFA failure or bypass |
| `cloud.risky_signin` | HIGH | 1 | -- | Provider risk engine fires |
| `cloud.signin_breach` | HIGH | 3 prior failures | 300s | Success after repeated failures |
| `cloud.impossible_travel` | HIGH | 1 | -- | Geographically impossible sign-in pair |

All rules can be adjusted or disabled from the dashboard Rules tab.


## AWS CloudTrail

Polls the CloudTrail `LookupEvents` API for `ConsoleLogin` events.

AWS Signature Version 4 is implemented directly with `hmac`/`hashlib`.
There is no `boto3` dependency.

### What is detected

- `ConsoleLogin` with `errorMessage = "Failed authentication"` -> `CLOUD_SIGNIN_FAIL`
- `ConsoleLogin` success without `MFAUsed = Yes` -> `CLOUD_MFA_FAIL`
- `ConsoleLogin` success after prior failures from the same IP -> `CLOUD_SIGNIN_BREACH`

### Config

```json
{
  "cloud_identity": {
    "enabled": true,
    "poll_interval_sec": 60,
    "aws": {
      "enabled":           true,
      "access_key_id":     "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region":            "us-east-1",
      "lookback_sec":      300
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable CloudTrail polling |
| `access_key_id` | | IAM access key with `cloudtrail:LookupEvents` permission |
| `secret_access_key` | | Corresponding secret key |
| `region` | `us-east-1` | AWS region for the CloudTrail endpoint |
| `lookback_sec` | `300` | How far back to look on the first poll (subsequent polls use cursor) |

### Required IAM permission

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "cloudtrail:LookupEvents",
      "Resource": "*"
    }
  ]
}
```

Create a dedicated IAM user with only this permission and use its
credentials in config. Never use root credentials.


## Azure AD

Polls Microsoft Graph's `signIns` endpoint using OAuth2 client
credentials flow. The access token is cached and refreshed automatically.

### What is detected

- `status.errorCode != 0` -> `CLOUD_SIGNIN_FAIL`
- `status.errorCode` in `{50074, 50079, 50076}` (MFA-related) -> `CLOUD_MFA_FAIL`
- `riskState` not in `{none, dismissed}` -> `CLOUD_RISKY_SIGNIN`

### Config

```json
{
  "cloud_identity": {
    "azure_ad": {
      "enabled":       true,
      "tenant_id":     "your-tenant-id",
      "client_id":     "your-app-client-id",
      "client_secret": "your-app-client-secret",
      "lookback_sec":  300
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable Azure AD polling |
| `tenant_id` | | Azure AD tenant (directory) ID |
| `client_id` | | App registration client ID |
| `client_secret` | | App registration client secret |
| `lookback_sec` | `300` | How far back on the first poll |

### Required Azure AD permissions

1. Azure Portal > App registrations > New registration
2. API permissions > Add > Microsoft Graph > Application permissions
3. Add `AuditLog.Read.All`
4. Grant admin consent
5. Create a client secret under Certificates & secrets

Note: `AuditLog.Read.All` gives read access to all audit logs in the
tenant. Use a dedicated app registration with no other permissions.


## GCP Cloud Identity

Polls Cloud Logging for Google Workspace login-audit entries that are
already being exported there. Authenticates using a service-account
JWT-bearer grant (RS256-signed via PyJWT's `crypto` extra) rather than
a hand-rolled signer -- see the connector's docstring in
`cnsl/cloud_identity.py` for why RSA signing isn't implemented from
scratch the way AWS's HMAC signing is.

**Prerequisite**: Workspace login-audit events must already reach Cloud
Logging. In the Admin console, go to Reporting > Audit and investigation
> Login audit log, and confirm a log sink (or the project's `_Default`
sink) is capturing them. This connector only reads that log -- it does
not configure the export.

### What is detected

- `login_success` -> `CLOUD_SIGNIN_SUCCESS`
- `login_failure` -> `CLOUD_SIGNIN_FAIL`
- `suspicious_login`, `suspicious_login_less_secure_app`,
  `suspicious_programmatic_login`, `account_disabled_hijacked` ->
  `CLOUD_RISKY_SIGNIN`
- `login_verification`, `2sv_verification_switch` -> `CLOUD_MFA_FAIL`

### Config

```json
{
  "cloud_identity": {
    "gcp": {
      "enabled":               true,
      "project_id":            "my-gcp-project",
      "service_account_email": "cnsl-reader@my-gcp-project.iam.gserviceaccount.com",
      "private_key":           "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
      "lookback_sec":          300
    }
  }
}
```

| Key | Default | Description |
|:---|:---|:---|
| `enabled` | `false` | Enable GCP Cloud Logging polling |
| `project_id` | | GCP project that holds the exported login-audit log |
| `service_account_email` | | The service account's `client_email` (from its JSON key) |
| `private_key` | | The service account's `private_key` (from its JSON key) |
| `lookback_sec` | `300` | How far back to look on the first poll |

### Required setup

1. IAM & Admin > Service Accounts > Create service account
2. Grant it `roles/logging.viewer` on the project
3. Keys > Add key > Create new key (JSON) -- download it
4. Copy `client_email` into `service_account_email` and `private_key`
   into `private_key` above (keep the `\n` line breaks intact)
5. Install the RS256 signing dependency: `pip install "pyjwt[crypto]"`
   (bare PyJWT can verify HS256 tokens but cannot sign RS256 ones)

Use a dedicated service account with only `roles/logging.viewer` --
never a project-owner or editor account.


## REST API

### Connector status

```
GET /api/cloud-identity/status
```

```json
{
  "enabled":          true,
  "any_enabled":      true,
  "poll_interval_sec": 60,
  "events_fed":       142,
  "connectors": {
    "aws_cloudtrail": {
      "enabled":     true,
      "poll_count":  47,
      "error_count": 0,
      "last_error":  null,
      "healthy":     true
    },
    "azure_ad": {
      "enabled":     true,
      "poll_count":  47,
      "error_count": 0,
      "last_error":  null,
      "healthy":     true,
      "token_valid": true
    },
    "gcp_identity": {
      "enabled":     true,
      "poll_count":  47,
      "error_count": 0,
      "last_error":  null,
      "healthy":     true,
      "token_valid": true
    }
  }
}
```


## Dashboard

The Cloud Identity Connectors panel appears in the Settings tab, above
the SIEM / SOAR Connectors section.

Each connector card shows: status (Healthy / Error / Disabled), poll
count, error count, token validity (Azure AD and GCP only), and the
last error message if any -- for GCP, a missing `pyjwt[crypto]`
dependency or a malformed private key both surface here as a plain
`last_error` string rather than a crash.

The panel refreshes automatically when the Settings tab is opened.


## Kill chain integration

Cloud events feed into the kill chain tracker alongside local events:

| Cloud event kind | Kill chain stage |
|:---|:---|
| `CLOUD_SIGNIN_FAIL` | Delivery (stage 2) |
| `CLOUD_SIGNIN_SUCCESS` | Exploitation (stage 3) |
| `CLOUD_MFA_FAIL` | Delivery (stage 2) |
| `CLOUD_RISKY_SIGNIN` | Exploitation (stage 3) |
| `CLOUD_IMPOSSIBLE_TRAVEL` | C2 (stage 5) |

This means an attacker who scans a web server (Reconnaissance) and then
brute-forces an Azure AD account (Delivery) will have both stages visible
in a single kill chain, even though the events came from different sources.


## Failure modes

If a connector's credentials are invalid or the API is unreachable:
- The poll attempt logs an error via `cloud_identity_poll_error`
- The error is visible in the dashboard status card
- The poller retries on the next poll interval
- Local detection is never affected

If `aiohttp` is not installed, connectors gracefully return empty lists.
If GCP is enabled but `pyjwt[crypto]` isn't installed, the GCP connector
reports a clear `last_error` and skips polling rather than raising.
The rest of the detection pipeline is unaffected in either case.


## Origin

Cloud identity integration was listed as future work in the original CNSL
research paper. The paper noted that identity-based attacks against cloud
accounts were increasingly common but outside the scope of host-based
detection. These connectors implement that future work item directly.

The enterprise version of the research paper is available in the separate `cnsl-research` repository.