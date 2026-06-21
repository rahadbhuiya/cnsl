# Cloud Identity Log Connectors

CNSL polls AWS CloudTrail and Azure AD for sign-in and authentication
events and feeds them into the same detection pipeline used for local
Linux logs.

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
   Azure AD) prevents the same event from being re-ingested.


## Event kinds

| Kind | Source | What it means |
|:---|:---|:---|
| `CLOUD_SIGNIN_FAIL` | Both | Sign-in / console login failed |
| `CLOUD_SIGNIN_SUCCESS` | Both | Sign-in succeeded (tracked for breach detection) |
| `CLOUD_MFA_FAIL` | Both | MFA challenge failed or was bypassed |
| `CLOUD_RISKY_SIGNIN` | Azure AD | Provider's risk engine flagged the sign-in |
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
    }
  }
}
```


## Dashboard

The Cloud Identity Connectors panel appears in the Settings tab, above
the SIEM / SOAR Connectors section.

Each connector card shows: status (Healthy / Error / Disabled), poll
count, error count, token validity (Azure AD only), and the last error
message if any.

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
The rest of the detection pipeline is unaffected.


## Origin

Cloud identity integration was listed as future work in the original CNSL
research paper. The paper noted that identity-based attacks against cloud
accounts were increasingly common but outside the scope of host-based
detection. These connectors implement that future work item directly.

See `../old-research/paper/paper2.md` for the enterprise paper that
first described this requirement.