# Notifications

CNSL supports five notification channels. All are independent — a failure in one
never affects the others. Configure under `"notifications"` in your config file.

## Severity Filter

```json
"notifications": {
  "min_severity": "MEDIUM"
}
```

Only alerts at or above `min_severity` are sent. Values: `LOW`, `MEDIUM`, `HIGH`.

---

## Alert Deduplication

Suppress duplicate alerts from the same IP+severity within a time window:

```json
"notifications": {
  "dedup_window_sec": 300
}
```

Default: `300` seconds (5 minutes). Set to `0` to disable deduplication.

---

## Daily Digest

Send a daily summary of all alerts to Telegram and/or Slack:

```json
"notifications": {
  "daily_digest": {
    "enabled": true,
    "hour": 8
  }
}
```

- `hour` — UTC hour to send the digest (0–23, default: 8)
- Digest includes total alert count, HIGH/MEDIUM/LOW breakdown, unique IPs, and top 3 events

---

## Telegram

1. Create a bot via `@BotFather` on Telegram → copy the bot token
2. Get your chat ID from `@userinfobot`

```json
"telegram": {
  "enabled":   true,
  "bot_token": "123456:ABC-DEF...",
  "chat_id":   "-1001234567890"
}
```

Messages use Telegram Markdown v1. Special characters in ISP names and city
names are automatically escaped so formatting never breaks.

---

## Discord

Create a webhook in your Discord server: Channel Settings → Integrations → Webhooks.

```json
"discord": {
  "enabled":     true,
  "webhook_url": "https://discord.com/api/webhooks/123456/abcdef..."
}
```

Discord alerts use rich embeds with severity color coding (red/orange/blue).

---

## Slack

Create an incoming webhook at https://api.slack.com/apps

```json
"slack": {
  "enabled":     true,
  "webhook_url": "https://hooks.slack.com/services/T.../B.../..."
}
```

---

## Email (SMTP)

Sends HTML + plaintext multipart alerts. Runs in a thread executor — never
blocks the detection engine.

```json
"email": {
  "enabled":        true,
  "smtp_host":      "smtp.gmail.com",
  "smtp_port":      587,
  "use_tls":        true,
  "use_ssl":        false,
  "username":       "alerts@example.com",
  "password":       "your-app-password",
  "from":           "CNSL Alerts <alerts@example.com>",
  "to":             ["soc@example.com", "oncall@example.com"],
  "subject_prefix": "[CNSL]"
}
```

### Provider quick-reference

| Provider | Host | Port | TLS | SSL |
|:---|:---|:---|:---:|:---:|
| Gmail | smtp.gmail.com | 587 | ✓ | — |
| Gmail (SSL) | smtp.gmail.com | 465 | — | ✓ |
| Outlook/Hotmail | smtp-mail.outlook.com | 587 | ✓ | — |
| Yahoo | smtp.mail.yahoo.com | 587 | ✓ | — |
| SendGrid | smtp.sendgrid.net | 587 | ✓ | — |
| Postmark | smtp.postmarkapp.com | 587 | ✓ | — |
| Self-hosted | your.mail.server | 587 | ✓ | — |

**Gmail setup:** Enable 2FA → Google Account → Security → App Passwords → generate password.
Use the App Password, not your regular Gmail password.

### Email alert format

The HTML email includes:
- Severity badge with color (red / orange / blue)
- Source IP, location, ISP
- Fail count and unique users
- Full detection reasons list
- Timestamp

A plaintext fallback is always included for mail clients that do not render HTML.

---

## Generic Webhook

POST a JSON payload to any HTTP endpoint.

```json
"webhook": {
  "enabled":       true,
  "url":           "https://your-server.com/cnsl-alerts",
  "secret_header": "X-CNSL-Secret",
  "secret_value":  "mysecret"
}
```

Payload schema:
```json
{
  "type":       "cnsl_alert",
  "time":       "2026-05-31T10:00:00Z",
  "ip":         "1.2.3.4",
  "severity":   "HIGH",
  "reasons":    ["brute_force: 9 fails in 60s"],
  "fail_count": 9,
  "geo": {
    "country":     "China",
    "countryCode": "CN",
    "city":        "Beijing",
    "isp":         "China Telecom"
  }
}
```

---

## Testing Notifications

**From the dashboard (recommended):**
```
POST /api/notify/test
```
Returns per-channel results: `{"results": {"telegram": "ok", "slack": "error: ..."}}`. Requires `admin` role.

**From the command line:**
```bash
python simulate.py notify
```

Or trigger manually with a brute-force simulation:
```bash
python simulate.py breach
```