# Two-Factor Authentication (2FA)

CNSL supports TOTP-based 2FA compatible with Google Authenticator, Authy,
and any RFC 6238 authenticator app. 2FA is per-user and optional.

## Requirements

- Dashboard auth must be enabled (`auth.enabled: true`)
- `pyotp` must be installed: `pip install pyotp`

## How It Works

The login flow becomes two steps when 2FA is enabled:

```
1. Enter username + password  ->  partial token (valid 5 min)
2. Enter 6-digit OTP code     ->  full access token
```

A partial token is only valid for the `/api/2fa/verify` endpoint.
It cannot access any other dashboard routes.

---

## Enabling 2FA (per user)

### Step 1 -- Generate QR code

Log in to the dashboard, then call:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/2fa/setup | jq .
```

Response:
```json
{
  "uri": "otpauth://totp/CNSL:admin?secret=BASE32SECRET&issuer=CNSL",
  "username": "admin"
}
```

Scan the URI as a QR code with your authenticator app.
You can generate a QR code from the URI with any online tool or:

```bash
pip install qrcode pillow
python3 -c "
import qrcode, sys
uri = sys.argv[1]
qr = qrcode.make(uri)
qr.save('cnsl_2fa_qr.png')
print('QR saved to cnsl_2fa_qr.png')
" "otpauth://totp/CNSL:admin?secret=..."
```

### Step 2 -- Confirm with first OTP

After scanning, enter the first 6-digit code to activate:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}' \
  http://127.0.0.1:8765/api/2fa/confirm | jq .
```

Success response -- **save these backup codes now, they are shown only once:**

```json
{
  "ok": true,
  "backup_codes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    "...8 codes total..."
  ]
}
```

2FA is now active for this user.

---

## Logging In with 2FA

### Dashboard (browser)

The login page automatically shows a second step for the OTP code.
Works with TOTP codes and backup codes.

### API (curl/script)

```bash
# Step 1: password login
PARTIAL=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  http://127.0.0.1:8765/api/login | jq -r .partial_token)

# Step 2: submit OTP
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"partial_token\":\"$PARTIAL\",\"code\":\"123456\"}" \
  http://127.0.0.1:8765/api/2fa/verify | jq -r .token)

echo "Token: $TOKEN"
```

---

## Backup Codes

8 single-use backup codes are generated when 2FA is activated.
Use them if you lose access to your authenticator app.

- Each code can only be used once
- Format: `XXXX-XXXX` (case insensitive, dash optional)
- Check remaining count:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/2fa/status
```

```json
{
  "enabled": true,
  "backup_codes_left": 6,
  "pyotp_available": true
}
```

If you run low on backup codes, disable and re-enable 2FA to generate new ones.

---

## Disabling 2FA

Requires password confirmation:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password": "your-password"}' \
  http://127.0.0.1:8765/api/2fa/disable
```

---

## API Reference

| Endpoint | Method | Auth | Description |
|:---|:---|:---|:---|
| `/api/login` | POST | -- | Step 1: password login. Returns `needs_2fa: true` + `partial_token` if 2FA enabled |
| `/api/2fa/verify` | POST | partial token | Step 2: submit OTP. Returns full access token |
| `/api/2fa/setup` | POST | full token | Generate new TOTP secret, returns `otpauth://` URI |
| `/api/2fa/confirm` | POST | full token | Confirm with first OTP, activates 2FA, returns backup codes |
| `/api/2fa/disable` | POST | full token | Disable 2FA (requires password) |
| `/api/2fa/status` | GET | full token | Check 2FA status and backup codes remaining |

---

## Security Notes

- Partial tokens expire after **5 minutes** -- if you do not complete 2FA in time, start over
- TOTP allows +/-1 window (+/-30 seconds) for clock drift
- Backup codes are SHA-256 hashed before storage -- even with DB access they cannot be recovered
- Brute-force protection from the password step still applies -- 5 failed password attempts locks the IP for 60 seconds