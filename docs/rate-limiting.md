# Rate Limiting & DDoS Protection

CNSL includes per-IP request rate limiting and DDoS detection for the
web dashboard. This protects the API from abuse, credential stuffing
against the login endpoint, and volumetric DDoS attacks.

## How It Works

**Rate limiting** — sliding window per IP. Each IP gets N requests per
window. Exceeding the limit returns `429 Too Many Requests` with a
`Retry-After` header.

**DDoS detection** — separate high-frequency counter per IP. If an IP
sends more than `ddos_threshold` requests in `ddos_window_sec` seconds,
it is flagged as a DDoS source and optionally auto-blocked via iptables/ipset.

**Per-endpoint limits** — stricter limits for sensitive endpoints like
`/api/login` to prevent credential stuffing.

---

## Config

```json
"rate_limiting": {
  "enabled":                true,
  "requests_per_min":       60,
  "burst":                  20,
  "window_sec":             60,
  "ddos_threshold":         500,
  "ddos_window_sec":        10,
  "auto_block":             true,
  "auto_block_duration_sec": 900,
  "whitelist":              ["127.0.0.1", "::1", "10.0.0.0/8"],
  "endpoints": {
    "/api/login":      { "requests_per_min": 10, "window_sec": 60 },
    "/api/2fa/verify": { "requests_per_min": 10, "window_sec": 60 }
  }
}
```

| Setting | Description |
|:---|:---|
| `requests_per_min` | Max requests per IP per window (default: 60) |
| `burst` | Extra requests allowed above the limit (default: 20) |
| `window_sec` | Sliding window duration in seconds (default: 60) |
| `ddos_threshold` | Requests in `ddos_window_sec` before DDoS flag (default: 500) |
| `ddos_window_sec` | DDoS detection window in seconds (default: 10) |
| `auto_block` | Block DDoS IPs via iptables/ipset (default: true) |
| `auto_block_duration_sec` | How long to block DDoS IPs (default: 900s = 15min) |
| `whitelist` | IPs never rate-limited (your management IPs, load balancers) |
| `endpoints` | Per-endpoint overrides — override `requests_per_min` and `window_sec` |

---

## Recommended Config for Production

```json
"rate_limiting": {
  "enabled":                true,
  "requests_per_min":       120,
  "burst":                  30,
  "ddos_threshold":         300,
  "ddos_window_sec":        5,
  "auto_block":             true,
  "whitelist":              ["127.0.0.1", "YOUR_MONITORING_IP"],
  "endpoints": {
    "/api/login":      { "requests_per_min": 5,  "window_sec": 60 },
    "/api/2fa/verify": { "requests_per_min": 5,  "window_sec": 60 },
    "/api/block":      { "requests_per_min": 30, "window_sec": 60 }
  }
}
```

---

## API Reference

### Rate Limit Stats

```
GET /api/rate-limit
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rate-limit | jq .
```

```json
{
  "enabled":            true,
  "requests_per_min":   60,
  "ddos_threshold":     500,
  "auto_block":         true,
  "active_blocks":      2,
  "active_block_ips":   {
    "1.2.3.4": 842.3,
    "5.6.7.8": 120.1
  },
  "total_requests":     48293,
  "rate_limited":       127,
  "ddos_detections":    3,
  "auto_blocked_total": 3
}
```

### Top Requesters

```
GET /api/rate-limit/top?n=10
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8765/api/rate-limit/top?n=5"
```

```json
{
  "top": [
    { "ip": "203.0.113.5", "requests": 58 },
    { "ip": "198.51.100.2", "requests": 34 }
  ]
}
```

### Reset Rate Limit for IP (analyst+)

```
POST /api/rate-limit/reset/{ip}
```

```bash
curl -s -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8765/api/rate-limit/reset/1.2.3.4
```

Clears the sliding window and any temporary blocks for that IP.

---

## Behind a Reverse Proxy

If CNSL runs behind nginx or a load balancer, enable `X-Forwarded-For` trust:

```nginx
# nginx.conf
location / {
    proxy_pass         http://127.0.0.1:8765;
    proxy_set_header   X-Forwarded-For $remote_addr;
    proxy_set_header   Host $host;
}
```

CNSL reads `X-Forwarded-For` automatically and uses the real client IP
for rate limiting (not the proxy IP).

---

## Compliance Reports

Rate limit statistics are automatically included in compliance reports:

- Total requests processed
- Rate-limited requests count
- DDoS detections
- Auto-blocked IPs
- Top 5 requesters in the period

See [compliance reports documentation](configuration.md#reports) for details.