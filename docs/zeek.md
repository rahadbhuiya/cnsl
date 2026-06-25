# Zeek Log Ingestion

CNSL can ingest logs from [Zeek](https://zeek.org) (formerly Bro), a powerful
network security monitor. Zeek runs on your network and writes detailed logs;
CNSL tails those logs and feeds them into the detection pipeline.

## Supported Log Files

| Log | Events | Detection |
|:---|:---|:---|
| `conn.log` | `NET_CONN` | Port scan flood, connection flood |
| `ssh.log` | `SSH_FAIL` / `SSH_SUCCESS` | Brute-force, credential breach |
| `http.log` | `WEB_SCAN` / `WEB_AUTH_FAIL` / `WEB_EXPLOIT_ATTEMPT` | Scan flood, auth flood, exploit |
| `dns.log` | `DNS_QUERY` | DNS tunneling (high-entropy subdomains) |
| `notice.log` | `ZEEK_NOTICE` | Zeek's built-in detection framework |
| `weird.log` | `ZEEK_WEIRD` | Protocol anomalies |

---

## Config

```json
"zeek": {
  "enabled":               true,
  "log_dir":               "/opt/zeek/logs/current",
  "format":                "tsv",
  "dns_entropy_threshold": 3.5,
  "conn_scan_threshold":   20,
  "logs": {
    "conn":   true,
    "ssh":    true,
    "http":   true,
    "dns":    true,
    "notice": true,
    "weird":  true
  }
}
```

| Setting | Description |
|:---|:---|
| `enabled` | Enable Zeek ingestion |
| `log_dir` | Path to Zeek's current log directory |
| `format` | `"tsv"` (default Zeek output) or `"json"` (with JSON logging policy) |
| `dns_entropy_threshold` | Shannon entropy threshold for DNS tunneling detection (default: 3.5) |
| `conn_scan_threshold` | Distinct dest ports before port-scan alert (default: 20) |
| `logs` | Per-log-file enable/disable |

---

## Log Format Support

### TSV (default)

Standard Zeek tab-separated output. CNSL reads the `#fields` header line
automatically, so custom field orders work correctly.

```
#separator \x09
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p ...
1620000000.0 abc123 1.2.3.4 54321 10.0.0.1 22 ...
```

### JSON

Enable in Zeek with:
```zeek
# /opt/zeek/share/zeek/site/local.zeek
@load policy/tuning/json-logs
```

Then set `"format": "json"` in CNSL config.

---

## Detection Details

### SSH Brute-Force (`ssh.log`)

Zeek's `ssh.log` records every SSH authentication attempt including
the result. CNSL maps these directly to `SSH_FAIL` / `SSH_SUCCESS`
events and feeds them into the existing SSH brute-force and credential
breach rules.

### Web Attacks (`http.log`)

- **Exploit paths** -- `/wp-login.php`, `/.env`, `/phpmyadmin`, path traversal, etc.
- **Auth failures** -- HTTP 401/403 responses
- **Scanner user-agents** -- sqlmap, nikto, nmap, masscan, gobuster, nuclei, etc.
- **Directory enumeration** -- HTTP 404 responses

### DNS Tunneling (`dns.log`)

Flags queries with high [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory))
in the subdomain -- a strong indicator of DNS tunneling or data exfiltration.

```
# Low entropy (normal):   www.google.com  -> entropy ~= 1.5
# High entropy (tunnel):  x7Kq2mN9pR4wZ.evil.com -> entropy ~= 3.8
```

The threshold is configurable. Lower = more sensitive (more false positives),
higher = less sensitive (may miss slow tunneling).

### Zeek Notices (`notice.log`)

Zeek's built-in detection framework generates notices for events like:
- `Scan::Port_Scan`
- `Scan::Address_Scan`
- `SSH::Password_Guessing`
- `Weird::Activity`

CNSL logs all notices as `ZEEK_NOTICE` events.

### Protocol Anomalies (`weird.log`)

Zeek logs protocol violations and anomalies (bad checksums, unexpected
flags, etc.) as `ZEEK_WEIRD` events. These are logged but do not
trigger automatic blocks.

---

## Common Log Paths

| Zeek install | Log dir |
|:---|:---|
| Package manager | `/opt/zeek/logs/current` |
| Manual build | `/usr/local/zeek/logs/current` |
| Zeekctl | `/opt/zeek/logs/current` |
| Docker | `/logs` (varies) |

---

## Zeek Setup Tips

**Install Zeek:**
```bash
# Ubuntu/Debian
sudo apt install zeek

# Or from source: https://github.com/zeek/zeek
```

**Start Zeek on an interface:**
```bash
sudo zeekctl deploy
# or
sudo zeek -i eth0 local
```

**Verify logs are being written:**
```bash
ls -lh /opt/zeek/logs/current/
# conn.log  dns.log  http.log  notice.log  ssh.log  weird.log
```

**Enable JSON output (optional):**
```bash
echo '@load policy/tuning/json-logs' >> /opt/zeek/share/zeek/site/local.zeek
sudo zeekctl deploy
```