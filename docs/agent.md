# CNSL Agent -- Remote Log Forwarding

The CNSL agent is a lightweight process that runs on remote servers and
forwards log events to a central CNSL instance over WebSocket. This lets
a single CNSL instance protect an entire fleet.

## Architecture

```
Remote server 1          Remote server 2
+-------------+         +-------------+
|  cnsl.agent |         |  cnsl.agent |
|  tails:     |         |  tails:     |
|  auth.log   |         |  auth.log   |
|  nginx.log  |   WS    |  syslog     |
+------+------+         +------+------+
       |  wss://cnsl.example.com/ws/agent
       +--------------+--------+
                +-----v------+
                |  CNSL      |
                |  /ws/agent |
                |  detector  |
                |  dashboard |
                +------------+
```

Events from all agents flow through the same detection pipeline, GeoIP
enrichment, UEBA, threat feed checks, and notification channels.

---

## Agent Installation

**On each remote server:**

```bash
# Install CNSL (minimal -- no optional deps needed)
pip install cnsl

# Or from source
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl && pip install -e .
```

---

## Configuration

Create `/etc/cnsl/agent.json` on each remote server:

```json
{
  "server":   "wss://cnsl.example.com/ws/agent",
  "token":    "YOUR_JWT_TOKEN",
  "hostname": "web-01",
  "sources": {
    "auth":   "/var/log/auth.log",
    "nginx":  "/var/log/nginx/access.log",
    "apache": null,
    "mysql":  null,
    "ufw":    "/var/log/ufw.log",
    "syslog": "/var/log/syslog"
  },
  "queue_size":    1000,
  "batch_size":    50,
  "flush_interval": 1.0
}
```

| Setting | Description |
|:---|:---|
| `server` | CNSL WebSocket URL. Use `wss://` for TLS (recommended) |
| `token` | JWT token from `POST /api/login` on the central CNSL instance |
| `hostname` | Label shown in dashboard for this agent |
| `sources` | Log file paths to tail. Set to `null` to disable |
| `queue_size` | Max events buffered locally (drop-oldest on overflow) |
| `batch_size` | Events per WebSocket message |
| `flush_interval` | Seconds between flushes when queue is quiet |

### Getting a token

```bash
curl -s -X POST https://cnsl.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"agent-user","password":"password"}' | jq -r .token
```

Create a dedicated `viewer` or `analyst` role user for agents.

---

## Running the Agent

**Manually:**
```bash
python -m cnsl.agent \
  --server wss://cnsl.example.com/ws/agent \
  --token  YOUR_JWT_TOKEN \
  --hostname web-01
```

**With config file:**
```bash
python -m cnsl.agent --config /etc/cnsl/agent.json
```

---

## systemd Service

```bash
sudo nano /etc/systemd/system/cnsl-agent.service
```

```ini
[Unit]
Description=CNSL Log Forwarding Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/python3 -m cnsl.agent --config /etc/cnsl/agent.json
WorkingDirectory=/etc/cnsl
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cnsl-agent
sudo journalctl -u cnsl-agent -f
```

---

## WebSocket Dashboard Connection (`/ws`)

The `/ws` endpoint provides a bidirectional WebSocket connection for
the dashboard browser. It replaces SSE for new clients while keeping
`/stream` (SSE) for backward compatibility.

### Auth handshake

```javascript
const ws = new WebSocket("wss://cnsl.example.com/ws");

// First message must be auth
ws.onopen = () => ws.send(JSON.stringify({
  type: "auth", token: localStorage.getItem("cnsl_token")
}));

ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.type === "auth_ok")  { /* connected */ }
  if (msg.type === "event")    { /* live detection event in msg.data */ }
  if (msg.type === "ping")     { ws.send(JSON.stringify({type:"pong"})); }
};
```

### Bidirectional actions

```javascript
// Block an IP
ws.send(JSON.stringify({ type: "block",   ip: "1.2.3.4" }));
ws.send(JSON.stringify({ type: "unblock", ip: "1.2.3.4" }));
```

Permissions are enforced server-side -- `block`/`unblock` require `analyst+` role.

---

## Server-side Config

On the central CNSL server, agents are accepted by default when auth is enabled.
No extra config needed beyond standard auth:

```json
"auth": {
  "enabled":    true,
  "secret_key": "your-secret",
  "users": {
    "agent-web-01": { "password_hash": "...", "role": "analyst" }
  }
}
```