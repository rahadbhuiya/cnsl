# Installation

## Requirements

- Python 3.10+
- Linux (Ubuntu, Debian, CentOS, RHEL, Fedora, OpenSUSE)
- `sudo` access for live blocking (dry-run works without it)

## Quick Install

```bash
git clone https://github.com/rahadbhuiya/cnsl.git
cd cnsl

python3 -m venv venv
source venv/bin/activate
pip install -e ".[full]"
```

## Install Extras

```bash
pip install -e .            # core only (pure stdlib — zero deps)
pip install -e ".[full]"    # everything recommended
pip install -e ".[dev]"     # + testing tools
```

| Extra | Packages | Required for |
|:---|:---|:---|
| `full` | aiohttp, aiosqlite, pyyaml, bcrypt, sklearn, numpy, reportlab | Dashboard, DB, auth, ML, PDF reports |
| `auth` | bcrypt, PyJWT | Dashboard login |
| `db` | aiosqlite | SQLite persistence |
| `geoip` | geoip2 | MaxMind offline GeoIP |
| `ml` | scikit-learn, numpy | ML anomaly detection |
| `reports` | reportlab | PDF compliance reports |
| `dev` | pytest + all above | Running tests |

> Always use the virtualenv Python (`venv/bin/python`) with `sudo`.
> Running `sudo python` uses the system Python which may not have all packages.

## Docker

```bash
docker build -t cnsl .

docker run --rm \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --network host \
  -v /var/log:/var/log:ro \
  -v /etc/cnsl:/etc/cnsl:ro \
  cnsl --config /etc/cnsl/config.json --execute --dashboard
```

## systemd Service

```bash
sudo nano /etc/systemd/system/cnsl.service
```

```ini
[Unit]
Description=CNSL — Correlated Network Security Layer
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=root
ExecStart=/opt/cnsl/venv/bin/python -m cnsl \
  --config /etc/cnsl/config.json \
  --execute \
  --dashboard
WorkingDirectory=/opt/cnsl
Restart=always
RestartSec=5
StandardOutput=append:/var/log/cnsl/service.log
StandardError=append:/var/log/cnsl/service.log

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cnsl
sudo journalctl -u cnsl -f
```

## Auth Log Paths by OS

| OS | Default path |
|:---|:---|
| Ubuntu / Debian | `/var/log/auth.log` |
| CentOS / RHEL / Fedora | `/var/log/secure` |
| OpenSUSE | `/var/log/messages` |