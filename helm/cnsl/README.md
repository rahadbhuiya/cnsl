# CNSL Helm Chart

Deploys [CNSL](https://github.com/rahadbhuiya/cnsl) (Correlated Network
Security Layer) -- a self-hosted SIEM for Linux -- to Kubernetes.

## Quick start

```bash
helm install cnsl ./helm/cnsl \
  --namespace cnsl --create-namespace
```

By default this installs a **DaemonSet** (one CNSL pod per node, each
monitoring that node's own traffic/logs and managing that node's own
iptables/ipset rules) with `actions.dry_run: true` -- CNSL will log what it
*would* block without touching any firewall rules until you review its
detections and flip that setting.

## Why DaemonSet by default?

CNSL is designed to protect the host it's running on: it captures live
traffic (tcpdump), tails local log files, and manages that host's own
iptables/ipset rules. In a cluster, that means **every node needs its own
CNSL instance** -- a single Deployment replica only ever sees and protects
one node. Set `deploymentMode: deployment` only for a single-node setup
(e.g. a bastion host) where that's actually what you want.

To tie every node's detections together into one view, enable the bundled
Redis (`redis.enabled: true`) and turn on federation in `.Values.config` --
see [`docs/kubernetes.md`](../../docs/kubernetes.md) in the main repo for
the full walkthrough, and hit `GET /api/federation/hub` afterward for the
aggregated multi-node picture.

## Configuration

CNSL's own `config.json` is supplied wholesale via `.Values.config` (a raw
string, rendered through Helm's `tpl` so it can reference chart-generated
names like the bundled Redis service). See
[`docs/configuration.md`](../../docs/configuration.md) in the main repo for
every available key -- this chart does not attempt to expose each one as an
individual Helm value.

Common overrides:

```bash
# Enable real blocking (default is dry-run/log-only)
helm install cnsl ./helm/cnsl -f my-values.yaml

# my-values.yaml:
config: |
  {
    "actions": {"dry_run": false, "block_duration_sec": 900,
                "block_backend": "iptables", "chain": "INPUT"},
    "store": {"backend": "sqlite", "db_path": "/var/lib/cnsl/cnsl_state.db"},
    "dashboard": {"enabled": true, "host": "0.0.0.0", "port": 8765},
    "redis": {"enabled": true, "host": "{{ include `cnsl.redis.fullname` . }}", "port": 6379}
  }
redis:
  enabled: true
```

| Value | Default | Description |
|---|---|---|
| `deploymentMode` | `daemonset` | `daemonset` (per-node) or `deployment` (single instance) |
| `image.repository` / `.tag` | `ghcr.io/rahadbhuiya/cnsl` / chart's `appVersion` | Image to run |
| `hostNetwork` | `true` | Required for tcpdump + iptables to see/act on real host traffic |
| `dashboard.enabled` / `.port` | `true` / `8765` | Dashboard + REST API |
| `persistence.hostPath` | `/var/lib/cnsl` | Per-node local state (DaemonSet mode -- a shared PVC can't work across nodes) |
| `persistence.enabled` / `.size` | `true` / `2Gi` | Used for the PVC in `deployment` mode when `hostPath` is unset |
| `hostLogs.enabled` / `.path` | `true` / `/var/log` | Mount the node's own logs read-only for nginx/apache/mysql/ufw/syslog tailing |
| `secrets.jwtSecret` / `.apiSecret` | auto-generated | Pin explicitly to manage secrets externally |
| `redis.enabled` | `false` | Bundle a Redis pod for blocklist sync + federation |
| `service.enabled` / `.type` | `true` / `ClusterIP` | Load-balances across all DaemonSet pods' dashboards |

## Security context

Containers run with `NET_ADMIN` and `NET_RAW` capabilities (needed for
iptables/ipset and tcpdump), matching the project's own
`docker-compose.yml`. This is a real privilege grant -- review your cluster's
Pod Security Standards / admission policy before deploying to a
multi-tenant cluster.

## Uninstall

```bash
helm uninstall cnsl -n cnsl
```

Data under `persistence.hostPath` on each node is **not** removed
automatically (by design -- it's your incident history). Clean it up
manually if you want a full teardown.