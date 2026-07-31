# Deploying CNSL on Kubernetes

CNSL ships a Helm chart at `helm/cnsl/` for cluster deployment. This guide
covers the concepts the chart's README doesn't -- read that first for the
value reference table.

## Why DaemonSet, not Deployment

CNSL is built to protect the host it runs on: it captures live traffic
(tcpdump), tails that host's own log files, and manages that host's own
iptables/ipset rules. None of that is meaningful from a *different* node.
A single `Deployment` replica only ever sees and protects the one node
it happens to land on -- every other node in the cluster stays unmonitored.

The chart therefore defaults to a **DaemonSet**: one independent CNSL pod
per node, each with:
- `hostNetwork: true` so tcpdump sees the node's real interface traffic
  (not a pod-network-namespaced view of it)
- `NET_ADMIN` + `NET_RAW` capabilities so it can actually write iptables/ipset
  rules and open raw sockets
- a `hostPath` volume for `/var/lib/cnsl` (that node's own incidents/blocks/
  FIM-baseline SQLite state -- **not** a PVC, since a single ReadWriteOnce
  volume can't be mounted by pods on different nodes at once)
- a read-only `hostPath` mount of `/var/log` so it can tail nginx/apache/
  mysql/ufw/syslog logs living on that node

Use `deploymentMode: deployment` only when you genuinely want a single
CNSL instance watching a single node (e.g. a bastion/jump host) rather than
cluster-wide coverage.

## Tying nodes together: federation + the hub view

Each DaemonSet pod is independent by default -- no shared state, no
cross-node correlation. To connect them:

1. Enable the bundled Redis: `--set redis.enabled=true`
2. In `.Values.config`, set `"redis": {"enabled": true, ...}` (the chart's
   default config already points `redis.host` at the bundled service's
   real name via Helm's `tpl` function -- see the chart README)
3. Add a `"federation"` block to `.Values.config` (see
   [`docs/configuration.md`](configuration.md) in this repo)

Once federation is running, hit **`GET /api/federation/hub`** (through the
chart's Service, which load-balances across all DaemonSet pods -- see
[`docs/api.md`](api.md)'s Federation section) for one aggregated view of
every node's health, incident counts, active blocks, and any IP seen
attacking 2+ nodes.

```bash
kubectl -n cnsl port-forward svc/cnsl 8765:8765
curl -H "Authorization: Bearer $TOKEN" http://localhost:8765/api/federation/hub
```

## A note on the ClusterIP Service with hostNetwork pods

The chart's Service selects the DaemonSet's pods by label, same as any
other Service. Because those pods use `hostNetwork: true`, their pod IP
*is* the node's IP -- most CNIs (iptables or IPVS kube-proxy mode) route
this correctly, but it's a less common combination than pod-network
Services, so verify connectivity after install (`helm test <release>` runs
a basic health check against it) rather than assuming it "just works" on
every CNI.

## Getting real blocking working

The chart's default config runs with `actions.dry_run: true` -- CNSL logs
every detection and what it *would* block, but never actually touches
iptables. This is intentional: review detections in your environment for a
while before flipping it. When ready:

```bash
helm upgrade cnsl ./helm/cnsl --reuse-values --set-string \
  config="$(cat my-production-config.json)"
```

or maintain a `values-prod.yaml` with your full `config` block and
`helm upgrade -f values-prod.yaml`.

## Log ingestion beyond hostPath-mounted files

For nodes where you can't (or don't want to) mount `/var/log` directly --
e.g. managed node pools with restricted hostPath access -- point cloud log
sources at CNSL's `cloud_identity`/log-source connectors instead (AWS
CloudTrail, Azure AD, GCP) or use the [remote syslog receiver /
Wazuh integration](configuration.md#remote-syslog-ingestion): any node,
container runtime, or Wazuh manager forwarding to CNSL's Service on its
syslog port works without a hostPath mount at all.

## Uninstalling

```bash
helm uninstall cnsl -n cnsl
```

`persistence.hostPath` data on each node is left in place deliberately --
it's your incident history, not ephemeral cache. Remove
`/var/lib/cnsl` on each node manually for a full teardown.