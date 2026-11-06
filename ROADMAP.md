# CNSL Engineering Roadmap

This document outlines the architectural direction and milestones for future releases of CNSL (Correlated Network Security Layer).

Current release series: **v3.4.x (LTS / Feature-Complete)**  
Next major milestone: **v4.0 (Lean Core & Kernel Offload)**

---

## Current Status (v3.4.x)

The v3.4.x release line provides a comprehensive, batteries-included security layer for Linux hosts, including multi-vector event correlation, iptables/ipset automated mitigation, honeypot telemetry, file integrity monitoring, and an embedded administrative dashboard.

All current functionality is fully tested and verified across Python 3.10 through 3.13. Future maintenance on v3.4.x is restricted to critical bug fixes and security patches.

---

## Milestone: v4.0 Architecture Evolution

The primary goal of v4.0 is to streamline the core daemon footprint, decouple niche protocol parsers into optional extensions, and offload high-volume mitigation directly to the Linux kernel via eBPF/XDP.

### 1. Modular Extension Decoupling (`cnsl-contrib`)
To maintain a minimalist memory footprint (<20 MB resident set size) on small VPS instances, niche enterprise modules will be moved from the core package into optional plugin packages:
- **OT / Industrial Protocols:** Move Modbus and DNP3 parsers (`cnsl/ot_parser.py`) into an optional `cnsl-ot` extension.
- **Cloud IAM Pollers:** Extract AWS CloudTrail, Azure AD, and GCP IAM connectors (`cnsl/cloud_identity.py`) into a dedicated `cnsl-cloud` package.
- **Case Management SLA:** Decouple SOC ticket tracking (`cnsl/case_sla.py`) into an optional webhook integration.

### 2. In-Kernel Fast-Path Offload (eBPF / XDP)
- **Direct Kernel Drop:** Replace userspace `subprocess` calls to `iptables` and `ipset` with direct eBPF/XDP map updates (integrating with kernel packet filters such as `xdp-guard`).
- **Wire-Speed Defense:** Drop malicious ingress traffic at the network driver / NIC layer before packets traverse the Linux network stack, eliminating CPU overhead during high-PPS volumetric scans.

### 3. Documentation & Asset Consolidation
- **Consolidated Manuals:** Condense the 33 individual reference documents in `docs/` into 6 authoritative, cohesive operational manuals:
  1. `quickstart.md` — Initial deployment, prerequisites, and first run
  2. `configuration.md` — Complete reference for `config.json`
  3. `detection-rules.md` — Thresholds, pattern learning, and correlation logic
  4. `architecture.md` — Core event loop, state machine, and data flow
  5. `deployment.md` — systemd, Docker, and Kubernetes deployment guides
  6. `api-reference.md` — REST and WebSocket endpoints
- **Static Template Separation:** Extract inline dashboard HTML/JS strings (`cnsl/dashboard_html.py`) into clean, independent template assets.

### 4. Hardened Unprivileged Daemon Profile
- **Capability Bounding:** Formalize default execution under an unprivileged `cnsl` system user leveraging Linux capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`) instead of requiring full root privileges.
- **Systemd Sandboxing:** Package production systemd unit files with `ProtectSystem=strict`, `ProtectHome=true`, and private temporary directories.

---

## Contributing & Development

Enhancements adhering to the core host-defense philosophy are welcome. Submissions should prioritize low resource overhead, high throughput, and zero external runtime dependencies for the core detection loop.
