# CNSL Engineering Roadmap

This document outlines the architectural direction and structured milestones for CNSL (Correlated Network Security Layer).

Current release series: **v3.4.x / v3.5 (LTS / Feature-Complete SIEM & SOAR)**  
Next major milestone: **v4.0 (Kernel Offload, eBPF/XDP Line-Rate Defense & Sovereign P2P Federation)**

---

## 1. Completed Milestone: v3.5 Sovereign SIEM & SOAR Foundation

The v3.5 milestone establishes a production-grade, multi-vector active defense system for Linux infrastructure with 1,300+ automated unit and integration tests (100% pass rate):

- **Multi-Source Correlated Ingestion:** Simultaneous ingestion and correlation across auth logs, web (Nginx/Apache), database (MySQL), firewall (UFW), network syslog (RFC 3164/5424), Wazuh, STIX/TAXII, and Grafana Loki (LogQL query_range pull).
- **Intelligent Threat Analytics:** Multi-stage kill chain tracking, unsupervised ML anomaly detection (Isolation Forest), Sigma rule engine, and recurrent attack pattern learning.
- **Advanced Deception & Containment:** Filesystem canary honeytokens (fake AWS/DB credentials), container runtime anomaly detection (Docker/Kubernetes exec and privilege escalation checks), and automated SOAR response playbooks.
- **Threat Intelligence & SOC Copilot:** MITRE ATT&CK enterprise tactic heatmaps and offline heuristic incident root-cause analysis with optional local Ollama, Gemini, and OpenAI backends.
- **Management & Observability:** Real-time web UI, visual configuration editor service with validation and versioning archives, JWT/OIDC authentication, and Prometheus metrics.

---

## 2. Milestone v4.0: High-Performance eBPF/XDP Kernel Defense Engine

**Goal:** Offload intrusion mitigation from userland packet filtering to native Linux kernel network driver space to achieve wire-speed line-rate defense (100 Gbps) without CPU exhaustion.

- **In-Kernel Direct Packet Dropping (XDP/TC):**
  - Implement native eXpress Data Path (XDP) programs to drop offending IPs and subnets in NIC driver space before `sk_buff` allocation.
  - Implement Traffic Control (TC) BPF programs for egress rate-limiting and connection disruption.
  - Implement fallback drivers for older Linux kernels lacking native XDP support (v5.4+).
- **Zero-Copy Kernel-Userland Synchronization:**
  - Leverage BPF ring-buffers (`BPF_MAP_TYPE_RINGBUF`) for non-blocking, zero-copy packet telemetry between kernel space and userland.
  - Implement atomic BPF hash-map updates for lockless ban list synchronization.
- **CO-RE (Compile Once - Run Everywhere) Portability:**
  - Build BPF Type Format (BTF) portable binaries compatible across major Linux distributions without requiring kernel development headers on the target host.

---

## 3. Milestone v4.1: Decentralized Sovereign Threat Federation

**Goal:** Enable independent, self-hosted CNSL instances to share threat intelligence collaboratively without relying on centralized SaaS vendors or leaking internal network topology.

- **Zero-Knowledge Threat Sharing (P2P Gossip):**
  - Design an encrypted peer-to-peer gossip protocol over mutual TLS and Noise protocol framework.
  - Implement cryptographic indicator-of-compromise (IOC) hashing (salted Bloom filters and HMAC ring identifiers) so participating nodes exchange verified attack signatures without disclosing internal IP addressing or sensitive URLs.
- **Bi-Directional STIX 2.1 & TAXII 2.1 Sync:**
  - Fully automated polling and publishing of structured threat intelligence feeds.
  - Autonomous trust scoring and reputation aging for federated nodes.

---

## 4. Milestone v4.2: Hardened Deception & Container Telemetry

**Goal:** Extend threat detection into Linux kernel system-call tracing and Kubernetes container runtime interfaces.

- **Kernel-Level Canary Lures:**
  - eBPF-based `sys_enter_openat` and `sys_enter_read` tracing on designated deception paths to detect credential scraping and memory dumping with zero false positives.
- **Container Runtime Socket Hooks:**
  - Native gRPC stream listeners for containerd (`/run/containerd/containerd.sock`) and CRI-O to intercept container breakout attempts and unauthorized namespace modifications.

---

## 5. Milestone v4.3: Multi-Distro Packaging & Minimal Distribution

**Goal:** Ensure turn-key installation and minimal system footprints across all production environments.

- **Native Package Feeds:**
  - Automated build pipelines for `.deb` (Debian/Ubuntu), `.rpm` (RHEL/Fedora/Rocky), Alpine APK, and Arch PKGBUILD.
  - Systemd hardened service units with `ProtectSystem=strict`, `NoNewPrivileges=true`, and ambient capability drops (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_BPF`).
- **Minimal Distroless / Scratch Containers:**
  - Ultra-lightweight container images (<30 MB) with zero unnecessary shell utilities to minimize attack surface in Kubernetes deployments.
- **Modular Extension Decoupling (`cnsl-contrib`):**
  - Extract niche enterprise protocols (SCADA/Modbus/DNP3) and cloud IAM pollers into optional lightweight plugin packages.

---

## 6. Engineering & Quality Assurance Standards

- **Zero Commercial Telemetry:** 100% self-hosted; zero cloud tracking, phone-home, or third-party proprietary dependencies.
- **Strict Test Coverage:** Every new module and kernel driver must maintain 100% automated test coverage with regression guards.
- **Deterministic Resource Limits:** Resident memory capped below 80 MB for core userland daemon; kernel maps bounded by strict pre-allocated sizing.
- **Pure Open Source:** All contributions released under the GNU Affero General Public License (AGPL-3.0).
