# ITSA Network OS — System Requirements Specification

> **Document ID:** DOC-REQ-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Traceability & Classification Standard

Requirements in ITSA Network OS are assigned stable alphanumeric identifiers. Every implementation task, commit, and unit test must trace directly back to an approved requirement ID.

- **Status Categories:** `VERIFIED` (implemented & tested), `IN_PROGRESS` (active milestone), `PLANNED` (roadmap item).
- **Impact Classifications:**
  - `Level 1 (Read-Only):` Safe non-intrusive queries, passive listening, local computation.
  - `Level 2 (Bounded Diagnostic):` Explicit network handshake, timeout-bounded socket connection.
  - `Level 3 (Configuration Modification):` Host or device configuration change; requires user prompt & dry-run.
  - `Level 4 (High-Risk Operation):` Firmware flash, interface reset, bootloader alteration; requires administrative authentication.

---

## 2. Core Application & Platform Requirements (REQ-CORE)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-CORE-001** | Python Runtime Isolation | Level 1 | `VERIFIED` | The platform must execute on Python 3.10+ (tested on 3.13+) in an isolated virtual environment without modifying system-wide packages. |
| **REQ-CORE-002** | Non-Root Host Execution | Level 1 | `VERIFIED` | The core application and user interfaces must execute strictly under unprivileged user permissions (non-root). |
| **REQ-CORE-003** | Structured Logging & Masking | Level 1 | `VERIFIED` | Structured logging must redact passwords, credentials, tokens, and private keys automatically before disk write or display. |
| **REQ-CORE-004** | Centralized Safe Configuration | Level 1 | `VERIFIED` | Configuration must load from `~/.config/itsa-network-os/config.json` with immutable safe defaults and zero unauthorized cloud beaconing. |
| **REQ-CORE-005** | Host Platform Health Monitoring | Level 1 | `VERIFIED` | The platform must evaluate runtime health, CPU core availability, virtual memory limits, and storage headroom non-destructively. |
| **REQ-CORE-006** | Dual Form Factor Support | Level 1 | `VERIFIED` | The application must function identically as a local CLI/GUI utility on Debian or inside the bootable Debian 13 Live ISO environment. |

---

## 3. Network Discovery & Interface Intelligence (REQ-NET)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-NET-001** | Local Interface Discovery | Level 1 | `VERIFIED` | Must discover all host physical, virtual, and loopback interfaces, operstate, MAC address, MTU, IPv4 addresses, IPv6 addresses, and netmasks from the Linux kernel. |
| **REQ-NET-002** | RFC Subnet Calculation | Level 1 | `VERIFIED` | Must calculate exact network address, broadcast, netmask, wildcard mask, host capacity, and usable range for IPv4/IPv6, including RFC 3021 /31 point-to-point subnets. |
| **REQ-NET-003** | Non-Root Latency Benchmarking | Level 2 | `VERIFIED` | Must benchmark TCP round-trip latency to a target host and port without root privileges, computing min, max, average, and jitter. |
| **REQ-NET-004** | DNS Diagnostics | Level 2 | `VERIFIED` | Must resolve host records (A, AAAA) safely, record response latency in milliseconds, and parse system nameservers from `/etc/resolv.conf`. |
| **REQ-NET-005** | Live Bandwidth Monitoring | Level 1 | `VERIFIED` | Must sample live byte and packet counters from Linux `/proc/net/dev` and compute real-time RX/TX throughput rates (KB/s, MB/s) and packet drops. |
| **REQ-NET-006** | System Routing & VLAN Inspection | Level 1 | `VERIFIED` | Must parse `/proc/net/route` non-destructively, identifying default gateways, interface metrics, and 802.1Q VLAN subinterface naming conventions. |
| **REQ-NET-007** | OSPF Dijkstra SPF Simulation | Level 1 | `VERIFIED` | Must simulate step-by-step Link-State Database (LSDB) shortest path calculations, mathematical edge relaxation, and dynamic link failure convergence. |

---

## 4. Multi-Vendor Intelligence & Evidence Modeling (REQ-DISC)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-DISC-001** | Evidence Attribution & Confidence | Level 1 | `PLANNED` | Every discovered device record must attach timestamp, source protocol (MNDP, ONVIF, ARP, mDNS), and explicit distinction between confirmed facts and inferences. |
| **REQ-DISC-002** | Authorized Scope Enclosure | Level 1 | `PLANNED` | Active scanning or packet transmission must only occur within explicitly user-authorized CIDR network blocks or interfaces. |
| **REQ-DISC-003** | Multi-Vendor Hardware Profiling | Level 1 | `VERIFIED` | System must categorize and display device profiles for MikroTik RouterOS, Ubiquiti airMAX, TP-Link Pharos CPE, Linux servers, and ONVIF cameras. |
| **REQ-DISC-004** | Live Passive Discovery Listeners | Level 1 | `PLANNED` | Must provide non-intrusive broadcast UDP listeners for MikroTik MNDP (UDP 5678) and ONVIF WS-Discovery (UDP 3702) without faking live results. |
| **REQ-DISC-005** | Wi-Fi Access Point Telemetry | Level 1 | `VERIFIED` | Must analyze 802.11 access points, standard generation (Wi-Fi 4/5/6/7), encryption protocol (WPA2/WPA3, WEP, Open), and co-channel interference. |
| **REQ-DISC-006** | RF Spectrum Congestion Scoring | Level 1 | `VERIFIED` | Must calculate RF spectrum utilization for 2.4 GHz and 5 GHz bands and recommend cleanest non-overlapping channels (1, 6, 11). |

---

## 5. Defensive Cybersecurity & Cryptography (REQ-SEC)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-SEC-001** | Local Posture & Service Audit | Level 1 | `VERIFIED` | Must scan localhost listening ports non-destructively, flagging cleartext legacy protocols (FTP, Telnet, unencrypted HTTP) and user privilege level. |
| **REQ-SEC-002** | TLS/SSL Cryptographic Handshake | Level 2 | `VERIFIED` | Must perform non-destructive client TLS handshake, validate X.509 certificate expiry and issuer, audit cipher strength, and flag deprecated TLS 1.0/1.1 or 3DES/RC4. |
| **REQ-SEC-003** | Host Dual-Boot Protection | Level 1 | `VERIFIED` | The software must never format disks, modify partition tables, touch Windows 11 partitions, or edit EFI bootloader entries on host storage. |
| **REQ-SEC-004** | Input Sanitization & Validation | Level 1 | `VERIFIED` | All user and network inputs (IPs, CIDRs, hostnames, ports, interfaces) must pass strict regex validation to prevent shell injection or buffer faults. |
| **REQ-SEC-005** | Privilege Separation Boundary | Level 3 | `PLANNED` | Privileged operations (e.g. raw packet capture) must be isolated behind a documented Polkit or dedicated unprivileged-to-privileged IPC helper interface. |

---

## 6. Persistence, History & Reporting (REQ-STOR)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-STOR-001** | Local SQLite Engine | Level 1 | `VERIFIED` | Diagnostic runs, subnet calculations, DNS queries, and latency benchmarks must persist locally under `~/.config/itsa-network-os/history.db`. |
| **REQ-STOR-002** | Structured JSON & Text Export | Level 1 | `VERIFIED` | All CLI commands must support `--json` output for automated pipeline consumption, as well as human-readable aligned tables. |
| **REQ-STOR-003** | Diagnostic Run Audit Trail | Level 1 | `PLANNED` | Expand database schema to record full session snapshots, discovered hardware inventories, and security findings with automated secret redaction. |

---

## 7. User Interface (REQ-UI)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-UI-001** | Professional Glassmorphic Theme | Level 1 | `VERIFIED` | Modern dark glassmorphic desktop interface powered by PySide6 with 14 integrated functional modules. |
| **REQ-UI-002** | Custom 2D Canvas Visualizers | Level 1 | `VERIFIED` | Custom QGraphicsScene / QPainter visualizers for Live Bandwidth, OSPF Dijkstra SPF tree, Wi-Fi RF bell curves, and 2D node-link topology. |
| **REQ-UI-003** | Graceful Headless Fallback | Level 1 | `VERIFIED` | If PySide6 or an X11/Wayland display server is absent, the application must provide informative CLI error handling without crashing. |

---

## 8. Distribution & Packaging (REQ-DIST)

| ID | Title | Level | Status | Specification |
|---|---|---|---|---|
| **REQ-DIST-001** | Debian 13 Live ISO Recipe | Level 1 | `VERIFIED` | Provide automated `live-build` configurations for Debian 13 (Trixie) amd64 with customized package lists, chroot hooks, and desktop launchers. |
| **REQ-DIST-002** | Isolated Containerized Builder | Level 1 | `VERIFIED` | Containerized ISO compilation environment using Docker to guarantee host invariance and build reproducibility. |
| **REQ-DIST-003** | Software Bill of Materials (SBOM) | Level 1 | `IN_PROGRESS` | Maintain an explicit audit of all redistributed packages, libraries, kernels, and third-party components with license obligations. |
