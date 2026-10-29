# ITSA Network OS — System Architecture & Module Boundaries

> **Document ID:** DOC-ARCH-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Architectural Philosophy

ITSA Network OS is engineered as an evidence-based, modular network operations platform. The system enforces strict separation of concerns, defensive programming, zero-trust input validation, and clear boundaries between verified technical facts and algorithmic inferences.

```
+---------------------------------------------------------------------------------------------------+
|                                      PRESENTATION TIER                                            |
|   CLI Interface (ui/cli.py)       |    Desktop PySide6 Shell (ui/desktop/)    |   Export / Reports|
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                                      APPLICATION CORE (app.py)                                    |
|   Task Orchestration  |  Lifecycle Management  |  Central Config  |  Sanitized Audit Logging      |
+---------------------------------------------------------------------------------------------------+
       |                                          |                                      |
+---------------+                        +------------------+                    +------------------+
| LOCAL HOST    |                        | NETWORK          |                    | DIAGNOSTICS &    |
| DISCOVERY     |                        | INTELLIGENCE     |                    | CYBERSECURITY    |
| - Interfaces  |                        | - Scope Guard    |                    | - DNS Engine     |
| - Netlink IPv4|                        | - Active/Passive |                    | - TCP Latency    |
| - IPv6 routes |                        | - Evidence Engine|                    | - Bandwidth Flow |
| - Gateways/DNS|                        | - Fact vs. Infer |                    | - TLS Inspector  |
| (inspector.py)|                        | (discovery/)     |                    | - Security Audit |
+---------------+                        +------------------+                    +------------------+
       |                                          |                                      |
+---------------------------------------------------------------------------------------------------+
|                              DATA MODEL & PERSISTENCE TIER (storage/)                             |
|  Unified Schema Models (Devices, Sessions, Evidence) | Local SQLite Database | Redaction Filter   |
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                           PRIVILEGE & OS BOUNDARY (security/privilege/)                           |
|  Unprivileged User Execution  <--- IPC / Polkit Boundary --->  Privileged Helpers (Read-Only Caps)|
+---------------------------------------------------------------------------------------------------+
                                                  |
+---------------------------------------------------------------------------------------------------+
|                           DISTRIBUTION & PACKAGING (debian-live/)                                 |
|  Debian 13 (Trixie) Live Recipe  |  Containerized Builder (docker/)  |  Release SBOM & Checksums   |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Logical Module Breakdown (Modules A through K)

### Module A: Operating System Foundation & ISO Generation
- **Scope:** Debian 13 (Trixie) live system configuration, custom package manifests (`itsa.list.chroot`), chroot build hooks (`01-install-itsa.hook.chroot`), and desktop entry integration.
- **Components:** `debian-live/`, `scripts/build_live_iso.sh`, `docker/Dockerfile`.
- **Invariants:** Live builds must be reproducible, isolated in containers or VMs, and must never touch host partition tables or bootloaders.

### Module B: Application Core (`itsa_network_os.core`)
- **Scope:** Application lifecycle, central configuration loading, structured event logging, health evaluation, and error handling.
- **Components:** `config.py`, `logger.py`, `health.py`.
- **Invariants:** Immutability of default configuration; automated scrubbing of tokens, passwords, and private keys in logs.

### Module C: Hardware & Interface Discovery (`itsa_network_os.network.inspector`)
- **Scope:** Host physical, virtual, and loopback interface discovery; operational status (`UP`/`DOWN`), MAC address, MTU, IPv4 addresses, IPv6 addresses, CIDR masks, and gateway bindings.
- **Components:** `inspector.py`, `models.py`.
- **Providers:**
  - `HostNetworkProvider`: Live Linux inspection reading from `/sys/class/net`, netlink, and `/proc/net`.
  - `MockNetworkProvider`: High-fidelity deterministic fixtures for isolated testing and development.

### Module D: Network Discovery & Intelligence Engine
- **Scope:** Authorized network scope definition, reachability checks, host/service discovery, and evidence-based device identification.
- **Components:** `network/vendor_manager.py`, `network/wifi.py`, `network/topology.py`.
- **Core Principle:** Explicit distinction between confirmed facts (e.g. verified TLS certificate subject, ONVIF XML response) and inferred information (e.g. estimated vendor model based on MAC OUI).

### Module E: Device Integration Layer
- **Scope:** Vendor-specific profiles, capability detection, and protocol adapters for MikroTik RouterOS, Ubiquiti airMAX, TP-Link Pharos, Linux servers, and IP surveillance cameras.
- **Components:** `network/vendor_manager.py`.
- **Invariants:** Read-only queries by default. No blind firmware flashing, configuration rewriting, or device resets.

### Module F: Diagnostics Engine
- **Scope:** Non-root latency and connectivity benchmarking, DNS resolution and response time diagnostics, live bandwidth throughput sampling, and system routing table analysis.
- **Components:** `latency.py`, `dns.py`, `bandwidth.py`, `routes.py`, `subnet.py`.

### Module G: Remediation & Workflow Engine
- **Scope:** Impact-rated workflow automation (Levels 1 through 4), pre-condition validation, dry-run simulations, and explicit user confirmation dialogs.
- **Safeguards:** Operations that modify state require user consent and validation.

### Module H: Reporting & History (`itsa_network_os.reports` & `storage`)
- **Scope:** Structured diagnostic persistence in local SQLite, JSON exports, aligned text tables, and secret-redacted audit trails.
- **Components:** `reports/exporter.py`, `storage/database.py`.

### Module I: User Interface (`itsa_network_os.ui`)
- **Scope:** Dual-mode user presentation:
  1. CLI interface (`cli.py`, `main.py`) with rich table formatting and JSON flags.
  2. PySide6 desktop interface (`desktop/app_window.py`) with 14 interactive views and custom 2D canvas visualizers.
  3. Unified Asset Inventory & Detail Inspector (`AssetDetailInspector`) featuring 5 facet tabs: *Identity & Attributes*, *Ports & Interfaces*, *IP Binding Timeline*, *Topology Links*, and *Evidence Provenance* (reconciled per advisory AUDIT-P3-003).
  4. Decoupled status indicators: global platform/safety status in `QStatusBar` vs. asset metrics in `AssetInventoryView` header banner (reconciled per advisory AUDIT-P3-004).
- **Invariants:** Graceful headless fallback when display server is unavailable.

### Module J: Security & Privilege Management (`itsa_network_os.security`)
- **Scope:** Least-privilege architecture, input validation, local security auditor, TLS/SSL cryptographic inspection, and protocol lab.
- **Components:** `validator.py`, `auditor.py`, `tls.py`, `lab.py`.

### Module K: Distribution & Release Engineering
- **Scope:** Debian package recipes, release checksum generation (SHA-256), software bill of materials, and license compliance audits.

---

## 3. Data Flow Architecture

```
User Input (CLI / Desktop GUI)
           |
           v
Strict Input Validation (validator.py)
           |
           v
Application Service Orchestrator (app.py)
           |
  +--------+--------+--------+--------+
  |                 |                 |
  v                 v                 v
Local Host      Network Engine    Security Engine
(inspector.py)  (dns, latency,    (tls, auditor,
(bandwidth.py)   routes, subnet)   packet lab)
  |                 |                 |
  +--------+--------+--------+--------+
           |
           v
Data Normalization & Evidence Tagging
           |
           v
Persistence & Export
 - Local SQLite Database (database.py)
 - JSON / Text Report Exporter (exporter.py)
```

---

## 4. Architectural Invariants

1. **Least Privilege by Default:** The application must never require `root` or `sudo` to launch or run standard diagnostics.
2. **Offline-First Resilience:** In the absence of an active network link, all calculation, modeling, and simulation tools remain fully operational.
3. **No Telemetry:** No metrics, telemetry, or crash reports are transmitted across the network. All data resides solely on the local machine.
