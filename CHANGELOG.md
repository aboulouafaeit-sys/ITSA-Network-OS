# Changelog — ITSA Network OS

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] — Phase 4 Enhancements

### Changed
- **Asynchronous GUI Responsiveness & Worker Lifecycle Hardening (TASK-P4-01, TASK-P4-02, TASK-P4-04)**:
  - Migrated diagnostic and discovery execution to asynchronous workers (`AsyncOperationWorker`, `AsyncWorkerRunner`) across DNS diagnostics, Latency benchmark, Security audit, Unified asset inventory, and Multi-vendor hardware manager.
  - Eliminated eager execution from view constructors, establishing truthful idle/ready states and duplicate-launch prevention with button toggling.
  - Added request ID tracking to prevent stale worker results from overwriting newer user state.
  - Hardened application shutdown and worker cancellation in `MainWindow.closeEvent` with `ActiveThreadRegistry.cancel_and_wait_all()`, guaranteeing QThread lifecycle integrity.
- **Truthful Runtime Health Indicator (TASK-P4-03)**:
  - Replaced static shell-header health label with asynchronous runtime health evaluation reflecting `Application.check_health()` status (`UNCHECKED`, `CHECKING`, `HEALTHY`, `WARNING`, `DEGRADED`, `UNAVAILABLE`).
- **Documentation Reconciliation (TASK-P4-05)**:
  - Reconciled `AssetDetailInspector` architecture specification to accurately reflect its 5 implemented facet tabs (*Identity & Attributes*, *Ports & Interfaces*, *IP Binding Timeline*, *Topology Links*, *Evidence Provenance*), resolving advisory AUDIT-P3-003.
  - Clarified separation of global safety status in `QStatusBar` and inventory count metrics in `AssetInventoryView` header banner, resolving advisory AUDIT-P3-004.

### Advisories Tracked
- **P4-ADV-001**: Validate late-running worker behavior after the 500 ms shutdown wait, including callbacks after window closure.
- **P4-ADV-002**: Perform a manual GUI smoke test on a real Debian 13 desktop session when practical.

---

## [0.1.0] — 2026-10-19 — Baseline Re-Engineering Release

### Added
- **Single Source of Truth Governance:**
  - Added `VISION.md`, `REQUIREMENTS.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `SECURITY.md`, `TESTING.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `DECISIONS.md`, and `LICENSES.md`.
  - Assigned stable requirement identifiers (`REQ-CORE-*`, `REQ-NET-*`, `REQ-DISC-*`, `REQ-SEC-*`, `REQ-STOR-*`, `REQ-UI-*`, `REQ-DIST-*`) and milestone task IDs (`TASK-001` through `TASK-018`).
- **Development Environment Stabilization:**
  - Configured native Debian 13 virtual environment with Python 3.13.5 and PySide6 6.12.0.
  - Achieved 100% test pass rate (107 of 107 tests passing, 0 skipped, 0 failures).
- **Core Network Diagnostic Toolchain:**
  - RFC-compliant IPv4 and IPv6 CIDR subnet calculator with /31 point-to-point support (`subnet.py`).
  - Read-only network interface inspector with safe mock provider (`inspector.py`).
  - DNS resolution diagnostics and `/etc/resolv.conf` system resolver parser (`dns.py`).
  - Non-root TCP handshake round-trip latency and jitter benchmark (`latency.py`).
  - Live kernel throughput monitor parsing Linux `/proc/net/dev` (`bandwidth.py`).
  - Kernel routing table parser reading `/proc/net/route` with VLAN detection (`routes.py`).
  - Step-by-step OSPF Dijkstra Shortest Path First simulator with dynamic link failure (`spf.py`).
- **Defensive Cybersecurity & Protocol Lab:**
  - Local listening port auditor and least-privilege checker (`auditor.py`).
  - Non-destructive client TLS handshake and X.509 certificate inspector (`tls.py`).
  - Educational packet dissection lab for Ethernet, IP, TCP, UDP, ICMP (`lab.py`).
  - Strict input validation engine for IPs, CIDRs, hostnames, and ports (`validator.py`).
  - Secret-sanitizing structured logging engine (`logger.py`).
  - Local SQLite persistence engine (`database.py`).
- **Desktop Graphical Interface (PySide6):**
  - Dark glassmorphic desktop interface with 14 functional tabs (`app_window.py`).
  - Custom interactive 2D canvas visualizers for Bandwidth, Dijkstra SPF, RF Wi-Fi spectrum, and network topology.
- **Debian 13 (Trixie) Live ISO Toolchain:**
  - Live-build configuration recipe (`debian-live/auto/config`).
  - Curated system package list (`itsa.list.chroot`).
  - System chroot installation hook (`01-install-itsa.hook.chroot`).
  - Automated ISO build script (`scripts/build_live_iso.sh`) and isolated Docker container environment.

---

## [Pre-0.1.0] — Initial Prototyping
- Prototyped initial modular structure, command-line interface, and research & development tracks.
