# ITSA Network OS — Project Roadmap

## Phase 1: Safe Foundation & Core Engine (Complete)
- [x] Establish modular Python project structure with PEP 621 packaging.
- [x] Safe, read-only system inspection and health diagnostics.
- [x] Robust IPv4/IPv6 subnet calculator with exhaustive unit tests.
- [x] Network interface abstraction with mock providers for offline-first safety.
- [x] Structured logging with sensitive data masking.
- [x] Non-root execution verification and documentation.

## Phase 2: Host Network Inspection & Diagnostics (Complete)
- [x] Safe read-only host network interface query abstraction.
- [x] DNS resolution diagnostics and response latency benchmarking (`DNSDiagnostics`).
- [x] Safe non-root latency and connectivity benchmarking (`LatencyTester`).
- [x] Local SQLite storage for diagnostic run history, DNS, and latency logs.
- [x] Structured report generation (JSON, CLI text tables).

## Phase 3: Desktop Graphical Interface (Complete)
- [x] PySide6 desktop interface with modern dark glassmorphic styling (`MainWindow`, `theme.py`).
- [x] Interactive CIDR subnet calculator visualizer and card dashboard.
- [x] Network interfaces live/mock browser table with status badges.
- [x] Integrated DNS diagnostics view with record tables.
- [x] Integrated Latency & Connectivity benchmark tool with probe graphs/metrics.
- [x] Graceful headless fallback and `--gui` launcher CLI flag.

## Phase 4: Cybersecurity Audit & Laboratory Modules (Complete)
- [x] Local system cybersecurity posture auditor (`SecurityAuditor`).
- [x] Local listening services port discovery and cleartext protocol warning.
- [x] Educational network packet analyzer with protocol dissection (`EducationalPacketLab`).
- [x] System routing table parser and IEEE 802.1Q VLAN detector (`RouteParser`).
- [x] Integrated Security Audit, Packet Lab, and Routing Table tabs into Desktop GUI.

## Phase 5: Distribution & Live OS Image (Complete)
- [x] Debian 13 (Trixie) live-build recipe and configuration (`debian-live/auto/config`).
- [x] Curated live-system package list with desktop & networking utilities (`itsa.list.chroot`).
- [x] Automated system chroot installer hook (`01-install-itsa.hook.chroot`).
- [x] Application desktop launchers for live user desktop and applications menu.
- [x] Automated live ISO compilation orchestration script (`scripts/build_live_iso.sh`).
- [x] Isolated containerized build environment (`docker/Dockerfile`, `compose.yaml`).
- [x] Comprehensive build and verification documentation (`docs/LIVE_BUILD.md`).
