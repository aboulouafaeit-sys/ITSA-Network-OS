# ITSA Network OS — Project Roadmap

## Core Foundation (Complete)
- [x] Establish modular Python project structure with PEP 621 packaging.
- [x] Safe, read-only system inspection and health diagnostics.
- [x] Robust IPv4/IPv6 subnet calculator with exhaustive unit tests.
- [x] Network interface abstraction with mock providers for offline-first safety.
- [x] Structured logging with sensitive data masking.
- [x] Non-root execution verification and documentation.

## Diagnostic Subsystems (Complete)
- [x] Safe read-only host network interface query abstraction.
- [x] DNS resolution diagnostics and response latency benchmarking (`DNSDiagnostics`).
- [x] Safe non-root latency and connectivity benchmarking (`LatencyTester`).
- [x] Local SQLite storage for diagnostic run history, DNS, and latency logs.
- [x] Structured report generation (JSON, CLI text tables).

## Desktop Graphical Interface (Complete)
- [x] PySide6 desktop interface with modern dark glassmorphic styling (`MainWindow`, `theme.py`).
- [x] Interactive CIDR subnet calculator visualizer and card dashboard.
- [x] Network interfaces live/mock browser table with status badges.
- [x] Integrated DNS diagnostics view with record tables.
- [x] Integrated Latency & Connectivity benchmark tool with probe graphs/metrics.
- [x] Graceful headless fallback and `--gui` launcher CLI flag.

## Cybersecurity Audit & Laboratory (Complete)
- [x] Local system cybersecurity posture auditor (`SecurityAuditor`).
- [x] Local listening services port discovery and cleartext protocol warning.
- [x] Educational network packet analyzer with protocol dissection (`EducationalPacketLab`).
- [x] System routing table parser and IEEE 802.1Q VLAN detector (`RouteParser`).

## Research & Development (R&D) Specialized Tracks (Active)
- [x] **Track 1: Interactive Network Topology Visualizer (`TopologyWidget`, `TopologyDiscoveryEngine`)**: 2D node-link graph canvas with pan, zoom, hierarchical layout, and device inspector.
- [x] **Track 2: Wi-Fi Inspection & Wireless Spectrum Analysis (`WifiSpectrumWidget`, `WirelessSpectrumAnalyzer`)**: Non-destructive 802.11 airwave scanner, RF bell-curve spectrum visualizer (2.4/5 GHz), co-channel interference calculator, and WEP/Open security audit.
- [ ] **Track 3: Live Bandwidth & Traffic Flow Monitor**: Real-time throughput graph and interface packet counter.
- [ ] **Track 4: TLS / SSL Cryptographic Inspector**: Certificate chain and cipher suite security auditor.
- [ ] **Track 5: Routing Protocol & Dijkstra SPF Simulator**: Step-by-step shortest path SPF link-state visualizer.

## Debian Live OS Distribution Recipe (Complete)
- [x] Debian 13 (Trixie) live-build recipe and configuration (`debian-live/auto/config`).
- [x] Curated live-system package list with desktop & networking utilities (`itsa.list.chroot`).
- [x] Automated system chroot installer hook (`01-install-itsa.hook.chroot`).
- [x] Application desktop launchers for live user desktop and applications menu.
- [x] Automated live ISO compilation orchestration script (`scripts/build_live_iso.sh`).
- [x] Isolated containerized build environment (`docker/Dockerfile`, `compose.yaml`).
- [x] Comprehensive build and verification documentation (`docs/LIVE_BUILD.md`).
