# ITSA Network OS

[![CI](https://github.com/aboulouafaeit-sys/ITSA-Network-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/aboulouafaeit-sys/ITSA-Network-OS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Terms of Use](https://img.shields.io/badge/Terms%20of%20Use-Documented-success.svg)](TERMS_OF_USE.md)
[![Python Versions](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-informational.svg)](https://www.python.org/)
[![GUI Framework](https://img.shields.io/badge/GUI-PySide6%20%2F%20Qt6-green.svg)](https://wiki.qt.io/Qt_for_Python)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Linux%20%7C%20POSIX-lightgrey.svg)](debian-live/)
[![Security Policy](https://img.shields.io/badge/Security-Enforced-blueviolet.svg)](SECURITY.md)

> **A safe, modular network engineering and cybersecurity diagnostic platform with a modern PySide6 desktop interface and scriptable CLI.**

ITSA Network OS is designed for network administrators, security engineers, systems architects, and learners to inspect, diagnose, and audit network systems safely with strict least-privilege guarantees and non-destructive host invariance.

---

## Table of Contents
- [Key Features](#key-features)
- [Repository & Architecture Structure](#repository--architecture-structure)
- [Project Documentation](#project-documentation-single-source-of-truth)
- [Quick Start](#quick-start)
  - [Prerequisites](#1-requirements)
  - [Installation](#2-setup-virtual-environment)
  - [Desktop GUI Launch](#launch-desktop-graphical-interface)
  - [CLI Diagnostics Reference](#cli-diagnostics--analysis-commands)
  - [Automated Verification](#4-run-automated-tests)
- [Terms of Use & Ethical Policy](#terms-of-use--ethical-policy)
- [Contributing](#contributing)
- [License & SBOM Attribution](#license--sbom-attribution)

---

## Key Features

- **Professional Desktop GUI**: Modern, dark glassmorphic desktop interface powered by PySide6 with 14 integrated tabs and async background workers.
- **Multi-Vendor Hardware & IP Camera Manager**: Non-destructive discovery and telemetry of IP surveillance cameras (Hikvision, Dahua, ONVIF/RTSP), outdoor wireless CPEs (TP-Link Pharos, Ubiquiti airMAX), MikroTik RouterBOARD/RouterOS (MNDP), and Linux/Ubuntu servers.
- **OSPF / Dijkstra Shortest Path First (SPF) Simulator**: Step-by-step Link-State Database (LSDB) shortest-path-first visualizer, mathematical relaxation trace, dynamic link failure simulation, and routing convergence.
- **TLS / SSL Cryptographic Inspector**: Non-destructive TLS client handshake, X.509 certificate chain validation, cipher suite auditing (flagging weak 3DES/RC4/CBC and TLS 1.0/1.1), days-to-expiry tracking, and security posture scoring.
- **Live Bandwidth & Traffic Flow Monitor**: Real-time dual-stream area chart (RX/TX in KB/s and MB/s), packet counters, and adapter drop/error tracking.
- **Wi-Fi Spectrum & Wireless Signal Analysis**: Non-destructive 802.11 airwave scanner, RF parabolic curve spectrum visualizer (2.4/5 GHz), co-channel interference calculator, and WEP/Open security audit.
- **Interactive Network Topology Visualizer**: 2D node-link graph canvas with pan, zoom, tier layout, and device inspector.
- **Cybersecurity Posture Auditor**: Non-destructive process privilege evaluation, open listening port discovery, and configuration security scoring.
- **Educational Cybersecurity Lab**: Built-in packet protocol dissector with educational breakdown of Ethernet, IPv4, TCP, UDP, and ICMP headers.
- **Routing & VLAN Inspector**: Safe read-only routing table parser and IEEE 802.1Q VLAN subinterface discovery.
- **CIDR Subnet Calculator**: Accurate IPv4 and IPv6 subnet breakdown (network address, netmask, wildcard mask, broadcast, total/usable host capacity, usable range).
- **DNS Diagnostics**: Non-destructive DNS record resolution and query latency measurement.
- **Latency & Connectivity Benchmarking**: Non-root TCP handshake round-trip latency, packet loss, and jitter analysis.
- **Safe Network Abstraction**: Interface querying with a built-in `MockNetworkProvider` ensuring offline predictability and safe operations.
- **Defensive Engineering**: Input validation, log sanitation (no secret leaks), and zero telemetry.

---

## Repository & Architecture Structure

```text
ITSA-Network-OS/
├── .github/                       # GitHub workflows, issue templates, PR templates
│   ├── workflows/ci.yml           # Automated CI testing matrix (Python 3.10-3.13)
│   ├── ISSUE_TEMPLATE/            # Structured bug report & feature request templates
│   └── PULL_REQUEST_TEMPLATE.md   # Pull request review and safety verification checklist
├── debian-live/                   # Bootable Debian Live ISO configurations (Trixie/Bookworm)
├── docker/                        # Containerized build and execution environments
├── docs/                          # Detailed engineering reports, specifications, and ADRs
├── packaging/                     # Polkit privilege delegation actions and system packaging
├── scripts/                       # ISO build scripts, test runners, and screenshot utilities
├── src/itsa_network_os/           # Primary application codebase
│   ├── core/                      # System configuration, logging, and validator invariants
│   ├── models/                    # Immutable domain models and schemas
│   ├── network/                   # Network providers, routing, Wi-Fi, TLS, and SPF engines
│   ├── security/                  # Privilege boundary IPC, Polkit helper, and security auditor
│   ├── storage/                   # SQLite persistence, schema migrations, and audit trails
│   └── ui/desktop/                # PySide6 desktop application, tabs, canvas, and worker threads
├── tests/                         # Full automated test suite (590+ unit and integration tests)
│   ├── integration/               # CLI and end-to-end integration tests
│   └── unit/                      # Modular unit test suites for all subsystems
├── ARCHITECTURE.md                # System architecture, module boundaries, and data flow
├── CHANGELOG.md                   # Verifiable version history and release notes
├── CODE_OF_CONDUCT.md             # Community standards and respectful participation guidelines
├── CONTRIBUTING.md                # Developer contribution guide, coding conventions, quality gates
├── DECISIONS.md                   # Architecture Decision Records (ADR-001 through ADR-010)
├── LICENSE                        # Official MIT License
├── LICENSES.md                    # Detailed Software Bill of Materials (SBOM) and compliance
├── REQUIREMENTS.md                # Traceable functional requirements matrix
├── ROADMAP.md                     # Milestone roadmap and delivery tracking
├── SECURITY.md                    # Threat model, privilege boundaries, and safety invariants
├── TERMS_OF_USE.md                # Acceptable use policy and operational boundaries
├── TESTING.md                     # Test strategy, offscreen execution, and coverage
├── THIRD_PARTY_NOTICES.md         # Comprehensive third-party package notices and licenses
└── VISION.md                      # Product vision, mission statement, and target personas
```

---

## Project Documentation (Single Source of Truth)

| Document | Purpose |
|---|---|
| [TERMS_OF_USE.md](TERMS_OF_USE.md) | **Acceptable Use Policy, legal terms, authorized operational scope, and disclaimers** |
| [LICENSE](LICENSE) | **Official MIT License text** |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community code of conduct and reporting guidelines |
| [VISION.md](VISION.md) | Product mission, target personas, differentiation, commercial editions |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Traceable functional & non-functional requirements (`REQ-CORE`, `REQ-NET`, etc.) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, logical modules A through K, and data flow |
| [ROADMAP.md](ROADMAP.md) | Phased development plan with task identifiers (`TASK-001` to `TASK-018`) |
| [SECURITY.md](SECURITY.md) | Threat model, privilege boundaries, and safe automation impact levels |
| [TESTING.md](TESTING.md) | Test strategy, test suites, quality gates, and offscreen GUI testing |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Coding conventions, type annotations, and pull request rules |
| [CHANGELOG.md](CHANGELOG.md) | Release history, verified capabilities, and version notes |
| [DECISIONS.md](DECISIONS.md) | Architecture Decision Records (ADR-001 through ADR-010) |
| [LICENSES.md](LICENSES.md) | Software Bill of Materials (SBOM) and commercial licensing compliance |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Detailed attribution and third-party upstream notices |

---

## Quick Start

### 1. Requirements
- Python 3.10+ (Debian 12/13, Ubuntu 22.04/24.04, or compatible POSIX/Windows)
- `pip` and `virtualenv`

### 2. Setup Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1
pip install -e .
pip install PySide6  # Required for desktop graphical interface
```

### 3. Launch Application

#### Launch Desktop Graphical Interface:
```bash
itsa-network-os --gui
```

#### CLI Diagnostics & Analysis Commands:
```bash
# Discover multi-vendor network hardware and IP surveillance cameras
itsa-network-os --vendor-scan
itsa-network-os --cams
itsa-network-os --vendor mikrotik
itsa-network-os --vendor ubiquiti
itsa-network-os --vendor tplink
itsa-network-os --vendor-scan --json

# Simulate OSPF Dijkstra Shortest Path First routing calculation
itsa-network-os --spf --source R1
itsa-network-os --spf --source R1 --fail-link R1-R2
itsa-network-os --spf --json

# Inspect TLS/SSL certificates and cryptographic posture
itsa-network-os --tls cloudflare.com
itsa-network-os --tls example.com --port 443 --json

# Sample live network interface throughput rates and packet counters
itsa-network-os --bandwidth

# Scan nearby Wi-Fi access points and security ratings
itsa-network-os --wifi-scan

# Analyze 2.4 GHz RF spectrum channel congestion
itsa-network-os --wifi-spectrum

# Analyze 5 GHz RF spectrum channel congestion
itsa-network-os --wifi-spectrum --band 5ghz

# Synthesize and inspect network topology
itsa-network-os --topology

# Security posture audit
itsa-network-os --audit

# Educational packet analysis lab
itsa-network-os --lab

# System routing table
itsa-network-os --routes

# System health diagnostics
itsa-network-os --health

# Calculate an IPv4 / IPv6 subnet
itsa-network-os --calc-subnet 10.0.0.0/22

# List network interfaces
itsa-network-os --list-interfaces

# DNS diagnostics on target host
itsa-network-os --dns example.com

# Non-root latency benchmark
itsa-network-os --latency 1.1.1.1 --port 443 --count 4
```

### 4. Run Automated Tests
```bash
# Execute standalone test runner (590+ unit and integration tests)
python scripts/run_tests.py

# Or via pytest
pytest
```

---

## Terms of Use & Ethical Policy

ITSA Network OS is built strictly for **authorized network administration, defensive cybersecurity verification, educational research, and infrastructure diagnostics**.

- **Permission Required:** Users must have explicit authorization before scanning, auditing, or probing any network host or device.
- **Host System Invariance:** The platform is engineered to never alter host partition tables, EFI bootloader records, or dual-boot system files.
- **Non-Destructive Operations:** All baseline discovery and telemetry tools operate passively or via bounded non-disruptive handshakes.

For complete legal terms, user responsibilities, and warranty disclaimers, please consult the official [TERMS_OF_USE.md](TERMS_OF_USE.md).

---

## Contributing

We welcome community feedback, bug reports, and pull requests! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide and adhere to our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## License & SBOM Attribution

- **Core Application:** Licensed under the [MIT License](LICENSE).
- **Third-Party Attribution:** Full license statements and SBOM details are provided in [LICENSES.md](LICENSES.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
