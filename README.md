# ITSA Network OS

> **A safe, modular network engineering and cybersecurity diagnostic platform.**

ITSA Network OS is designed for network administrators, security engineers, and learners to inspect, diagnose, and audit network systems safely with strict least-privilege guarantees.

---

## Key Features
- **Professional Desktop GUI**: Modern, dark glassmorphic desktop interface powered by PySide6 with 11 integrated tabs.
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

## Quick Start

### 1. Requirements
- Python 3.10+
- Linux (Debian 12/13 recommended) or compatible POSIX/Windows environment

### 2. Setup Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\Activate.ps1
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
python scripts/run_tests.py
# Or with pytest:
pytest
```

---

## License
MIT License. Built for secure, reproducible network engineering.
