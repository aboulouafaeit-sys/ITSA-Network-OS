# ITSA Network OS — System Architecture

## 1. Overview
ITSA Network OS is designed as a high-integrity, modular network engineering and cybersecurity diagnostic platform.
It is architected following clean separation of concerns, defensive programming principles, and zero-trust input handling.

```
+---------------------------------------------------------------------------------------+
|                                    Entry Points                                       |
|             CLI (main.py / cli.py)  |  PySide6 Desktop GUI (app_window.py)             |
+---------------------------------------------------------------------------------------+
                                           |
+---------------------------------------------------------------------------------------+
|                               Application Layer (app.py)                              |
|                  Command Dispatching | Lifecycle | Result Formatting                  |
+---------------------------------------------------------------------------------------+
            |                              |                             |
+-----------------------+      +-----------------------+      +-------------------------+
|      Core Layer       |      |     Network Layer     |      |     Security Layer      |
| - config.py (Safe)    |      | - subnet.py (CIDR)    |      | - validator.py (Input)  |
| - logger.py (Sanitized|      | - inspector.py (Mock) |      | - auditor.py (Posture)  |
| - health.py (Status)  |      | - dns.py (Diagnostic) |      | - lab.py (Packet Lab)   |
|                       |      | - latency.py (Probe)  |      |                         |
|                       |      | - routes.py (VLAN)    |      |                         |
|                       |      | - models.py (Typed)   |      |                         |
+-----------------------+      +-----------------------+      +-------------------------+
            |                              |                             |
+---------------------------------------------------------------------------------------+
|                           Storage & Persistence (storage/)                            |
|                         Local SQLite Engine (Zero Telemetry)                          |
+---------------------------------------------------------------------------------------+
```

## 2. Layer Responsibilities

### 2.1 Core (`src/itsa_network_os/core/`)
- **`config.py`**: Manages configuration with immutable safe defaults. Stores data locally under `~/.config/itsa-network-os/`. Disables telemetry by default.
- **`logger.py`**: Provides structured logging (JSON and formatted console). Automatically sanitizes tokens, passwords, and sensitive system identifiers.
- **`health.py`**: Evaluates platform readiness, Python runtime health, memory, storage limits, and virtual environment isolation without root privileges.

### 2.2 Network (`src/itsa_network_os/network/`)
- **`models.py`**: Strongly-typed domain models (`NetworkInterface`, `IPAddressInfo`, `SubnetCalculationResult`) using Python `dataclass` and `Enum`.
- **`subnet.py`**: High-performance IPv4/IPv6 subnet calculation engine implementing RFC standards (CIDR, broadcast, netmask, host counts, usable host spans).
- **`inspector.py`**: Provider-based network interface inspection. Uses `MockNetworkProvider` by default for safe offline and test environments; implements read-only host inspection with explicit fallback.
- **`dns.py`**: Non-destructive DNS resolution diagnostics, server response latency measurement, and system resolver detection.
- **`latency.py`**: Safe round-trip network connectivity and latency benchmarking using unprivileged TCP handshake timing, computing min/avg/max latency, packet loss, and jitter.
- **`routes.py`**: Read-only system routing table parser and IEEE 802.1Q VLAN subinterface detector.
- **`topology.py`**: 2D node-link network graph data model with automated hierarchical coordinate layout engine.
- **`wifi.py`**: 802.11 wireless airwave inspection, access point classification (Wi-Fi 4/5/6/7, WPA2/WPA3, WEP), and RF spectrum channel congestion and cleanest channel evaluation engine for 2.4 GHz and 5 GHz bands.

### 2.3 Security (`src/itsa_network_os/security/`)
- **`validator.py`**: Strict input validation for IP addresses, CIDR blocks, hostnames, and file paths to prevent injection or invalid state execution.
- **`auditor.py`**: Non-destructive system security posture auditor checking privilege levels, open local listening service ports, and configuration permissions.
- **`lab.py`**: Educational protocol dissection and synthetic packet capture laboratory explaining Ethernet, IP, TCP, UDP, and ICMP header fields.

### 2.4 Storage (`src/itsa_network_os/storage/`)
- **`database.py`**: Lightweight SQLite interface for persisting diagnostic histories, subnets, DNS resolutions, and latency benchmarks locally.

### 2.5 UI (`src/itsa_network_os/ui/`)
- **`cli.py`**: Standard terminal UI with clean tables, structured headers, and exit codes suitable for scripting and pipelines.
- **`desktop/`**: Modern PySide6 desktop dashboard featuring 10 interactive tabs with dark glassmorphic styling:
  1. System Overview & Health
  2. CIDR Subnet Calculator
  3. Network Interfaces
  4. DNS Resolution Diagnostics
  5. Latency Benchmark
  6. Cybersecurity Posture Audit
  7. Packet & Protocol Dissection Lab
  8. Routing Table & VLANs
  9. 2D Network Topology Visualizer
  10. Wi-Fi Spectrum & Wireless Signal Analysis

## 3. Security & Safety Guarantees
- **Least Privilege**: Application runs strictly as an unprivileged user (`non-root`).
- **Read-Only Network Operations**: Does not alter routing tables, network interfaces, firewall rules, or DNS settings.
- **Offline First**: All core calculation, DNS, latency, audit, and packet dissection functions execute with zero external network connectivity by default.
