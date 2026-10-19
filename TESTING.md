# ITSA Network OS — Test Strategy & Verification Procedures

> **Document ID:** DOC-TEST-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Quality Objectives & Test Philosophy

Every meaningful change in ITSA Network OS must pass automated quality gates before release.
- **Correctness over Assumption:** No feature is complete merely because code exists or a GUI screen renders. A feature is complete only when behavior, error handling, limitations, and automated tests are verified.
- **Invariance Guarantee:** All tests must run safely without requiring root privileges, without modifying host network interfaces, and without touching host storage or bootloaders.
- **Explicit Invariant Distinction:** Tests must distinguish explicitly between simulated mock hardware fixtures, virtualized environments, and live physical hardware.

---

## 2. Test Execution Environments

### 2.1 Standard Test Runner (Zero External Dependencies)
Uses Python's standard `unittest` library for dependency-free validation in minimal environments:
```bash
python3 scripts/run_tests.py
```

### 2.2 Pytest Runner (With Coverage & Rich Reporting)
```bash
# Run full suite in virtual environment
.venv/bin/pytest -v

# Run with test coverage report
.venv/bin/pytest --cov=src/itsa_network_os --cov-report=term-missing
```

### 2.3 Headless Desktop GUI Testing
Desktop GUI widgets (`MainWindow`, custom canvases) are tested offscreen without requiring a physical monitor:
```bash
QT_QPA_PLATFORM=offscreen .venv/bin/pytest tests/unit/test_gui.py
```

---

## 3. Test Organization & Scope

```
tests/
├── integration/
│   ├── test_cli.py               # End-to-end CLI command parsing, flags, --json, exit codes
│   └── test_host_provider.py     # Live host provider inspection, read-only structural invariants
└── unit/
    ├── test_auditor.py           # Security posture checks, open ports, privilege level
    ├── test_bandwidth.py         # /proc/net/dev parser, rate formatting, delta calculations
    ├── test_config.py            # Configuration defaults, JSON parsing, immutability
    ├── test_dns.py               # socket.getaddrinfo DNS resolution, resolver detection
    ├── test_evidence.py          # EvidenceRecord, confidence boundaries, and ManagedDevice integration
    ├── test_gui.py               # PySide6 MainWindow, 14 tabs, offscreen event handling
    ├── test_health.py            # Host CPU, memory, storage health evaluation
    ├── test_inspector.py         # NetworkInterface models, Mock/Host providers
    ├── test_lab.py               # Educational packet lab trace generator & serialization
    ├── test_latency.py           # TCP handshake round-trip latency, jitter, loss
    ├── test_live_recipe.py       # Debian live-build config, hooks, desktop files
    ├── test_routes.py            # /proc/net/route parser, hex-to-IP conversion, VLANs
    ├── test_scope.py             # Authorized network scope enclosure, CIDR boundaries, runtime guard
    ├── test_spf.py               # OSPF Dijkstra SPF tree calculations, link failure
    ├── test_subnet.py            # IPv4/IPv6 RFC subnet math, /31 point-to-point, /32
    ├── test_tls.py               # TLS handshake, X.509 cert analysis, cipher grading
    ├── test_topology.py          # 2D network topology graph node layout coordinates
    ├── test_validator.py         # Regex input validation for IPs, CIDRs, hostnames, ports
    ├── test_vendor_manager.py    # Multi-vendor hardware & camera model telemetry
    └── test_wifi.py              # 802.11 AP security, 2.4/5GHz RF spectrum congestion
```

---

## 4. Quality Gates Checklist

Before any pull request or milestone commit is approved:
1. **Syntax & Linting:** `python3 -m py_compile` across all `src/` and `tests/` files.
2. **Automated Unit Tests:** 100% of unit tests pass with zero errors.
3. **Integration Tests:** CLI command execution, exit codes, and JSON outputs verified.
4. **GUI Offscreen Tests:** `test_gui.py` instantiates all 14 tabs without unhandled exceptions.
5. **No Secret Leaks:** Verify that test artifacts do not commit API keys, passwords, or host-identifying tokens.
6. **Live Build Verification:** Live-build configuration and chroot hooks pass `test_live_recipe.py`.
