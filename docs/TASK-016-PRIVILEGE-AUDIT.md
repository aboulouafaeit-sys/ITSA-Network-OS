# TASK-016 — Least-Privilege Authorization & System Privilege Inventory

**Document ID:** DOC-PRIV-TASK016-001  
**Project:** ITSA Network OS  
**Platform:** Debian 13 (Trixie) | Linux x86_64 | Python 3.13  
**Milestone:** MILE-05 — Privilege Boundaries & Distribution Packaging  
**Dependencies:** TASK-008 (Authorized Network Scope Enclosure, ADR-010)  
**Predecessors:** TASK-014, TASK-015, TASK-015-FIX-REVIEW  
**Status:** Approved Engineering Inventory  

---

## 1. Executive Summary & Core Principles

ITSA Network OS adheres to the principle of least privilege (**ADR-005**). The core application and PySide6 desktop GUI run strictly as an unprivileged standard user (`non-root`). Running the entire application or GUI under `sudo` or as `root` is prohibited as a severe security vulnerability.

This audit evaluates every functional subsystem across the codebase on Debian 13 (Trixie) to determine:
1. Which operations genuinely require Linux kernel privileges or capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`).
2. Which operations can execute completely unprivileged using standard kernel interfaces (`/sys`, `/proc`, unprivileged sockets).
3. The exact boundaries required to isolate necessary elevated operations behind a strictly validated Inter-Process Communication (IPC) interface governed by Polkit authorization.

---

## 2. Comprehensive System Privilege Inventory

The table below catalogs every operational category across ITSA Network OS, evaluating current entry points, kernel capability requirements, input/output data, security impact, and proposed execution identity.

| Operation Category | Current Entry Point | Elevated Privileges Required? | Required Linux Capabilities | Input / Output Telemetry | Potential Security Impact | Proposed Execution Identity | Architectural Placement |
|---|---|---|---|---|---|---|---|
| **1. GUI Startup & Event Loop** | `ui.desktop.launcher`, `app_window.py` | **NO** | None (Standard user) | Input: User window events<br>Output: QPainter 2D renders | X11/Wayland injection if run as root; arbitrary file overwrite if privileged | Unprivileged User (UID > 1000) | Unprivileged Desktop Client |
| **2. Host Interface Enumeration** | `HostNetworkProvider.discover_interfaces`, `inspector.py` | **NO** | None (sysfs/procfs world-readable; Netlink `RTM_GETADDR` unprivileged) | Input: None<br>Output: List of `NetworkInterface` objects | Information disclosure of local MAC/IP topology (benign) | Unprivileged User | Unprivileged Application Core |
| **3. Passive Wi-Fi Scan Dump** | `LinuxWirelessScanner.get_access_points`, `iw dev <iface> scan dump` | **NO** | None (Querying cached BSS scan dump is unprivileged on modern Linux) | Input: Wireless interface name<br>Output: List of `AccessPointInfo` | Radio spectrum visibility; passive BSS observation | Unprivileged User | Unprivileged Network Layer |
| **4. DNS Diagnostics** | `DNSDiagnostics.query`, `dns.py` | **NO** | None (Unprivileged UDP/TCP client socket on ephemeral ports) | Input: Target domain/IP<br>Output: `DNSResolutionResult` | Cache snooping; outbound recursive resolution queries | Unprivileged User (ScopeGuard enforced) | Unprivileged Network Layer |
| **5. Latency & Loss Benchmarks** | `LatencyTester.benchmark`, `latency.py` | **NO** | None (Safe TCP handshake connection timing using unprivileged `connect()`) | Input: Target host, port<br>Output: `LatencyBenchmarkResult` | Targeted port probing; prevented by ScopeGuard fail-closed CIDR | Unprivileged User (ScopeGuard enforced) | Unprivileged Network Layer |
| **6. Passive Broadcast Listeners** | `MndpDiscoveryListener`, `OnvifDiscoveryListener`, `vendor_manager.py` | **NO** | None (Unprivileged UDP sockets bound to ports > 1024: 5678 and 3702) | Input: Incoming UDP broadcast datagrams<br>Output: Discovered vendor hardware records | Local broadcast inspection; no packet transmission | Unprivileged User (ScopeGuard attribution) | Unprivileged Network Layer |
| **7. TLS Cryptographic Inspection** | `TLSInspectorEngine.inspect`, `security.tls.py` | **NO** | None (Standard client TLS socket over unprivileged TCP) | Input: Target host:port<br>Output: `TLSInspectionReport` | Reading TLS certificate trust chains; no active modification | Unprivileged User (ScopeGuard enforced) | Unprivileged Security Layer |
| **8. Multi-Vendor Device Discovery** | `VendorDiscoveryEngine`, `vendor_canvas.py` | **NO** | None (Standard HTTP, RTSP, ONVIF unprivileged client requests) | Input: Target IP addresses<br>Output: Camera / CPE / Router profiles | Device fingerprinting; strictly constrained by ScopeGuard | Unprivileged User (ScopeGuard enforced) | Unprivileged Security Layer |
| **9. Low-Level Packet Capture & BPF** | `EducationalPacketLab`, packet analysis helper | **YES** | **`CAP_NET_RAW`** (`socket(AF_PACKET, SOCK_RAW, ...)`) | Input: Validated interface, packet count limit (≤ 50), timeout, BPF filter<br>Output: Dissected `ParsedPacket` structures | Potential eavesdropping on link-layer frames; sensitive credential exposure | **Privileged Helper** (`org.itsa.networkos.capture`) | **Isolated Privileged IPC Helper** |
| **10. Host Network Reconfiguration** | N/A (Prohibited by system invariants) | **YES** | `CAP_NET_ADMIN` | N/A | High: Altering IP routes, DNS resolvers, or firewall state violates Host Invariance | **DISALLOWED** | **Excluded by Architecture Policy** |
| **11. Report Export & SQLite Storage** | `ReportExporter`, `DatabaseManager`, `storage.database` | **NO** | None (User home directory `~/.config/itsa-network-os/data.sqlite3`, mode `0600`) | Input: Completed sessions<br>Output: Encrypted / redacted JSON/CSV/MD | Local data leakage if permissions loose; guarded by `0600` permissions | Unprivileged User | Unprivileged Storage Layer |

---

## 3. Kernel Privilege Analysis: Raw Packet Capture

### 3.1 Why Raw Packet Capture Genuinely Requires Elevation
On Linux kernels (including Debian 13 Trixie), opening raw link-layer packet sockets:
```c
int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```
strictly requires the **`CAP_NET_RAW`** capability in the initial user namespace (`EPERM` is returned to unprivileged users).

While packet reception can be accomplished unprivileged on standard UDP/TCP listening sockets, capturing raw Ethernet headers, arbitrary ICMP types, ARP announcements, and link-layer protocol handshakes for educational dissection in the **Packet & Protocol Lab** cannot be performed without raw socket access.

### 3.2 Mitigation of Uncontrolled Elevation
Rather than granting `CAP_NET_RAW` to the Python binary or launching the GUI via `sudo`, ITSA Network OS implements a **narrowly scoped, isolated privileged helper** (`itsa-priv-helper`).

Key guardrails:
1. **Finite Action Set:** The helper exposes only explicit operations:
   - `OP_PING` (Health and version check)
   - `OP_GET_CAPABILITIES` (Compile-time capability check)
   - `OP_START_CAPTURE` (Asynchronous capture session creation with capability token)
   - `OP_STOP_CAPTURE` (Targeted session cancellation with capability token verification)
   - `OP_GET_CAPTURE_RESULTS` (Targeted session status and results retrieval)
   - `OP_CAPTURE_PACKETS` (Bounded synchronous packet capture with session tracking)
2. **Fail-Closed Peer Credential Verification:** `SO_PEERCRED` verifies caller PID, UID, and GID directly from kernel space. Any failure fails closed with `PeerCredentialError`; no fallback to helper EUID or default root identity is permitted.
3. **Session Ownership & Capability Tokens:** Every active session is tracked in a thread-safe `SessionRegistry`. Cancellation requires both caller UID ownership matching and constant-time capability token verification (`hmac.compare_digest`). No global cancellation state exists.
4. **Deterministic Server-Side Packet Filtering:** Filter expressions are parsed and compiled into a strict `PacketFilter` on the trusted server side, enforcing protocol predicates (`tcp`, `udp`, `icmp`, `arp`) and port predicates without shell invocation or arbitrary code execution.
5. **Mandatory ScopeGuard Enforcement:** Privileged capture mandates a non-empty list of valid target CIDR networks. Capture requests with missing or empty scopes fail closed with `SCOPE_VIOLATION`. Captured packets must have proven in-scope addresses to be admitted.
6. **Strict Bounded Output:** Captures are bounded to a maximum of 50 packets, maximum 10.0 seconds execution duration, and maximum 1500 bytes per packet frame.

---

## 4. PolicyKit (Polkit) Authorization Integration

Privilege elevation is mediated by PolicyKit:
- **Action Identifier:** `org.itsa.networkos.capture`
- **Default Policy:**
  - `allow_any`: `no` (Remote/unauthenticated sessions cannot capture)
  - `allow_inactive`: `no` (Background sessions cannot capture)
  - `allow_active`: `auth_admin` (Requires local administrator authentication)
- **Invocation Mechanism:** The unprivileged application spawns or contacts the privileged helper via `pkexec` or an authenticated local Unix domain socket.
- **Fail-Closed Semantics:** If Polkit authorization is denied, cancelled by the user, or unavailable, the application logs an audit record, surfaces an actionable error in the UI, and never attempts unauthorized fallback.

---

## 5. ScopeGuard Alignment & Invariant Guarantees

In accordance with **TASK-008 (ADR-010)**:
1. Privileged helpers validate all target interfaces against `InputValidator.validate_interface_name()`.
2. Packet capture filters and IP targets are evaluated against the mandatory active `ScopeGuard` enclosure.
3. No privileged operation can be used to scan arbitrary external subnets, public supernets (prefixlen < 8), or non-attributed interfaces.
4. All authorization decisions and capture sessions generate immutable audit records.
