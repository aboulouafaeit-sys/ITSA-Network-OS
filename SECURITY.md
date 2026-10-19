# ITSA Network OS — Security Policy & Privilege Architecture

> **Document ID:** DOC-SEC-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Safety Principles & Host Invariance

ITSA Network OS is developed under strict non-negotiable safety invariants to guarantee zero disruption to host environments, dual-boot partitions, and system configurations:

1. **Host Invariance:**
   - The application shall **never** alter host partition tables, EFI bootloader entries, Windows 11 partitions, or GRUB configurations.
   - Destructive disk operations (`dd`, `mkfs`, `fdisk`, `parted`) are strictly prohibited in the application runtime.
2. **Read-Only Network Operations:**
   - Core diagnostic modules operate strictly in read-only mode.
   - The application does not modify host routing tables, DNS resolvers (`/etc/resolv.conf`), or interface assignments without explicit user action and confirmation prompts.
3. **Privilege Boundary:**
   - The software runs under regular unprivileged user credentials. Running the primary UI or CLI under `sudo` or `root` is prohibited and flagged as a security warning by the built-in auditor.
4. **Credential & Secret Protection:**
   - The logging engine ([logger.py](file:///home/emorphi/Desktop/netF/itsa-network-os/src/itsa_network_os/core/logger.py)) automatically scrubs API keys, auth tokens, passwords, and private keys.
   - Zero telemetry, zero external beaconing, and zero unauthorized analytics calls.

---

## 2. Safe Automation Hierarchy

To protect external networks and internal infrastructure, automated operations are classified by impact level:

```
+-----------------------------------------------------------------------------------+
| LEVEL 1 — READ-ONLY (Default)                                                     |
| - Passive packet listening (MNDP, ONVIF)                                          |
| - Local kernel metric inspection (/proc/net/dev, /sys/class/net)                  |
| - Offline mathematical calculations (Subnet CIDR, Dijkstra SPF)                   |
| - Local port listening checks (127.0.0.1)                                         |
+-----------------------------------------------------------------------------------+
| LEVEL 2 — BOUNDED DIAGNOSTIC                                                      |
| - Explicit TCP connection timing (Latency benchmark)                              |
| - Read-only TLS client handshake (Certificate & cipher inspection)                |
| - DNS record resolution queries (socket.getaddrinfo)                              |
+-----------------------------------------------------------------------------------+
| LEVEL 3 — CONFIGURATION CHANGES (Gated)                                           |
| - Requires explicit user prompt & parameter validation                            |
| - Requires dry-run preview and documented expected outcome                        |
| - Reversible where technically feasible; limits documented                        |
+-----------------------------------------------------------------------------------+
| LEVEL 4 — HIGH-RISK OPERATIONS (Strictly Restricted)                              |
| - Firmware updates, device factory resets, network interface restarts             |
| - NEVER triggered automatically by discovery                                      |
| - Requires administrative authentication & explicit dual confirmation            |
+-----------------------------------------------------------------------------------+
```

### 2.1 Authorized Network Scope Enclosure (REQ-DISC-002 / ADR-010)

All Level 2 active network operations (TCP latency benchmarks, TLS handshakes, live DNS diagnostics, and future active discovery queries) are governed by an immutable `ScopeEnclosure` and enforced via `ScopeGuard`:

1. **Fail-Closed Default (Default-Deny):**
   - Active network operations require an explicitly authorized network scope (`--scope <CIDRS>`).
   - An unconfigured `ScopeGuard` or empty `ScopeEnclosure` strictly denies all active network operations and raises `ScopeViolationError`.
   - `clear()` resets the guard to an empty default-deny enclosure (`cidrs=()`, `allow_loopback=False`).
   - Passive local operations (interface inspection, subnet calculation, routing table view, packet lab, offline mock mode) operate unhindered without requiring scope configuration.
2. **Mandatory Interface Attribution:**
   - When a scope enclosure specifies interface constraints (`--scope-interface <IFACE>`), active operations without explicit interface attribution (`interface=None`) or targeting unapproved interfaces fail closed.
   - `--scope-interface` specified without `--scope` is rejected immediately on the CLI with exit code `1`.
3. **Unprivileged Interface Binding:**
   - Sockets bind to the authorized interface's local IP via `source_address` without requiring `CAP_NET_RAW` / root privileges. If no compatible local IP exists on the interface, the operation fails closed with `ScopeViolationError`.
4. **Engine-Level Gating & Bypass Prevention:**
   - Active diagnostic engines (`LatencyTester`, `TLSInspectorEngine`, `DNSDiagnostics`) mandate an authorized `ScopeGuard` in live mode and reject unconfigured calls prior to socket creation or DNS resolution.
5. **Resolution-to-Connection Integrity:**
   - Hostnames are resolved once and all resolved IPs verified against the authorized enclosure. Sockets connect strictly to the verified IP, preventing DNS rebinding attacks while preserving TLS SNI and certificate validation.
6. **Supernet & Unicast Target Restriction:**
   - Broad supernets (IPv4 `< 8`, IPv6 `< 7`, and `== 0`) are prohibited without explicit `allow_global_internet=True`.
   - Subnet network (.0) and broadcast (.255) addresses for prefixes $\le 30$ are ineligible for active unicast connections, while RFC 3021 `/31` and `/32` remain permitted.

---

## 3. Threat Model & Mitigations

| Threat Vector | Potential Impact | Built-in Mitigation |
|---|---|---|
| **Host Dual-Boot Corruption** | Inadvertent damage to Windows 11 partition or EFI bootloader. | Code-level exclusion of raw block device writes; build scripts enforce chroot boundaries. |
| **Command Injection via Network Input** | Malicious interface names, hostnames, or CIDR strings executing shell commands. | Strict input validation via `InputValidator` regex; no `shell=True` in subprocess calls. |
| **Credential Leakage in Logs** | Cleartext passwords from RTSP URLs or configs written to disk. | Automated regex masking in `SanitizingFilter` across all logging handlers. |
| **Rogue Network Overload** | Diagnostic probes causing packet storms or triggering IDS/IPS alerts. | Hard rate limits on latency probes, configurable sample counts, zero blind port flooding. |
| **Privilege Escalation Vulnerability** | Exploitation of unprivileged-to-root execution pathways. | Architecture adheres strictly to non-root execution; GUI and CLI operate as regular user. |
| **Out-of-Scope Active Probing / DNS Rebinding** | Probing unauthorized IP addresses, accidental WAN scanning, or DNS rebinding bypasses. | Fail-closed `ScopeGuard`, strict CIDR containment, supernet prohibitions, and single-resolution verified IP binding (ADR-010). |

---

## 4. Reporting Security Vulnerabilities

If you identify a security issue, vulnerability, or unintentional privilege requirement within ITSA Network OS, please document the issue locally and contact the project maintainers without public disclosure until remediation is verified.

