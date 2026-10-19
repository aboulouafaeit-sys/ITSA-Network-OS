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

---

## 3. Threat Model & Mitigations

| Threat Vector | Potential Impact | Built-in Mitigation |
|---|---|---|
| **Host Dual-Boot Corruption** | Inadvertent damage to Windows 11 partition or EFI bootloader. | Code-level exclusion of raw block device writes; build scripts enforce chroot boundaries. |
| **Command Injection via Network Input** | Malicious interface names, hostnames, or CIDR strings executing shell commands. | Strict input validation via `InputValidator` regex; no `shell=True` in subprocess calls. |
| **Credential Leakage in Logs** | Cleartext passwords from RTSP URLs or configs written to disk. | Automated regex masking in `SanitizingFilter` across all logging handlers. |
| **Rogue Network Overload** | Diagnostic probes causing packet storms or triggering IDS/IPS alerts. | Hard rate limits on latency probes, configurable sample counts, zero blind port flooding. |
| **Privilege Escalation Vulnerability** | Exploitation of unprivileged-to-root execution pathways. | Architecture adheres strictly to non-root execution; GUI and CLI operate as regular user. |

---

## 4. Reporting Security Vulnerabilities

If you identify a security issue, vulnerability, or unintentional privilege requirement within ITSA Network OS, please document the issue locally and contact the project maintainers without public disclosure until remediation is verified.
