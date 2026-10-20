# TASK-016 — Threat Model & Security Posture Assessment

**Document ID:** DOC-THREAT-TASK016-001  
**Project:** ITSA Network OS  
**Platform:** Debian 13 (Trixie) | Linux x86_64 | Python 3.13  
**Milestone:** MILE-05 — Privilege Boundaries & Distribution Packaging  
**Dependencies:** TASK-008 (Authorized Network Scope Enclosure, ADR-010)  
**Predecessors:** TASK-014, TASK-015, TASK-015-FIX-REVIEW  
**Status:** Approved Security Assessment  

---

## 1. Executive Threat Model Overview

ITSA Network OS introduces a privileged boundary for low-level raw packet capture (`CAP_NET_RAW`) to power the **Educational Packet & Protocol Laboratory**. Because privileged helpers run with elevated kernel capabilities, they represent high-value targets for local privilege escalation (LPE).

This document applies the **STRIDE** methodology to systematically identify threats against the IPC boundary and establish defense-in-depth mitigations.

---

## 2. STRIDE Threat Matrix & Mitigations

| Threat Category | Potential Attack Vector | Severity | Architectural Mitigation & Defense-in-Depth | Residual Risk Level |
|---|---|---|---|---|
| **Spoofing** | Unauthorized local user connects to helper Unix socket, impersonates root, or cancels another user's session | **HIGH** | 1. Kernel-level peer credential inspection using `SO_PEERCRED` fails closed (`PeerCredentialError`); never falls back to helper EUID.<br>2. Socket directory `/run/itsa-network-os/` created with mode `0700` (`root:root`).<br>3. Session ownership bound to both peer UID and cryptographically unguessable capability token (`session_token`) verified via `hmac.compare_digest`.<br>4. Capability tokens are never logged or exposed in error messages. | **LOW** (Kernel & capability enforced) |
| **Tampering** | Command injection via crafted interface names, malformed scopes, or bypass via filter expressions | **CRITICAL** | 1. **Zero Shell Execution:** No `sh -c`, `system()`, or shell subshells.<br>2. Interface names validated via strict regex (`^[a-zA-Z0-9_\-\.]{1,16}$`).<br>3. Deterministic server-side `PacketFilter` compiles and enforces protocol (`tcp`, `udp`, `icmp`, `arp`) and port predicates; rejects shell metacharacters and incompatible combinations at schema validation.<br>4. Scope enclosure mandates non-empty, valid CIDR networks; empty scopes fail closed. | **NEGLIGIBLE** |
| **Repudiation** | Malicious or unauthorized packet captures executed without administrative audit trail | **MEDIUM** | 1. Helper records immutable structured audit entries for all operations.<br>2. Audit records include timestamp, client PID, client UID, target interface, packet count, and authorization status.<br>3. Audit logs written to system journal / local log. | **LOW** |
| **Information Disclosure** | Eavesdropping on unauthorized link-layer traffic or leaking sensitive payload credentials in logs | **HIGH** | 1. **TASK-008 Mandatory ScopeGuard Enforcement:** Packets outside authorized CIDR bounds or lacking proven addresses are discarded.<br>2. Packet capture buffer strictly capped at 50 packets.<br>3. Logging engine strictly redacts packet payloads; only layer metadata, addresses, and length are persisted.<br>4. Unprivileged desktop application cannot inspect packets outside user session. | **LOW** |
| **Denial of Service** | Resource exhaustion via giant messages, infinite packet loops, un-reaped zombie helpers, or unowned global cancellation | **HIGH** | 1. Maximum request payload enforced at `64 KB`; maximum response at `1 MB`.<br>2. Capture loop bounded by monotonic timer (maximum `10.0` seconds).<br>3. Threaded client connection handling ensures concurrent cancellation requests are never blocked by an active capture loop.<br>4. Per-session dedicated cancellation events isolate sessions; stopping one session cannot affect another.<br>5. Multi-stage process termination guarantees zero zombie processes. | **LOW** |
| **Elevation of Privilege** | Attacker exploits helper functionality to execute arbitrary binaries or modify system files | **CRITICAL** | 1. **Finite Action Allowlist:** Helper exposes only `OP_PING`, `OP_GET_CAPABILITIES`, `OP_START_CAPTURE`, `OP_STOP_CAPTURE`, `OP_GET_CAPTURE_RESULTS`, `OP_CAPTURE_PACKETS`.<br>2. Helper provides no generic command execution, file writing, or process spawning primitives.<br>3. Polkit action `org.itsa.networkos.capture` defaults to `auth_admin` (requires root password).<br>4. Helper does not preserve or load ambient environment variables (`LD_PRELOAD`, `PYTHONPATH` scrubbed by `pkexec`). | **NEGLIGIBLE** |

---

## 3. Scope Boundary & Host Invariance Assurances

1. **Host Invariance (ADR-005, SECURITY.md):**
   - The privileged helper has no code paths that modify network configuration, firewall tables (`iptables`/`nftables`), routing tables, or disk files.
   - Promiscuous mode flag is restored upon capture termination.
2. **ScopeGuard Compliance (ADR-010):**
   - Any capture request specifying an out-of-scope IP target or unapproved interface fails closed with `SCOPE_VIOLATION`.
   - The helper rejects supernets (IPv4 prefix < 8, IPv6 prefix < 7) and broadcast addresses.

---

## 4. PolicyKit Elevation Boundaries & Defaults

The PolicyKit action `org.itsa.networkos.capture` enforces:
```xml
<action id="org.itsa.networkos.capture">
  <description>Run low-level packet capture helper for ITSA Network OS</description>
  <message>Authentication is required to perform low-level packet capture diagnostics.</message>
  <defaults>
    <allow_any>no</allow_any>
    <allow_inactive>no</allow_inactive>
    <allow_active>auth_admin</allow_active>
  </defaults>
</action>
```

- **Fail-Closed Guarantee:** If the user dismisses the authentication dialog, enters an invalid password, or Polkit daemon is inactive, the request is rejected immediately with `DENIED`. The application handles this gracefully, surfacing an error in the GUI without falling back to mock or attempting unauthenticated execution.
