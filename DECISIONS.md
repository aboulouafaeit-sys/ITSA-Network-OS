# Architecture Decision Records (ADRs) — ITSA Network OS

> **Document ID:** DOC-ADR-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## Index of Technical Decisions

- **ADR-001:** Debian 13 (Trixie) as Foundational Operating System
- **ADR-002:** Python 3.10+ as Primary Application Core Language
- **ADR-003:** PySide6 (Qt for Python) for Desktop Graphical Interface
- **ADR-004:** Offline-First Architecture & Mock Provider Invariants
- **ADR-005:** Least Privilege by Default & Non-Root Execution
- **ADR-006:** Local SQLite Storage Without External Telemetry
- **ADR-007:** Evidence Attribution Over Unverified Device Inferences
- **ADR-008:** Explicit Distinction Between Linux Kernel Scope and RFC Address Classification

---

### ADR-001: Debian 13 (Trixie) as Foundational Operating System
- **Context:** The platform requires an operating system base that offers maximum hardware stability, extensive native networking packages (iproute2, iw, ethtool, tcpdump), long-term support, and robust live-build tooling.
- **Decision:** Select Debian 13 (Trixie) as the initial distribution base.
- **Rationale:** Debian provides predictable packaging, reproducible live-build (`live-build`), wide architecture support (amd64, arm64), and an open governance model suitable for future commercial rebranding.
- **Consequences:** Distribution engineering leverages `live-build` and `debootstrap`. Commercial licensing must strictly respect Debian's Social Contract and Free Software Guidelines.

---

### ADR-002: Python 3.10+ as Primary Application Core Language
- **Context:** Core diagnostic logic, protocol parsing, and mathematical calculations need high maintainability, rapid iteration, and cross-platform testability without complex compilation toolchains.
- **Decision:** Implement application core and diagnostic subsystems in Python 3.10+ (tested against 3.13+).
- **Rationale:** Standard library networking (`socket`, `ssl`, `ipaddress`, `sqlite3`) covers 90% of non-root diagnostic requirements without external dependencies.
- **Consequences:** Low-level kernel or raw packet operations requiring microsecond timing or direct C syscalls are encapsulated behind well-defined IPC boundaries rather than scattering C extensions.

---

### ADR-003: PySide6 (Qt for Python) for Desktop Graphical Interface
- **Context:** The desktop GUI requires high-performance rendering for 2D graphs (real-time bandwidth charts, Dijkstra SPF trees, RF spectrum parabolas, and topology node graphs), dark glassmorphic styling, and native Linux desktop integration.
- **Decision:** Utilize PySide6 (official Qt for Python) with headless fallback.
- **Rationale:** Qt Graphics View framework (`QGraphicsScene`, `QPainter`) provides superior hardware-accelerated 2D canvas rendering compared to webview wrappers (Electron) or Tkinter. PySide6 is distributed under the LGPLv3 license, which allows dynamic linking in commercial applications.
- **Consequences:** PySide6 is an optional dependency for headless/CLI environments; all CLI commands remain 100% operational without Qt installed.

---

### ADR-004: Offline-First Architecture & Mock Provider Invariants
- **Context:** Network diagnostics are frequently required in air-gapped environments, isolated lab testbeds, or during link-down catastrophic failures.
- **Decision:** Implement all engines with offline-first deterministic mock provider fallbacks.
- **Rationale:** Guarantees that automated CI/CD test suites run in isolated containers without internet access, and prevents unhandled crashes when network interfaces are unconfigured.
- **Consequences:** The UI and CLI must explicitly distinguish between live data and simulated data, never presenting mock data as verified live evidence.

---

### ADR-005: Least Privilege by Default & Non-Root Execution
- **Context:** Running desktop applications or CLI tools as `root` or under `sudo` presents severe security risks (arbitrary file overwrite, unintended packet generation).
- **Decision:** Enforce non-root execution across all user-facing interfaces. Flag root execution as a security hazard.
- **Rationale:** Essential network diagnostics (DNS query, TCP latency, subnet calculation, `/proc` throughput inspection, TLS handshake) can be accomplished cleanly without root privileges.
- **Consequences:** Operations requiring Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`) must be isolated behind documented Polkit or dedicated unprivileged IPC helpers.

---

### ADR-006: Local SQLite Storage Without External Telemetry
- **Context:** Professional network diagnostic tools handle sensitive infrastructure topology, internal IP addresses, and security vulnerabilities that must remain strictly private.
- **Decision:** Store diagnostic history in local SQLite databases (`~/.config/itsa-network-os/`) with automated credential scrubbing. Zero telemetry or cloud beaconing.
- **Rationale:** Guarantees total data sovereignty for security consultants and enterprise administrators.
- **Consequences:** Multi-device synchronization in future commercial editions must be user-controlled and opt-in.

---

### ADR-007: Evidence Attribution Over Unverified Device Inferences
- **Context:** Network scanners often guess device operating systems or models from MAC addresses or single open ports, leading to inaccurate diagnostic reports.
- **Decision:** Enforce evidence tagging on all discovered attributes: track source protocol, timestamp, confidence level, and distinguish verified facts from inferences.
- **Rationale:** Technical decision-makers require accurate, defensible diagnostic reports.
- **Consequences:** The discovery engine refuses to claim a model or firmware version is verified unless direct evidence (certificate, SNMP MIB, HTTP banner, ONVIF response) confirms it.

---

### ADR-008: Explicit Distinction Between Linux Kernel Scope and RFC Address Classification
- **Context:** Linux network interface tooling (`iproute2`, `/proc/net/if_inet6`) attaches routing scope metadata (`RT_SCOPE`, e.g. `scope global`, `scope link`, `scope host`). In the Linux kernel, private RFC 1918 addresses (such as `10.125.191.24` and `192.168.1.1`) and IPv6 Unique Local Addresses (ULA, RFC 4193, `fc00::/7`) are assigned `scope global` to signify they route beyond the local broadcast link within the host's network. However, `scope global` does not mean the address is globally routable or reachable from the public Internet. Conflating kernel routing scope with RFC architectural address classification causes diagnostic ambiguity and false security assumptions.
- **Decision:** Explicitly decouple Linux interface scope metadata from RFC address classification in `IPAddressInfo` and `HostNetworkProvider`:
  - `scope`: Stores Linux kernel routing scope metadata (`"global"`, `"link"`, `"host"`, `"site"`).
  - `classification`: Stores RFC standard address classification derived via Python standard library `ipaddress` (`"loopback"`, `"private"`, `"link-local"`, `"unique-local"`, `"global-unicast"`, `"site-local"`, `"multicast"`, `"unspecified"`, `"reserved"`).
- **Rationale:** Preserves accurate low-level kernel metadata while providing true Internet-standard address classification without heuristic string slicing.
- **Consequences:** All consumers have clear, unambiguous data models. Backward compatibility is maintained because `scope` continues to convey kernel routing scope, and `classification` is exposed as a typed, optional field with default `None`.

---

### ADR-009: Local Gateway and DNS Association Semantics and Provenance
- **Context:** In multi-interface and dual-stack hosts, interfaces may have different routing roles (default gateway vs. isolated link) and differing resolver scopes (per-interface DNS from NetworkManager/systemd-resolved vs. host-wide fallback in `/etc/resolv.conf`). Conflating host-wide DNS with a specific interface or guessing default gateways based solely on IP addresses violates the evidence-based design principles of ITSA Network OS.
- **Decision:**
  1. Default Gateways: Associate default IPv4 and IPv6 gateways (`GatewayInfo`) strictly with the interface named by the corresponding default route (`0.0.0.0/0` or `::/0`). Never assume a gateway exists merely because an interface has an IP address. Preserve route metrics and origin protocols (`dhcp`, `ra`, `static`).
  2. DNS Nameservers: Model DNS nameservers using `DNSServerInfo` with explicit `scope` (`"interface"` vs. `"system"`), `interface` binding, and `provenance` (`"networkmanager"`, `"systemd-resolved"`, `"resolv.conf"`, `"mock"`).
     - Case A: When only host-wide `/etc/resolv.conf` exists, associate nameservers with interfaces holding a default route using `scope="system"`, `interface=None`, and `provenance="resolv.conf"`.
     - Case B: When reliable OS metadata links nameservers to a specific interface, associate them using `scope="interface"` and `interface="<ifname>"`.
     - Case C: Non-routed interfaces (e.g. `lo` or unrouted links) receive empty DNS server lists.
- **Rationale:** Eliminates misleading associations while providing complete diagnostic context. The interface object clearly distinguishes between verified per-link nameservers and global system resolvers.
- **Consequences:** `NetworkInterface` safely supports dual-stack default gateways and multi-nameserver resolver lists without breaking backwards compatibility or constructor signatures.


