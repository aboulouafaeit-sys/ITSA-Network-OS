# ITSA Network OS — Engineering Roadmap & Milestones

> **Document ID:** DOC-ROADMAP-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Roadmap Overview & Phased Progression

This roadmap outlines the systematic development of ITSA Network OS from its modular foundation to an independently maintained, commercially viable network operations platform.

---

## 2. Milestone 0: Foundation, Governance & Environment (`MILE-00`)

**Status:** `COMPLETED`
**Focus:** Audit verification, Single Source of Truth governance documentation, Linux virtual environment stabilization, and baseline safety tagging.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-001** | Git Safety Baseline Tag | None | `COMPLETED` | Tag `audit-baseline-v0.1.0` verified on master branch. |
| **TASK-002** | Linux Virtual Environment Stabilization | None | `COMPLETED` | Dedicated Linux virtual environment configured with PySide6 and dev tools; 107 tests pass natively. |
| **TASK-003** | Consolidate Single Source of Truth Documentation | None | `COMPLETED` | Root documents created: VISION, REQUIREMENTS, ARCHITECTURE, ROADMAP, SECURITY, TESTING, CONTRIBUTING, CHANGELOG, DECISIONS, LICENSES. |

---

## 3. Milestone 1: High-Fidelity Local Host Discovery (`MILE-01`)

**Status:** `COMPLETED`
**Focus:** Upgrade host interface discovery from partial `/sys/class/net` attributes to full IPv4/IPv6 addresses, netmasks, broadcast addresses, and gateway bindings on Linux.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-004** | Linux Kernel IP Address Resolver | TASK-002 | `COMPLETED` | Implement non-destructive socket/netlink/proc resolver in `HostNetworkProvider` extracting real IPv4/IPv6 addresses and CIDR prefix lengths. |
| **TASK-005** | Local Gateway & DNS Association | TASK-004 | `COMPLETED` | Associate default IPv4/IPv6 gateways and DNS nameservers directly with corresponding parent interfaces in `NetworkInterface`. |
| **TASK-006** | Unit & Integration Test Expansion for Host Provider | TASK-004 | `COMPLETED` | Exhaustive tests verifying interface IP extraction across physical, virtual, loopback, and wireless interfaces. |

---

## 4. Milestone 2: Evidence-Based Network Intelligence & Discovery (`MILE-02`)

**Status:** `COMPLETED`
**Focus:** Refactor multi-vendor discovery and wireless analysis to enforce evidence attribution, eliminate silent mock fallback, and implement passive broadcast listeners.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-007** | Evidence Data Model & Confidence Scoring | TASK-003 | `COMPLETED` | Implement `EvidenceRecord` attaching source protocol, timestamp, confidence (0.0-1.0), and `is_verified_fact` flag. |
| **TASK-008** | Authorized Network Scope Enclosure | TASK-007 | `COMPLETED` | Enforce fail-closed CIDR boundaries (default-deny, mandatory interface attribution, rebinding prevention, supernet rejection) preventing active queries outside user-approved networks (ADR-010). |
| **TASK-009** | Passive MNDP & ONVIF Broadcast Listeners | TASK-007 | `COMPLETED` | Implement unprivileged UDP broadcast listeners for MikroTik MNDP (UDP 5678) and ONVIF WS-Discovery (UDP 3702) with zero packet transmission, pure decoders, IP_PKTINFO attribution, and ScopeGuard authorization. |
| **TASK-010** | Elimination of Silent Mock Fallback | TASK-009 | `COMPLETED` | Clearly indicate in UI/CLI when live discovery returns 0 results vs. simulated mock fixtures. |

---

## 5. Milestone 3: Unified Data Schema & Persistence (`MILE-03`)

**Status:** `IN_PROGRESS`
**Focus:** Extend SQLite persistence engine to support all diagnostic entities, historical sessions, and secret-redacted export workflows.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-011** | SQLite Database Schema Migration Engine | TASK-003 | `COMPLETED` | Support versioned SQLite schema migrations for device inventory, Wi-Fi scans, and TLS audits. |
| **TASK-012** | Audit Trail & Historical Session Recording | TASK-011 | `PLANNED` | Persist full diagnostic sessions with automated redaction of sensitive credentials. |
| **TASK-013** | Multi-Format Technical Exporter | TASK-012 | `PLANNED` | Export technical reports in JSON, CSV, and formatted Markdown with executive summaries. |

---

## 6. Milestone 4: Wireless & Live RF Spectrum Engine (`MILE-04`)

**Status:** `PLANNED`  
**Focus:** Implement Linux-native non-destructive 802.11 airwave scanner using `nl80211` / `iw` parsers with graceful unprivileged fallback.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-014** | Linux Wireless Scanner Provider | TASK-004 | `PLANNED` | Parse 802.11 scan results non-destructively when wireless interface is present on host. |
| **TASK-015** | Live RF Waterfall & Congestion Analyzer | TASK-014 | `PLANNED` | Enhance Wi-Fi canvas visualizer to render real-time RF channel congestion metrics. |

---

## 7. Milestone 5: Privilege Boundaries & Distribution Packaging (`MILE-05`)

**Status:** `PLANNED`  
**Focus:** Define Polkit privilege boundaries, validate containerized Debian 13 Live ISO builds, and complete commercial SBOM compliance.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-016** | Polkit & Least-Privilege IPC Specification | TASK-008 | `PLANNED` | Document Polkit elevation policy for low-level packet capture helpers. |
| **TASK-017** | Automated Containerized ISO Build Verification | TASK-001 | `PLANNED` | Verify `scripts/build_live_iso.sh` generates a bootable Debian 13 ISO inside Docker container. |
| **TASK-018** | Commercial Licensing & SBOM Finalization | TASK-003 | `COMPLETED` | Full audit of third-party dependencies, licenses (MIT, LGPL, GPL), and release documentation. |

---

## 8. Milestone H: Official Global Brand Identity, Logo & Documentation (`MILE-H`)

**Status:** `COMPLETED`  
**Focus:** Establish an original, distinctive, globally recognizable brand identity, master vector artwork, complete design system, desktop UI integration, and professional GitHub documentation.

| Task ID | Task Description | Dependencies | Status | Acceptance Criteria |
|---|---|---|---|---|
| **TASK-H01** | Master Vector Symbol & Wordmark Design | None | `COMPLETED` | Geometric Resilient Lattice symbol and custom ITSA wordmark designed in clean, editable SVG format across dark, light, and monochrome variants. |
| **TASK-H02** | Complete Visual Identity System Specification | TASK-H01 | `COMPLETED` | Authored `docs/BRAND_IDENTITY.md` documenting brand mission, color palettes (HEX/RGB/CMYK), typography scale, 4px/8px grid, and prohibited modifications. |
| **TASK-H03** | Desktop Application Branding & About Dialog | TASK-H01 | `COMPLETED` | Window icon set via `setWindowIcon()`, header brand logo badge integrated into persistent shell, and branded About Dialog (`QDialog`) implemented. |
| **TASK-H04** | Debian Live System Launcher & Iconography | TASK-H01 | `COMPLETED` | Configured `itsa-network-os.desktop` with `Icon=itsa-network-os`, distributed scalable and raster icons to `/usr/share/icons/hicolor/`. |
| **TASK-H05** | Professional GitHub Presentation & Badges | TASK-H02 | `COMPLETED` | Updated `README.md` with official brand banner, visual directory hierarchy, 14 actual application screenshots, and verified status badges. |
| **TASK-H06** | Brand Quality Gate Verification & Raster Matrix | TASK-H01 | `COMPLETED` | Generated high-resolution transparent PNGs (16px to 512px), multi-resolution `.ico` binaries, and verified 100% test pass rate across 592 test cases. |

