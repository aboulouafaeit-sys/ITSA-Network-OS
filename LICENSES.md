# Software Bill of Materials (SBOM) & Licensing Compliance — ITSA Network OS

> **Document ID:** DOC-LIC-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Commercial Licensing Strategy & Legal Invariants

ITSA Network OS is designed to be distributed and sold legally as a commercial product with optional paid features, enterprise support, and custom device adapters.

### Non-Negotiable Legal Invariants:
1. **Debian & Linux Compliance:** Any distribution based on Debian must strictly honor the licenses of redistributed packages (Linux Kernel GPLv2, GNU utilities GPLv3, system libraries).
2. **Proprietary vs. Open Boundaries:** Proprietary or commercial extensions must interact with GPL components via standard user-space boundaries (CLI, IPC, network sockets) rather than static linking into copyleft binaries.
3. **PySide6 (Qt) LGPLv3 Compliance:** PySide6 and Qt libraries are dynamically linked via standard Python wheel/virtual environment mechanisms. Source code for Qt/PySide6 modifications (if any) must be provided in compliance with LGPLv3.
4. **Attribution & Notice:** All third-party copyright notices, licenses, and disclaimers must be preserved in redistributed builds.

---

## 2. Direct Software Bill of Materials (SBOM)

| Component Name | Type | Version / Range | License | Redistribution Terms & Compliance Actions |
|---|---|---|---|---|
| **ITSA Network OS Core** | Application | 0.1.0 | MIT License | Permissive; full commercial use, sublicensing, and modification allowed. |
| **Python Standard Library** | Runtime | 3.10 – 3.13 | PSF License 2.0 | Permissive; commercial redistribution permitted with notice. |
| **PySide6 / Qt6** | GUI Framework | 6.5.0 – 6.12.0 | LGPLv3 / Commercial | Dynamically linked via Python wheels; no static compilation; satisfies LGPLv3. |
| **Shiboken6** | Binding Generator | 6.12.0 | LGPLv3 | Dynamically linked; satisfies LGPLv3. |
| **Pytest** | Dev / Test | >=7.0.0 | MIT License | Permissive; dev dependency only (not shipped in runtime ISO). |
| **Pytest-Cov** | Dev / Test | >=4.0.0 | MIT License | Permissive; dev dependency only. |
| **Coverage** | Dev / Test | >=7.0.0 | Apache 2.0 | Permissive; dev dependency only. |

---

## 3. Debian 13 (Trixie) System Packages (Live ISO Manifest)

The bootable Debian Live ISO redistributes standard Debian packages defined in [itsa.list.chroot](file:///home/emorphi/Desktop/netF/itsa-network-os/debian-live/config/package-lists/itsa.list.chroot):

| Package Name | Category | Primary License | Compliance Mechanism |
|---|---|---|---|
| **linux-image-amd64** | Linux Kernel | GNU GPLv2 | Distributed via official Debian binary repositories; kernel sources available via Debian mirrors. |
| **systemd / systemd-sysv** | Init & Core System | LGPLv2.1+ / GPLv2 | Standard Debian binary distribution. |
| **iproute2** | Network Stack | GNU GPLv2 | Standard Debian binary distribution. |
| **iputils-ping** | Network Utilities | BSD-3-Clause / GPLv2 | Permissive & copyleft; standard distribution. |
| **dnsutils** | DNS Utilities | MPL-2.0 | Standard Debian binary distribution. |
| **ethtool** | NIC Diagnostics | GNU GPLv2 | Standard Debian binary distribution. |
| **tcpdump** | Packet Inspection | BSD-3-Clause | Permissive BSD license. |
| **net-tools** | Legacy Network Tools | GNU GPLv2 | Standard Debian binary distribution. |
| **traceroute** | Route Diagnostics | GNU GPLv2+ | Standard Debian binary distribution. |
| **curl** | Transfer Tool | curl / MIT | Permissive MIT-like license. |
| **sqlite3** | Embedded Database | Public Domain | Unrestricted public domain dedication. |
| **nmap** | Port Scanner | NPSL (Nmap Public Source License) | Documented attribution; standard Debian package. |
| **tshark / wireshark** | Packet Dissector | GNU GPLv2+ | Standard Debian binary distribution. |
| **iptables / nftables** | Packet Filtering | GNU GPLv2 | Standard Debian binary distribution. |
| **xfce4 / lightdm** | Desktop Environment | GPLv2+ / LGPLv2+ | Standard Debian desktop packages. |

---

## 4. Compliance Verification Procedure

To verify license compliance before any release:
1. Inspect virtual environment packages via `pip list --format=json` and verify licenses against the SBOM.
2. Ensure no proprietary commercial code is statically linked to GPLv2/GPLv3 libraries.
3. Validate that the Debian Live ISO build script (`build_live_iso.sh`) points exclusively to approved Debian archive areas (`main contrib non-free-firmware`).
4. Generate release SHA-256 checksums and archive SBOM snapshots alongside ISO releases.
