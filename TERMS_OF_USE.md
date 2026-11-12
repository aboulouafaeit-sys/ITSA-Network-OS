# ITSA Network OS — Terms of Use & Acceptable Use Policy

> **Document ID:** DOC-TERMS-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-11-13  

---

## 1. Acceptance of Terms

By accessing, downloading, installing, running, compiling, or contributing to **ITSA Network OS**, you agree to be bound by the terms, conditions, policies, and operational invariants set forth in this document. If you do not agree with these terms, you must not use or distribute this software.

---

## 2. Intended Defensive Purpose & Authorized Scope

ITSA Network OS is engineered exclusively as a **defensive network engineering, diagnostics, educational research, and infrastructure visibility platform**.

### 2.1 Authorized Scenarios
Users may deploy ITSA Network OS for:
- Auditing and monitoring network infrastructure owned by the user.
- Diagnosing systems where express written authorization has been granted by the network owner.
- Academic, research, lab, and training simulations inside isolated sandbox environments.
- Telemetry collection, bandwidth profiling, and cryptographic certificate auditing in compliance with local organizational policies.

### 2.2 Prohibited Conduct & Misuse
You strictly agree NOT to:
- Use ITSA Network OS against any network, host, service, or device without prior explicit authorization from the legitimate owner.
- Deploy active probes, automated latency floods, or connection exhausts to degrade network availability (Denial of Service).
- Attempt to intercept, decrypt, or tamper with communications belonging to third parties outside your designated testing scope.
- Violate applicable local, national, or international computer crime laws, regulations, or telecommunications statutes.

---

## 3. Host System Invariants & Non-Destructive Guarantees

ITSA Network OS is designed with non-negotiable architectural safety invariants:
1. **Zero Partition Tampering:** The platform runtime shall never format, modify, repartition, or overwrite host partition tables, EFI bootloader partitions, or neighboring operating system files (including Windows and other Linux distributions).
2. **Read-Only Baseline:** Core diagnostic modules operate strictly in read-only mode by default. No route alterations, DNS modifications, or interface state changes occur without interactive administrative confirmation.
3. **Least-Privilege Enforcement:** The graphical interface and CLI commands execute under standard unprivileged user credentials. Any privileged operations are isolated behind dedicated IPC helpers and Polkit authentication gates.
4. **Data Privacy & Zero Telemetry:** No user metrics, host identifiers, network topologies, or scan outputs are transmitted to external servers. All operations remain entirely local.

---

## 4. Software Licensing & Distribution Invariants

- **ITSA Network OS Core:** Licensed under the permissive MIT License (see [LICENSE](LICENSE)).
- **Third-Party Components:** The software links to and coordinates with open-source components (including Python, PySide6/Qt, and Debian system packages). Each component remains governed by its respective upstream license (GPL, LGPLv3, Apache 2.0, BSD, etc.).
- **Redistribution Compliance:** Anyone redistributing ITSA Network OS or ISO builds must preserve all copyright notices, disclaimers, and the Software Bill of Materials (see [LICENSES.md](LICENSES.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

---

## 5. Disclaimer of Warranties

ITSA NETWORK OS IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. THE AUTHORS AND MAINTAINERS DO NOT GUARANTEE THAT THE PLATFORM WILL OPERATE ERROR-FREE, UNINTERRUPTED, OR COMPATIBLE WITH EVERY HARDWARE VENDOR IMPLEMENTATION.

---

## 6. Limitation of Liability

IN NO EVENT SHALL THE AUTHORS, MAINTAINERS, OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA, NETWORK DOWNTIME, SECURITY INCIDENTS, HARDWARE DAMAGE, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## 7. Modifications & Inquiries

The maintainers reserve the right to revise these Terms of Use as new capabilities, safety controls, and statutory requirements evolve.

For inquiries, permissions, or security disclosures:
- **Security Policy:** [SECURITY.md](SECURITY.md)
- **Maintainer Contact:** `aboulouafae.sys@gmail.com`
- **Issue Tracker:** https://github.com/aboulouafaeit-sys/ITSA-Network-OS/issues
