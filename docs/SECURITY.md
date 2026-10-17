# Security Policy — ITSA Network OS

## 1. Safety Principles & Host Protection
ITSA Network OS is developed under strict safety invariants to guarantee zero disruption to host environments, dual-boot partitions, and system configurations:

1. **Host Invariance**:
   - The application shall never alter partition tables, EFI boot entries, Windows partitions, or GRUB configurations.
   - The application shall never execute destructive disk operations (`dd`, `mkfs`, etc.).
2. **Read-Only Network Operations**:
   - Application modules do not modify host routing tables, DNS resolvers (`/etc/resolv.conf`), or interface assignments without explicit user action and prompt confirmation.
3. **Privilege Boundary**:
   - The software runs under regular user credentials. Administrator/root privileges (`sudo`) are prohibited for everyday operation.
4. **Credential & Secret Protection**:
   - The logging engine filters out keys, tokens, passwords, and sensitive system identifiers.
   - No telemetry, external beaconing, or unauthorized network calls are permitted.
5. **Safe Development**:
   - Initial and test network data is powered by `MockNetworkProvider` to ensure complete isolation and predictability.

## 2. Reporting Vulnerabilities
If you discover a security issue or unintentional privilege requirement within ITSA Network OS, please document the issue locally or notify maintainers without public disclosure until remediation is verified.
