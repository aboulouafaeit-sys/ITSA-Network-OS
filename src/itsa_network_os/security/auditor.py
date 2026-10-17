"""Safe, read-only local security auditing and configuration assessment."""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Vulnerability or advisory severity rating."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class SecurityFinding:
    """Individual security audit finding."""

    category: str
    title: str
    severity: Severity
    description: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(frozen=True)
class SecurityAuditReport:
    """Consolidated security audit report."""

    overall_score: int  # 0 to 100
    findings: List[SecurityFinding] = field(default_factory=list)
    open_local_ports: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "findings": [f.to_dict() for f in self.findings],
            "open_local_ports": self.open_local_ports,
        }


class SecurityAuditor:
    """Non-destructive security configuration auditor operating under least privilege."""

    # Common local ports to check for insecure legacy protocols or exposed services on localhost
    AUDIT_PORTS = {
        21: ("FTP", Severity.HIGH, "Unencrypted File Transfer Protocol detected listening locally."),
        23: ("Telnet", Severity.CRITICAL, "Insecure cleartext Telnet service detected listening locally."),
        22: ("SSH", Severity.INFO, "Secure Shell service detected listening locally."),
        80: ("HTTP", Severity.LOW, "Plaintext HTTP web service listening locally."),
        443: ("HTTPS", Severity.INFO, "Encrypted HTTPS service detected listening locally."),
        3306: ("MySQL", Severity.LOW, "MySQL database service detected listening locally."),
        5432: ("PostgreSQL", Severity.LOW, "PostgreSQL database service detected listening locally."),
        6379: ("Redis", Severity.MEDIUM, "Redis in-memory store listening locally. Ensure auth is enabled."),
    }

    @classmethod
    def audit_local_services(cls, timeout: float = 0.1) -> List[int]:
        """Scan localhost (127.0.0.1) ports safely to detect local service bindings."""
        open_ports: List[int] = []
        for port in cls.AUDIT_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    if sock.connect_ex(("127.0.0.1", port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        return open_ports

    @classmethod
    def run_audit(cls, use_mock: bool = False) -> SecurityAuditReport:
        """Execute non-destructive security audit and compile report."""
        if use_mock:
            return cls._mock_audit()

        findings: List[SecurityFinding] = []
        deductions = 0

        # 1. Privilege level audit
        is_root = False
        if hasattr(os, "geteuid"):
            is_root = (os.geteuid() == 0)

        if is_root:
            findings.append(
                SecurityFinding(
                    category="Privilege Boundary",
                    title="Process Running as Superuser / Root",
                    severity=Severity.HIGH,
                    description="The application is executing with superuser permissions.",
                    recommendation="Execute network tools under an unprivileged user account to restrict blast radius.",
                )
            )
            deductions += 25
        else:
            findings.append(
                SecurityFinding(
                    category="Privilege Boundary",
                    title="Unprivileged Execution Verified",
                    severity=Severity.INFO,
                    description="Application process is executing as an unprivileged user.",
                    recommendation="Maintain non-root execution policy.",
                )
            )

        # 2. Local listening services audit
        open_ports = cls.audit_local_services()
        for port in open_ports:
            svc_name, sev, desc = cls.AUDIT_PORTS.get(port, ("Unknown", Severity.INFO, "Service listening"))
            findings.append(
                SecurityFinding(
                    category="Network Exposure",
                    title=f"Local Service Detected: {svc_name} (Port {port})",
                    severity=sev,
                    description=desc,
                    recommendation=f"Review if port {port} is required. Disable unnecessary services or bind to localhost only.",
                )
            )
            if sev == Severity.CRITICAL:
                deductions += 35
            elif sev == Severity.HIGH:
                deductions += 20
            elif sev == Severity.MEDIUM:
                deductions += 10
            elif sev == Severity.LOW:
                deductions += 5

        # 3. Secure storage permissions check
        config_dir = Path.home() / ".config" / "itsa-network-os"
        if config_dir.is_dir() and hasattr(os, "stat"):
            mode = config_dir.stat().st_mode & 0o777
            if mode not in (0o700, 0o750, 0o755):
                findings.append(
                    SecurityFinding(
                        category="Access Control",
                        title="Configuration Directory Permissions Permissive",
                        severity=Severity.MEDIUM,
                        description=f"Local configuration directory mode is {oct(mode)}.",
                        recommendation=f"Restrict configuration directory permissions to 0700 (`chmod 700 {config_dir}`).",
                    )
                )
                deductions += 10

        overall_score = max(0, 100 - deductions)
        return SecurityAuditReport(
            overall_score=overall_score,
            findings=findings,
            open_local_ports=open_ports,
        )

    @classmethod
    def _mock_audit(cls) -> SecurityAuditReport:
        """Deterministic mock audit report for offline testing."""
        return SecurityAuditReport(
            overall_score=95,
            findings=[
                SecurityFinding(
                    category="Privilege Boundary",
                    title="Unprivileged Execution Verified",
                    severity=Severity.INFO,
                    description="Application is executing with regular non-root privileges.",
                    recommendation="Maintain non-root policy.",
                ),
                SecurityFinding(
                    category="Network Exposure",
                    title="Local Service Detected: HTTPS (Port 443)",
                    severity=Severity.INFO,
                    description="Encrypted HTTPS service detected listening locally.",
                    recommendation="Ensure TLS 1.3 is enforced and certificates are up to date.",
                ),
            ],
            open_local_ports=[443],
        )
