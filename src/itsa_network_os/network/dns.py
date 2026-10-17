"""Safe DNS diagnostics and resolution benchmarking."""

from __future__ import annotations

import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DNSRecord:
    """DNS resolution record entry."""

    record_type: str
    value: str
    ttl: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DNSDiagnosticResult:
    """Consolidated DNS diagnostic query result."""

    target_host: str
    response_time_ms: float
    records: List[DNSRecord] = field(default_factory=list)
    system_resolvers: List[str] = field(default_factory=list)
    status: str = "SUCCESS"
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["records"] = [r.to_dict() for r in self.records]
        return data


class DNSDiagnostics:
    """Performs non-destructive DNS resolution queries and latency checks."""

    @staticmethod
    def get_system_resolvers() -> List[str]:
        """Read system DNS resolvers from /etc/resolv.conf safely on Linux."""
        resolvers: List[str] = []
        resolv_path = Path("/etc/resolv.conf")
        if resolv_path.is_file():
            try:
                for line in resolv_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("nameserver "):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
            except Exception:
                pass

        if not resolvers:
            resolvers.append("System Default Resolver")
        return resolvers

    @classmethod
    def query(cls, host: str, timeout: float = 3.0, use_mock: bool = False) -> DNSDiagnosticResult:
        """Resolve host addresses safely and measure response latency."""
        host_clean = host.strip()
        system_resolvers = cls.get_system_resolvers()

        if use_mock:
            return cls._mock_query(host_clean, system_resolvers)

        start_time = time.perf_counter()
        records: List[DNSRecord] = []

        try:
            # Safe standard library resolution (A and AAAA records)
            addr_info = socket.getaddrinfo(host_clean, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            seen_addresses = set()
            for family, _, _, _, sockaddr in addr_info:
                ip = sockaddr[0]
                if ip not in seen_addresses:
                    seen_addresses.add(ip)
                    record_type = "AAAA" if family == socket.AF_INET6 else "A"
                    records.append(DNSRecord(record_type=record_type, value=ip))

            return DNSDiagnosticResult(
                target_host=host_clean,
                response_time_ms=elapsed_ms,
                records=records,
                system_resolvers=system_resolvers,
                status="SUCCESS",
            )
        except socket.gaierror as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DNSDiagnosticResult(
                target_host=host_clean,
                response_time_ms=elapsed_ms,
                records=[],
                system_resolvers=system_resolvers,
                status="FAILED",
                error_message=f"Resolution error: {exc}",
            )
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DNSDiagnosticResult(
                target_host=host_clean,
                response_time_ms=elapsed_ms,
                records=[],
                system_resolvers=system_resolvers,
                status="ERROR",
                error_message=f"Unexpected error: {exc}",
            )

    @classmethod
    def _mock_query(cls, host: str, resolvers: List[str]) -> DNSDiagnosticResult:
        """Return safe mock DNS results for isolated offline testing."""
        mock_records = [
            DNSRecord(record_type="A", value="93.184.216.34"),
            DNSRecord(record_type="AAAA", value="2606:2800:220:1:248:1893:25c8:1946"),
        ]
        return DNSDiagnosticResult(
            target_host=host,
            response_time_ms=12.45,
            records=mock_records,
            system_resolvers=resolvers if resolvers else ["127.0.0.53"],
            status="SUCCESS",
        )
