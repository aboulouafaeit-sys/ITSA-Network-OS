"""Safe DNS diagnostics and resolution benchmarking."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from itsa_network_os.network.models import DNSServerInfo


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
        """Read system DNS resolvers from /etc/resolv.conf safely on Linux (legacy helper)."""
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
    def get_system_dns_servers(
        cls, use_mock: bool = False, resolv_content: Optional[str] = None
    ) -> List[DNSServerInfo]:
        """Read system-wide DNS nameservers from /etc/resolv.conf safely.

        Returns DNSServerInfo entries explicitly marked with scope='system'
        and interface=None to indicate host-level resolver configuration.
        """
        if use_mock:
            return [
                DNSServerInfo(
                    address="1.1.1.1",
                    scope="system",
                    interface=None,
                    provenance="mock",
                ),
                DNSServerInfo(
                    address="1.0.0.1",
                    scope="system",
                    interface=None,
                    provenance="mock",
                ),
            ]

        servers: List[DNSServerInfo] = []
        seen = set()

        content = resolv_content
        if content is None:
            resolv_path = Path("/etc/resolv.conf")
            if resolv_path.is_file():
                try:
                    content = resolv_path.read_text(encoding="utf-8")
                except Exception:
                    content = ""
            else:
                content = ""

        if not content:
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    ip_str = parts[1].strip()
                    try:
                        # Validate valid IPv4 or IPv6 address syntax
                        ipaddress.ip_address(ip_str)
                        if ip_str not in seen:
                            seen.add(ip_str)
                            servers.append(
                                DNSServerInfo(
                                    address=ip_str,
                                    scope="system",
                                    interface=None,
                                    provenance="resolv.conf",
                                )
                            )
                    except ValueError:
                        continue

        return servers

    @classmethod
    def parse_nmcli_dev_show_dns(cls, output: str) -> Dict[str, List[DNSServerInfo]]:
        """Parse unprivileged nmcli dev show output for per-interface DNS nameservers."""
        results: Dict[str, List[DNSServerInfo]] = {}
        current_dev: Optional[str] = None

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Support both colon-separated (terse) and column-aligned formats
            if line.startswith("GENERAL.DEVICE:"):
                current_dev = line.split(":", 1)[1].strip()
            elif "GENERAL.DEVICE" in line:
                parts = line.split()
                if len(parts) >= 2:
                    current_dev = parts[-1].strip()
            elif current_dev and ("IP4.DNS" in line or "IP6.DNS" in line):
                if ":" in line:
                    val = line.split(":", 1)[1].strip()
                else:
                    parts = line.split()
                    val = parts[-1].strip() if parts else ""

                if val:
                    try:
                        ipaddress.ip_address(val)
                        results.setdefault(current_dev, [])
                        if not any(d.address == val for d in results[current_dev]):
                            results[current_dev].append(
                                DNSServerInfo(
                                    address=val,
                                    scope="interface",
                                    interface=current_dev,
                                    provenance="networkmanager",
                                )
                            )
                    except ValueError:
                        pass

        return results

    @classmethod
    def get_interface_dns_servers(
        cls, use_mock: bool = False, raw_nmcli: Optional[str] = None
    ) -> Dict[str, List[DNSServerInfo]]:
        """Query operating system metadata for trustworthy per-interface DNS associations."""
        if use_mock:
            return {
                "eth0": [
                    DNSServerInfo(
                        address="192.168.1.1",
                        scope="interface",
                        interface="eth0",
                        provenance="mock",
                    )
                ]
            }

        if raw_nmcli is not None:
            return cls.parse_nmcli_dev_show_dns(raw_nmcli)

        try:
            res = subprocess.run(
                ["nmcli", "-t", "-f", "GENERAL.DEVICE,IP4.DNS,IP6.DNS", "dev", "show"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.5,
            )
            if res.returncode == 0 and res.stdout.strip():
                return cls.parse_nmcli_dev_show_dns(res.stdout)
        except Exception:
            pass

        return {}

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
