"""Security validation and sanitization for ITSA Network OS."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path


class SecurityValidationError(ValueError):
    """Raised when an input fails security validation checks."""


class InputValidator:
    """Strict input validation rules for network parameters and system inputs."""

    INTERFACE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,16}$")

    @classmethod
    def validate_ipv4_address(cls, address: str) -> ipaddress.IPv4Address:
        """Validate string as IPv4 address."""
        clean = address.strip()
        try:
            return ipaddress.IPv4Address(clean)
        except ValueError as exc:
            raise SecurityValidationError(f"Invalid IPv4 address format: '{address}'") from exc

    @classmethod
    def validate_ipv4_network(cls, cidr: str) -> ipaddress.IPv4Network:
        """Validate string as IPv4 CIDR network (e.g., '192.168.1.0/24')."""
        clean = cidr.strip()
        try:
            return ipaddress.IPv4Network(clean, strict=False)
        except ValueError as exc:
            raise SecurityValidationError(f"Invalid IPv4 CIDR network: '{cidr}'") from exc

    @classmethod
    def validate_ip_network(cls, cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        """Validate string as either IPv4 or IPv6 CIDR network."""
        clean = cidr.strip()
        try:
            return ipaddress.ip_network(clean, strict=False)
        except ValueError as exc:
            raise SecurityValidationError(f"Invalid IP CIDR network: '{cidr}'") from exc

    @classmethod
    def validate_interface_name(cls, name: str) -> str:
        """Ensure interface name is alphanumeric without dangerous metacharacters."""
        clean = name.strip()
        if not cls.INTERFACE_PATTERN.match(clean):
            raise SecurityValidationError(f"Invalid network interface name: '{name}'")
        return clean

    @classmethod
    def validate_safe_path(cls, path_str: str, base_dir: Path | None = None) -> Path:
        """Check path against path traversal attacks."""
        resolved = Path(path_str).resolve()
        if base_dir:
            base_resolved = base_dir.resolve()
            try:
                resolved.relative_to(base_resolved)
            except ValueError as exc:
                raise SecurityValidationError(
                    f"Path '{path_str}' escapes allowed directory boundary '{base_dir}'"
                ) from exc
        return resolved
