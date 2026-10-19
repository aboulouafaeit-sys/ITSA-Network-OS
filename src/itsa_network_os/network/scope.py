"""Authorized Network Scope Enclosure and Runtime Scope Guard for ITSA Network OS.

Enforces strict CIDR boundaries preventing active diagnostic queries or packet
transmission outside explicitly user-approved target networks and interfaces (REQ-DISC-002).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from itsa_network_os.security.validator import InputValidator, SecurityValidationError


class ScopeViolationError(SecurityValidationError):
    """Raised when an active diagnostic query targets an unauthorized IP, network, or interface."""


@dataclass(frozen=True)
class ScopeEnclosure:
    """Immutable data model representing user-authorized target CIDRs and interfaces.

    Attributes:
        cidrs: Tuple of validated IPv4/IPv6 CIDR networks.
        interfaces: Tuple of validated local network interfaces allowed for discovery.
        allow_loopback: If True (default), permits 127.0.0.1 and ::1 for local diagnostics.
        allow_global_internet: If False (default), prohibits overly broad 0.0.0.0/0 or ::/0.
    """

    cidrs: Tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], ...] = ()
    interfaces: Tuple[str, ...] = ()
    allow_loopback: bool = True
    allow_global_internet: bool = False

    def __post_init__(self) -> None:
        # Validate that cidrs is a tuple of networks
        validated_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for net in self.cidrs:
            if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                raise SecurityValidationError(
                    f"CIDR elements must be IPv4Network or IPv6Network, got {type(net).__name__}"
                )
            if net.prefixlen == 0 and not self.allow_global_internet:
                raise SecurityValidationError(
                    f"Overly broad network scope '{net}' is prohibited without explicit allow_global_internet=True"
                )
            validated_cidrs.append(net)
        object.__setattr__(self, "cidrs", tuple(validated_cidrs))

        # Validate interfaces
        validated_ifaces: List[str] = []
        for iface in self.interfaces:
            clean_iface = InputValidator.validate_interface_name(iface)
            validated_ifaces.append(clean_iface)
        object.__setattr__(self, "interfaces", tuple(validated_ifaces))

        # Ensure boolean fields
        if not isinstance(self.allow_loopback, bool):
            raise TypeError(f"allow_loopback must be a bool, got {type(self.allow_loopback).__name__}")
        if not isinstance(self.allow_global_internet, bool):
            raise TypeError(f"allow_global_internet must be a bool, got {type(self.allow_global_internet).__name__}")

    @classmethod
    def from_strings(
        cls,
        cidrs: Union[str, Iterable[str]] = (),
        interfaces: Union[str, Iterable[str]] = (),
        allow_loopback: bool = True,
        allow_global_internet: bool = False,
    ) -> ScopeEnclosure:
        """Construct ScopeEnclosure from string representations of CIDRs and interfaces.

        Accepts single comma-delimited strings or iterables of strings.
        """
        raw_cidr_list: List[str] = []
        if isinstance(cidrs, str):
            raw_cidr_list = [c.strip() for c in cidrs.split(",") if c.strip()]
        elif isinstance(cidrs, Iterable):
            raw_cidr_list = [str(c).strip() for c in cidrs if str(c).strip()]

        parsed_cidrs: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for c in raw_cidr_list:
            net = InputValidator.validate_ip_network(c)
            parsed_cidrs.append(net)

        raw_iface_list: List[str] = []
        if isinstance(interfaces, str):
            raw_iface_list = [i.strip() for i in interfaces.split(",") if i.strip()]
        elif isinstance(interfaces, Iterable):
            raw_iface_list = [str(i).strip() for i in interfaces if str(i).strip()]

        parsed_ifaces: List[str] = []
        for i in raw_iface_list:
            clean_i = InputValidator.validate_interface_name(i)
            parsed_ifaces.append(clean_i)

        return cls(
            cidrs=tuple(parsed_cidrs),
            interfaces=tuple(parsed_ifaces),
            allow_loopback=allow_loopback,
            allow_global_internet=allow_global_internet,
        )

    def is_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> bool:
        """Evaluate if target IP/host and interface fall strictly within authorized boundaries."""
        # 1. Check interface constraint if interface restrictions exist
        if self.interfaces and interface is not None:
            clean_iface = str(interface).strip()
            if clean_iface not in self.interfaces:
                return False

        # 2. Check IP address
        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip_obj = target
        else:
            clean_target = str(target).strip()
            if not clean_target:
                return False
            try:
                ip_obj = ipaddress.ip_address(clean_target)
            except ValueError:
                # Target is not an IP literal; candidate hostname
                if clean_target.lower() in ("localhost", "localhost.localdomain"):
                    return self.allow_loopback

                # Resolve hostname
                if resolver is not None:
                    resolved_ips = resolver(clean_target)
                else:
                    try:
                        addrinfo = socket.getaddrinfo(clean_target, None)
                        resolved_ips = list({item[4][0] for item in addrinfo})
                    except (socket.gaierror, OSError):
                        return False

                if not resolved_ips:
                    return False

                # All resolved IPs must be authorized
                return all(self.is_authorized(r_ip, interface=interface) for r_ip in resolved_ips)

        # 3. Check loopback authorization
        if self.allow_loopback and ip_obj.is_loopback:
            return True

        # 4. Check CIDR inclusion
        for cidr in self.cidrs:
            if ip_obj in cidr:
                return True

        # Default deny
        return False

    def assert_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> None:
        """Verify target authorization, raising ScopeViolationError if unauthorized."""
        if self.interfaces and interface is not None:
            clean_iface = str(interface).strip()
            if clean_iface not in self.interfaces:
                raise ScopeViolationError(
                    f"Interface '{clean_iface}' is not in authorized interfaces: {list(self.interfaces)}"
                )

        if not self.is_authorized(target, interface=interface, resolver=resolver):
            raise ScopeViolationError(
                f"Target '{target}' is outside user-authorized network scope (CIDRs: {[str(c) for c in self.cidrs]})"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize ScopeEnclosure to dictionary."""
        return {
            "cidrs": [str(c) for c in self.cidrs],
            "interfaces": list(self.interfaces),
            "allow_loopback": self.allow_loopback,
            "allow_global_internet": self.allow_global_internet,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScopeEnclosure:
        """Deserialize ScopeEnclosure from dictionary."""
        return cls.from_strings(
            cidrs=data.get("cidrs", ()),
            interfaces=data.get("interfaces", ()),
            allow_loopback=bool(data.get("allow_loopback", True)),
            allow_global_internet=bool(data.get("allow_global_internet", False)),
        )


class ScopeGuard:
    """Runtime boundary enforcement gatekeeper for active diagnostics and network queries."""

    def __init__(self, enclosure: Optional[ScopeEnclosure] = None, active: bool = True) -> None:
        self._enclosure = enclosure
        self._active = active

    @property
    def enclosure(self) -> Optional[ScopeEnclosure]:
        """Active ScopeEnclosure, or None if unconstrained."""
        return self._enclosure

    @property
    def is_active(self) -> bool:
        """Return True if scope enforcement is currently active."""
        return self._active and self._enclosure is not None

    def set_enclosure(self, enclosure: ScopeEnclosure) -> None:
        """Set or update the active authorized scope enclosure."""
        if not isinstance(enclosure, ScopeEnclosure):
            raise TypeError(f"enclosure must be a ScopeEnclosure, got {type(enclosure).__name__}")
        self._enclosure = enclosure
        self._active = True

    def clear(self) -> None:
        """Clear the active scope enclosure, resetting to unconstrained."""
        self._enclosure = None
        self._active = False

    def is_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> bool:
        """Return True if target is authorized under current active enclosure."""
        if not self.is_active or self._enclosure is None:
            return True
        return self._enclosure.is_authorized(target, interface=interface, resolver=resolver)

    def assert_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> None:
        """Raise ScopeViolationError if target is unauthorized under current active enclosure."""
        if not self.is_active or self._enclosure is None:
            return
        self._enclosure.assert_authorized(target, interface=interface, resolver=resolver)
