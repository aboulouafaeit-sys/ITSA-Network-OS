"""Authorized Network Scope Enclosure and Runtime Scope Guard for ITSA Network OS.

Enforces strict CIDR boundaries preventing active diagnostic queries or packet
transmission outside explicitly user-approved target networks and interfaces (REQ-DISC-002).
Implements a strict fail-closed (default-deny) policy for all active network operations.
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
        allow_global_internet: If False (default), prohibits overly broad prefixes
            (IPv4 prefixlen < 8, IPv6 prefixlen < 7, and prefixlen == 0). These are scope-size
            rules designed to prevent internet-wide scanning, not RFC 1918 or ULA classifications;
            public subnets meeting prefix-length limits (e.g. 8.8.8.0/24) are permitted.
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
            if not self.allow_global_internet:
                if net.prefixlen == 0:
                    raise SecurityValidationError(
                        f"Overly broad network scope '{net}' (prefixlen 0) is prohibited without explicit allow_global_internet=True"
                    )
                if isinstance(net, ipaddress.IPv4Network) and net.prefixlen < 8:
                    raise SecurityValidationError(
                        f"Overly broad IPv4 network scope '{net}' (prefixlen < 8) is prohibited without explicit allow_global_internet=True"
                    )
                if isinstance(net, ipaddress.IPv6Network) and net.prefixlen < 7:
                    raise SecurityValidationError(
                        f"Overly broad IPv6 network scope '{net}' (prefixlen < 7) is prohibited without explicit allow_global_internet=True"
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
        # 1. Mandatory interface constraint check
        if self.interfaces:
            if interface is None:
                # Missing interface attribution fails closed when interfaces are restricted
                return False
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
                    try:
                        resolved_ips = resolver(clean_target)
                    except Exception:
                        return False
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

        # 4. Check IPv4-mapped IPv6 address (e.g. ::ffff:192.168.1.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            mapped_v4 = ip_obj.ipv4_mapped
            if self.allow_loopback and mapped_v4.is_loopback:
                return True
            for cidr in self.cidrs:
                if isinstance(cidr, ipaddress.IPv4Network) and mapped_v4 in cidr:
                    return True

        # 5. Check CIDR inclusion
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
        if self.interfaces:
            if interface is None:
                raise ScopeViolationError(
                    f"Target '{target}' requested without interface attribution, but scope restricts "
                    f"operations to interfaces: {list(self.interfaces)}"
                )
            clean_iface = str(interface).strip()
            if clean_iface not in self.interfaces:
                raise ScopeViolationError(
                    f"Interface '{clean_iface}' is not in authorized interfaces: {list(self.interfaces)}"
                )

        if not self.is_authorized(target, interface=interface, resolver=resolver):
            raise ScopeViolationError(
                f"Target '{target}' is outside user-authorized network scope (CIDRs: {[str(c) for c in self.cidrs]})"
            )

    def is_active_unicast_target(
        self, target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]
    ) -> bool:
        """Verify if target is a valid unicast host (excluding IPv4 network/broadcast addresses for prefixes <= 30).

        RFC 3021 /31 point-to-point subnets and /32 host routes permit all addresses as valid endpoints.
        """
        if isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            ip_obj = target
        else:
            clean = str(target).strip()
            try:
                ip_obj = ipaddress.ip_address(clean)
            except ValueError:
                return True

        if isinstance(ip_obj, ipaddress.IPv4Address):
            for cidr in self.cidrs:
                if isinstance(cidr, ipaddress.IPv4Network) and ip_obj in cidr:
                    if cidr.prefixlen <= 30:
                        if ip_obj == cidr.network_address or ip_obj == cidr.broadcast_address:
                            return False
        return True

    def resolve_and_verify(
        self,
        target: str,
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
        check_unicast: bool = False,
    ) -> str:
        """Resolve target and verify ALL resolved IPs are in scope.

        Returns the verified IP string to use for subsequent socket connection,
        guaranteeing no DNS rebinding or re-resolution mismatch occurs.
        """
        clean_target = str(target).strip()
        if not clean_target:
            raise ScopeViolationError("Target address cannot be empty")

        # Check if target is already an IP literal
        try:
            ip_obj = ipaddress.ip_address(clean_target)
            self.assert_authorized(ip_obj, interface=interface)
            if check_unicast and not self.is_active_unicast_target(ip_obj):
                raise ScopeViolationError(
                    f"Target IP '{clean_target}' is a subnet network or broadcast address and ineligible for active unicast connections"
                )
            return clean_target
        except ValueError:
            pass

        # Target is a candidate hostname
        if clean_target.lower() in ("localhost", "localhost.localdomain"):
            if not self.allow_loopback:
                raise ScopeViolationError(f"Target '{clean_target}' resolves to loopback which is disabled by scope policy")
            return "127.0.0.1"

        if resolver is not None:
            try:
                resolved_ips = resolver(clean_target)
            except Exception as exc:
                raise ScopeViolationError(f"Failed to resolve target hostname '{clean_target}': {exc}") from exc
        else:
            try:
                addrinfo = socket.getaddrinfo(clean_target, None)
                resolved_ips = list({item[4][0] for item in addrinfo})
            except (socket.gaierror, OSError) as exc:
                raise ScopeViolationError(f"Failed to resolve target hostname '{clean_target}': {exc}") from exc

        if not resolved_ips:
            raise ScopeViolationError(f"Target hostname '{clean_target}' resolved to 0 addresses")

        # Every resolved IP must be authorized
        for r_ip in resolved_ips:
            self.assert_authorized(r_ip, interface=interface)
            if check_unicast and not self.is_active_unicast_target(r_ip):
                raise ScopeViolationError(
                    f"Target hostname '{clean_target}' resolved to ineligible network/broadcast IP '{r_ip}'"
                )

        # Return the first validated IP for deterministic socket connection
        return resolved_ips[0]

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
    """Runtime boundary enforcement gatekeeper for active diagnostics and network queries.

    Implements a strict fail-closed (default-deny) policy. If unconfigured or cleared,
    active network operations are strictly rejected.
    """

    def __init__(self, enclosure: Optional[ScopeEnclosure] = None) -> None:
        self._enclosure = enclosure

    @property
    def enclosure(self) -> Optional[ScopeEnclosure]:
        """Active ScopeEnclosure, or None if unconfigured."""
        return self._enclosure

    @property
    def is_configured(self) -> bool:
        """Return True if an authorized scope enclosure has been configured."""
        return self._enclosure is not None and bool(self._enclosure.cidrs or self._enclosure.interfaces)

    @property
    def is_active(self) -> bool:
        """Return True if an authorized scope enclosure has been configured."""
        return self.is_configured

    def set_enclosure(self, enclosure: ScopeEnclosure) -> None:
        """Set or update the active authorized scope enclosure."""
        if not isinstance(enclosure, ScopeEnclosure):
            raise TypeError(f"enclosure must be a ScopeEnclosure, got {type(enclosure).__name__}")
        self._enclosure = enclosure

    def clear(self) -> None:
        """Clear active scope enclosure, resetting to safe default-deny state."""
        self._enclosure = ScopeEnclosure(cidrs=(), interfaces=(), allow_loopback=False)

    def is_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> bool:
        """Return True if target is authorized under current active enclosure.

        Fails closed (returns False) when unconfigured.
        """
        if self._enclosure is None:
            return False
        return self._enclosure.is_authorized(target, interface=interface, resolver=resolver)

    def assert_authorized(
        self,
        target: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
    ) -> None:
        """Raise ScopeViolationError if target is unauthorized.

        Fails closed (raises ScopeViolationError) when unconfigured.
        """
        if self._enclosure is None:
            raise ScopeViolationError(
                f"No authorized network scope has been configured; active query targeting '{target}' "
                "is denied by default-deny security policy (REQ-DISC-002)"
            )
        self._enclosure.assert_authorized(target, interface=interface, resolver=resolver)

    def resolve_and_verify_target(
        self,
        target: str,
        interface: Optional[str] = None,
        resolver: Optional[Callable[[str], List[str]]] = None,
        check_unicast: bool = True,
    ) -> str:
        """Resolve target and verify compliance, returning validated IP for connection.

        Fails closed when unconfigured.
        """
        if self._enclosure is None:
            raise ScopeViolationError(
                f"No authorized network scope has been configured; active query targeting '{target}' "
                "is denied by default-deny security policy (REQ-DISC-002)"
            )
        return self._enclosure.resolve_and_verify(
            target,
            interface=interface,
            resolver=resolver,
            check_unicast=check_unicast,
        )


def get_interface_source_ip(interface_name: str, target_ip: str) -> Optional[str]:
    """Find local IP address assigned to interface matching the target address family.

    Note on Linux Weak Host Routing:
    Binding source_address to an interface's local IP assigns the source IP header
    of outgoing packets, but does not by itself force physical egress through that
    interface when Linux weak host routing directs traffic based on destination FIB lookups.
    Use check_interface_route to verify routing table alignment at preflight.
    """
    from itsa_network_os.network.inspector import HostNetworkProvider

    try:
        target_obj = ipaddress.ip_address(target_ip)
        target_family = "IPv4" if isinstance(target_obj, ipaddress.IPv4Address) else "IPv6"
    except ValueError:
        target_family = "IPv4"

    try:
        provider = HostNetworkProvider()
        interfaces = provider.get_interfaces()
        for iface in interfaces:
            if iface.name == interface_name:
                for addr in iface.addresses:
                    if addr.family == target_family:
                        return addr.address
    except Exception:
        pass
    return None


def check_interface_route(
    interface_name: str,
    target_ip: str,
    use_mock: bool = False,
    routes: Optional[List[Any]] = None,
) -> None:
    """Preflight check validating kernel route to target_ip aligns with interface_name.

    Performs longest-prefix-match (and metric tie-breaking) across IPv4/IPv6 routing tables.
    Fails closed with ScopeViolationError if:
    - target_ip is invalid or cannot be parsed.
    - No matching kernel route exists.
    - The winning route directs traffic through an interface other than interface_name.

    Guarantees and Platform Limitations:
    On Linux, unprivileged sockets adhere to the weak host routing model (RFC 1122).
    Binding source_address alone sets the source IP header but does NOT force egress
    through the physical interface associated with that IP if the kernel routing
    table directs the packet elsewhere.
    This unprivileged preflight check verifies that kernel routes currently match the
    requested interface at check time. However, it cannot guarantee physical interface
    confinement against concurrent route changes (TOCTOU) or complex policy routing,
    and unprivileged processes cannot use SO_BINDTODEVICE (which requires CAP_NET_RAW / root).
    """
    from itsa_network_os.network.routes import RouteParser

    clean_target = str(target_ip).strip()
    try:
        target_obj = ipaddress.ip_address(clean_target)
    except ValueError as exc:
        raise ScopeViolationError(
            f"Target '{clean_target}' is not a valid IP address for route preflight: {exc}"
        ) from exc

    target_family = "IPv4" if isinstance(target_obj, ipaddress.IPv4Address) else "IPv6"

    if routes is None:
        routes = RouteParser.get_routes(use_mock=use_mock, family=target_family)

    matching_routes: List[Tuple[int, int, Any]] = []

    for route in routes:
        if getattr(route, "family", "IPv4") != target_family:
            continue

        dest = str(getattr(route, "destination", "")).strip()
        netmask = str(getattr(route, "netmask", "")).strip()

        try:
            if target_family == "IPv4":
                if dest == "default":
                    network = ipaddress.IPv4Network("0.0.0.0/0")
                elif "/" in dest:
                    network = ipaddress.IPv4Network(dest, strict=False)
                elif netmask and netmask != "0.0.0.0":
                    network = ipaddress.IPv4Network(f"{dest}/{netmask}", strict=False)
                else:
                    network = ipaddress.IPv4Network(f"{dest}/32")
            else:
                if dest == "default":
                    network = ipaddress.IPv6Network("::/0")
                elif "/" in dest:
                    network = ipaddress.IPv6Network(dest, strict=False)
                elif netmask and netmask.startswith("::/"):
                    prefix = netmask.split("/")[1]
                    network = ipaddress.IPv6Network(f"{dest}/{prefix}", strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{dest}/128")

            if target_obj in network:
                metric = int(getattr(route, "metric", 0))
                matching_routes.append((network.prefixlen, -metric, route))
        except (ValueError, Exception):
            continue

    if not matching_routes:
        raise ScopeViolationError(
            f"No kernel route found for target IP '{clean_target}'; cannot establish interface egress constraint for '{interface_name}'"
        )

    # Sort: longest prefix match first, lowest metric tie-breaker
    matching_routes.sort(key=lambda item: (item[0], item[1]), reverse=True)
    best_route = matching_routes[0][2]

    if best_route.interface != interface_name:
        raise ScopeViolationError(
            f"Kernel routing table directs traffic for '{clean_target}' via interface '{best_route.interface}', "
            f"which does not match requested interface constraint '{interface_name}'"
        )

