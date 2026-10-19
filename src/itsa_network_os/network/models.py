"""Data models for networking entities in ITSA Network OS."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class InterfaceType(str, Enum):
    """Classification of network interface."""

    ETHERNET = "Ethernet"
    WIRELESS = "Wireless"
    LOOPBACK = "Loopback"
    VIRTUAL = "Virtual"
    UNKNOWN = "Unknown"


class InterfaceState(str, Enum):
    """Operational state of network interface."""

    UP = "UP"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class IPAddressInfo:
    """IP address attached to an interface."""

    address: str
    prefix_length: int
    family: str  # IPv4 or IPv6
    netmask: str = ""
    broadcast: Optional[str] = None
    scope: Optional[str] = None  # Linux interface scope metadata (e.g. "global", "link", "host")
    classification: Optional[str] = None  # RFC architectural classification (e.g. "private", "loopback", "global-unicast", "link-local", "unique-local")
    flags: List[str] = field(default_factory=list)


    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GatewayInfo:
    """Default gateway associated with a network interface.

    Attributes:
        gateway: IPv4 or IPv6 gateway address (e.g. "192.168.1.1" or "fe80::1").
        family: Address family ("IPv4" or "IPv6").
        metric: Optional route priority metric (lower indicates higher priority).
        interface: Associated network interface name (e.g. "eth0").
        protocol: Routing protocol or origin (e.g. "dhcp", "kernel", "static", "ra").
        flags: Route flags (e.g. ["UG"]).
    """

    gateway: str
    family: str  # IPv4 or IPv6
    metric: Optional[int] = None
    interface: str = ""
    protocol: Optional[str] = None
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DNSServerInfo:
    """DNS nameserver entry with provenance and association scope.

    Attributes:
        address: IP address of the DNS resolver (e.g. "1.1.1.1" or "2606:4700:4700::1111").
        scope: Association scope:
            - "interface": Proven per-interface nameserver from NetworkManager, systemd-resolved, or DHCP lease.
            - "system": Host-wide nameserver from /etc/resolv.conf without verified interface-specific binding.
        interface: Specific interface name if scope == "interface", else None.
        provenance: Origin of resolver data (e.g. "networkmanager", "systemd-resolved", "resolv.conf", "mock").
    """

    address: str
    scope: str = "system"  # "interface" or "system"
    interface: Optional[str] = None
    provenance: str = "resolv.conf"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NetworkInterface:
    """Network interface representation."""

    name: str
    mac_address: str
    state: InterfaceState
    interface_type: InterfaceType
    mtu: int = 1500
    addresses: List[IPAddressInfo] = field(default_factory=list)
    gateways: List[GatewayInfo] = field(default_factory=list)
    dns_servers: List[DNSServerInfo] = field(default_factory=list)

    @property
    def default_ipv4_gateway(self) -> Optional[str]:
        """Convenience accessor for primary IPv4 default gateway address."""
        v4_gws = [g for g in self.gateways if g.family == "IPv4"]
        if not v4_gws:
            return None
        v4_sorted = sorted(v4_gws, key=lambda g: g.metric if g.metric is not None else 999999)
        return v4_sorted[0].gateway

    @property
    def default_ipv6_gateway(self) -> Optional[str]:
        """Convenience accessor for primary IPv6 default gateway address."""
        v6_gws = [g for g in self.gateways if g.family == "IPv6"]
        if not v6_gws:
            return None
        v6_sorted = sorted(v6_gws, key=lambda g: g.metric if g.metric is not None else 999999)
        return v6_sorted[0].gateway

    @property
    def interface_dns_servers(self) -> List[DNSServerInfo]:
        """Verified per-interface DNS nameservers."""
        return [d for d in self.dns_servers if d.scope == "interface"]

    @property
    def system_dns_servers(self) -> List[DNSServerInfo]:
        """System-wide DNS nameservers associated for routing context."""
        return [d for d in self.dns_servers if d.scope == "system"]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["interface_type"] = self.interface_type.value
        return data


@dataclass(frozen=True)
class SubnetCalculationResult:
    """Detailed IPv4 or IPv6 subnet calculation result."""

    cidr: str
    ip_version: int
    network_address: str
    netmask: str
    wildcard_mask: str
    broadcast_address: str
    total_hosts: int
    usable_hosts: int
    first_usable_ip: str
    last_usable_ip: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
