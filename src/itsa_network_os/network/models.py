"""Data models for networking entities in ITSA Network OS."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
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


class InterfaceConstraintError(RuntimeError):
    """Raised when an interface constraint cannot be enforced or the requested interface does not exist."""
    pass


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


class EvidenceProtocol(str, Enum):
    """Network observation protocols and evidence acquisition sources."""

    MNDP = "MNDP"
    ONVIF = "ONVIF"
    ARP = "ARP"
    MDNS = "mDNS"
    LLDP = "LLDP"
    CDP = "CDP"
    TLS = "TLS"
    DHCP = "DHCP"
    SNMP = "SNMP"
    HTTP = "HTTP"
    RTSP = "RTSP"
    MOCK = "MOCK"
    KERNEL_RTNETLINK = "KERNEL_RTNETLINK"
    SYSTEM_RESOLV_CONF = "SYSTEM_RESOLV_CONF"


@dataclass(frozen=True)
class EvidenceRecord:
    """Attribution metadata for discovered network intelligence and device telemetry.

    Distinguishes verified technical facts (e.g. cryptographic handshakes, direct protocol
    responses) from algorithmic inferences (e.g. MAC OUI vendor lookups, heuristic OS guesses).

    Attributes:
        source_protocol: The protocol or observation source (e.g. "MNDP", "ONVIF", "ARP").
            Accepts EvidenceProtocol enum members or any non-empty string for future protocols.
        timestamp: Observation timestamp in UTC instant, stored and serialized as an ISO 8601 string.
        confidence: Normalized confidence metric bounded between 0.0 and 1.0 inclusive.
        is_verified_fact: True if confirmed by direct protocol/cryptographic proof, False if inferred.
        attribute: Optional target attribute or telemetry field to which the evidence applies.
        details: Optional human-readable or raw evidence payload details.
    """

    source_protocol: str | EvidenceProtocol
    timestamp: str | datetime
    confidence: float
    is_verified_fact: bool
    attribute: Optional[str] = None
    details: Optional[str] = None

    def __post_init__(self) -> None:
        # Validate confidence type
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(
                f"confidence must be a float or int, got {type(self.confidence).__name__}"
            )
        # Validate confidence is finite
        if math.isnan(self.confidence) or math.isinf(self.confidence):
            raise ValueError(
                f"confidence must be a finite number between 0.0 and 1.0, got {self.confidence}"
            )
        # Validate confidence range
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
        object.__setattr__(self, "confidence", float(self.confidence))

        # Validate is_verified_fact is genuinely boolean
        if not isinstance(self.is_verified_fact, bool):
            raise TypeError(
                f"is_verified_fact must be a bool, got {type(self.is_verified_fact).__name__}"
            )

        # Validate and normalize source_protocol
        if isinstance(self.source_protocol, Enum):
            proto_val = str(self.source_protocol.value)
        elif isinstance(self.source_protocol, str):
            proto_val = self.source_protocol.strip()
            if not proto_val:
                raise ValueError("source_protocol cannot be empty or whitespace")
        else:
            raise TypeError(
                f"source_protocol must be a string or Enum, got {type(self.source_protocol).__name__}"
            )
        object.__setattr__(self, "source_protocol", proto_val)

        # Validate and normalize timestamp
        if not isinstance(self.timestamp, (str, datetime)):
            raise TypeError(
                f"timestamp must be an ISO 8601 string or datetime object, got {type(self.timestamp).__name__}"
            )
        if isinstance(self.timestamp, str):
            ts_str = self.timestamp.strip()
            if not ts_str:
                raise ValueError("timestamp cannot be empty")
            try:
                dt = datetime.fromisoformat(ts_str)
            except ValueError as exc:
                raise ValueError(f"Invalid ISO 8601 timestamp: {self.timestamp!r}") from exc
        else:
            dt = self.timestamp

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        object.__setattr__(self, "timestamp", dt.isoformat())

        # Validate optional attribute and details
        if self.attribute is not None and not isinstance(self.attribute, str):
            raise TypeError(
                f"attribute must be a string or None, got {type(self.attribute).__name__}"
            )
        if self.details is not None and not isinstance(self.details, str):
            raise TypeError(
                f"details must be a string or None, got {type(self.details).__name__}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize EvidenceRecord to a JSON-compatible dictionary."""
        return {
            "source_protocol": self.source_protocol,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "is_verified_fact": self.is_verified_fact,
            "attribute": self.attribute,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceRecord:
        """Deserialize EvidenceRecord from a dictionary."""
        return cls(
            source_protocol=data["source_protocol"],
            timestamp=data["timestamp"],
            confidence=float(data["confidence"]),
            is_verified_fact=bool(data["is_verified_fact"]),
            attribute=data.get("attribute"),
            details=data.get("details"),
        )
