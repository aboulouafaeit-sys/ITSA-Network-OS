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
    scope: Optional[str] = None
    flags: List[str] = field(default_factory=list)

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
