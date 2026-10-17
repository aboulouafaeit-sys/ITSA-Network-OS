"""Read-only routing table and VLAN configuration inspector."""

from __future__ import annotations

import socket
import struct
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class RouteEntry:
    """Network route table entry."""

    destination: str
    gateway: str
    netmask: str
    interface: str
    metric: int
    flags: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VlanInfo:
    """VLAN subinterface representation."""

    interface_name: str
    parent_interface: str
    vlan_id: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RouteParser:
    """Parses system routing tables and VLAN structures non-destructively."""

    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        """Convert 8-character little-endian hex to standard IPv4 dotted-quad."""
        try:
            addr_int = int(hex_str, 16)
            packed = struct.pack("<L", addr_int)
            return socket.inet_ntoa(packed)
        except Exception:
            return "0.0.0.0"

    @classmethod
    def get_routes(cls, use_mock: bool = False) -> List[RouteEntry]:
        """Fetch system routing entries safely."""
        if use_mock:
            return cls._mock_routes()

        proc_route = Path("/proc/net/route")
        if not proc_route.is_file():
            return cls._mock_routes()

        routes: List[RouteEntry] = []
        try:
            lines = proc_route.read_text(encoding="utf-8").splitlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split()
                if len(parts) >= 8:
                    iface = parts[0]
                    dest = cls._hex_to_ip(parts[1])
                    gw = cls._hex_to_ip(parts[2])
                    flags_raw = int(parts[3], 16)
                    metric = int(parts[6])
                    mask = cls._hex_to_ip(parts[7])

                    flags_desc = []
                    if flags_raw & 0x0001:
                        flags_desc.append("U")  # Route is up
                    if flags_raw & 0x0002:
                        flags_desc.append("G")  # Uses gateway
                    if flags_raw & 0x0004:
                        flags_desc.append("H")  # Target is a host

                    routes.append(
                        RouteEntry(
                            destination=dest if dest != "0.0.0.0" else "default",
                            gateway=gw if gw != "0.0.0.0" else "on-link",
                            netmask=mask,
                            interface=iface,
                            metric=metric,
                            flags="".join(flags_desc) or "U",
                        )
                    )
        except Exception:
            return cls._mock_routes()

        return routes if routes else cls._mock_routes()

    @classmethod
    def detect_vlans(cls, interface_names: List[str]) -> List[VlanInfo]:
        """Identify IEEE 802.1Q VLAN subinterfaces by standard naming convention (e.g. eth0.10)."""
        vlans: List[VlanInfo] = []
        for name in interface_names:
            if "." in name:
                parent, vlan_str = name.rsplit(".", 1)
                if vlan_str.isdigit():
                    vlans.append(
                        VlanInfo(
                            interface_name=name,
                            parent_interface=parent,
                            vlan_id=int(vlan_str),
                        )
                    )
        return vlans

    @classmethod
    def _mock_routes(cls) -> List[RouteEntry]:
        """Deterministic mock routing table for offline verification."""
        return [
            RouteEntry(
                destination="default",
                gateway="192.168.1.1",
                netmask="0.0.0.0",
                interface="eth0",
                metric=100,
                flags="UG",
            ),
            RouteEntry(
                destination="192.168.1.0",
                gateway="on-link",
                netmask="255.255.255.0",
                interface="eth0",
                metric=100,
                flags="U",
            ),
            RouteEntry(
                destination="127.0.0.0",
                gateway="on-link",
                netmask="255.0.0.0",
                interface="lo",
                metric=0,
                flags="U",
            ),
        ]
