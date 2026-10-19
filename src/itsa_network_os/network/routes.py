"""Read-only routing table and VLAN configuration inspector."""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from itsa_network_os.network.models import GatewayInfo


@dataclass(frozen=True)
class RouteEntry:
    """Network route table entry."""

    destination: str
    gateway: str
    netmask: str
    interface: str
    metric: int
    flags: str
    family: str = "IPv4"

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

    @staticmethod
    def _hex_to_ipv6(hex_str: str) -> str:
        """Convert 32-character big-endian hex to standard IPv6 string."""
        try:
            hex_clean = hex_str.strip()
            if len(hex_clean) != 32:
                return "::"
            return str(ipaddress.IPv6Address(bytes.fromhex(hex_clean)))
        except Exception:
            return "::"

    @classmethod
    def parse_proc_route(cls, content: str) -> List[RouteEntry]:
        """Parse Linux /proc/net/route text table safely."""
        routes: List[RouteEntry] = []
        lines = content.splitlines()
        if not lines:
            return routes

        for line in lines[1:]:  # skip header line
            parts = line.strip().split()
            if len(parts) >= 8:
                try:
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
                            family="IPv4",
                        )
                    )
                except Exception:
                    continue
        return routes

    @classmethod
    def parse_proc_ipv6_route(cls, content: str) -> List[RouteEntry]:
        """Parse Linux /proc/net/ipv6_route text table safely."""
        routes: List[RouteEntry] = []
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 10:
                try:
                    dest_hex = parts[0]
                    dest_prefix = int(parts[1], 16)
                    next_hop_hex = parts[4]
                    metric = int(parts[5], 16)
                    flags_raw = int(parts[8], 16)
                    iface = parts[9]

                    # Filter out reject or blackhole routes (RTF_REJECT = 0x00000200)
                    if flags_raw & 0x00000200:
                        continue

                    # Ignore fallback routes with max metric (unreachable)
                    if metric == 0xFFFFFFFF:
                        continue

                    if dest_hex == "0" * 32 and dest_prefix == 0:
                        dest_str = "default"
                    else:
                        dest_addr = cls._hex_to_ipv6(dest_hex)
                        dest_str = f"{dest_addr}/{dest_prefix}"

                    if next_hop_hex == "0" * 32:
                        gw_str = "on-link"
                    else:
                        gw_str = cls._hex_to_ipv6(next_hop_hex)

                    flags_desc = ["U"]
                    if flags_raw & 0x00000002:  # RTF_GATEWAY
                        flags_desc.append("G")

                    routes.append(
                        RouteEntry(
                            destination=dest_str,
                            gateway=gw_str,
                            netmask=f"::/{dest_prefix}",
                            interface=iface,
                            metric=metric,
                            flags="".join(flags_desc),
                            family="IPv6",
                        )
                    )
                except Exception:
                    continue
        return routes

    @classmethod
    def parse_ip_route_json(cls, raw_json: str, family: str = "IPv4") -> List[RouteEntry]:
        """Parse 'ip -j route show' or 'ip -6 -j route show' JSON output safely."""
        try:
            entries = json.loads(raw_json)
            if not isinstance(entries, list):
                return []
        except Exception:
            return []

        routes: List[RouteEntry] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            dst = item.get("dst")
            if not dst:
                continue

            gateway = item.get("gateway")
            dev = item.get("dev", "")
            metric = int(item.get("metric", 0)) if item.get("metric") is not None else 0
            flags_list = item.get("flags", [])
            flags_str = "".join(f.upper() for f in flags_list) or "U"

            routes.append(
                RouteEntry(
                    destination=dst,
                    gateway=gateway if gateway else "on-link",
                    netmask="" if dst == "default" else "",
                    interface=dev,
                    metric=metric,
                    flags=flags_str,
                    family=family,
                )
            )
        return routes

    @classmethod
    def get_routes(cls, use_mock: bool = False, family: Optional[str] = None) -> List[RouteEntry]:
        """Fetch system routing entries safely."""
        if use_mock:
            mock_list = cls._mock_routes()
            if family:
                return [r for r in mock_list if r.family == family]
            return mock_list

        routes: List[RouteEntry] = []

        # IPv4 routes
        if family is None or family == "IPv4":
            proc_route = Path("/proc/net/route")
            if proc_route.is_file():
                try:
                    routes.extend(cls.parse_proc_route(proc_route.read_text(encoding="utf-8")))
                except Exception:
                    pass

        # IPv6 routes
        if family is None or family == "IPv6":
            proc_ipv6 = Path("/proc/net/ipv6_route")
            if proc_ipv6.is_file():
                try:
                    routes.extend(cls.parse_proc_ipv6_route(proc_ipv6.read_text(encoding="utf-8")))
                except Exception:
                    pass

        return routes if routes else cls._mock_routes()

    @classmethod
    def get_default_gateways(cls, use_mock: bool = False) -> List[GatewayInfo]:
        """Fetch all active default IPv4 and IPv6 gateways with interface associations."""
        if use_mock:
            return [
                GatewayInfo(
                    gateway="192.168.1.1",
                    family="IPv4",
                    metric=100,
                    interface="eth0",
                    protocol="dhcp",
                    flags=["UG"],
                ),
                GatewayInfo(
                    gateway="fe80::1",
                    family="IPv6",
                    metric=1024,
                    interface="eth0",
                    protocol="ra",
                    flags=["UG"],
                ),
            ]

        gateways: List[GatewayInfo] = []

        # Method 1: ip -j route show default (IPv4 and IPv6)
        v4_found = False
        try:
            res_v4 = subprocess.run(
                ["ip", "-4", "-j", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.5,
            )
            if res_v4.returncode == 0 and res_v4.stdout.strip():
                entries = json.loads(res_v4.stdout)
                if isinstance(entries, list):
                    for item in entries:
                        if isinstance(item, dict) and item.get("gateway") and item.get("dev"):
                            gateways.append(
                                GatewayInfo(
                                    gateway=str(item["gateway"]),
                                    family="IPv4",
                                    metric=int(item["metric"]) if item.get("metric") is not None else None,
                                    interface=str(item["dev"]),
                                    protocol=item.get("protocol"),
                                    flags=item.get("flags", []) if isinstance(item.get("flags"), list) else [],
                                )
                            )
                            v4_found = True
        except Exception:
            pass

        v6_found = False
        try:
            res_v6 = subprocess.run(
                ["ip", "-6", "-j", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=False,
                timeout=1.5,
            )
            if res_v6.returncode == 0 and res_v6.stdout.strip():
                entries = json.loads(res_v6.stdout)
                if isinstance(entries, list):
                    for item in entries:
                        if isinstance(item, dict) and item.get("gateway") and item.get("dev"):
                            gateways.append(
                                GatewayInfo(
                                    gateway=str(item["gateway"]),
                                    family="IPv6",
                                    metric=int(item["metric"]) if item.get("metric") is not None else None,
                                    interface=str(item["dev"]),
                                    protocol=item.get("protocol"),
                                    flags=item.get("flags", []) if isinstance(item.get("flags"), list) else [],
                                )
                            )
                            v6_found = True
        except Exception:
            pass

        # Method 2: Kernel proc fallback if not discovered via ip command
        if not v4_found:
            proc_route = Path("/proc/net/route")
            if proc_route.is_file():
                try:
                    v4_routes = cls.parse_proc_route(proc_route.read_text(encoding="utf-8"))
                    for r in v4_routes:
                        if r.destination == "default" and r.gateway not in ("on-link", "0.0.0.0", ""):
                            gateways.append(
                                GatewayInfo(
                                    gateway=r.gateway,
                                    family="IPv4",
                                    metric=r.metric,
                                    interface=r.interface,
                                    flags=[r.flags],
                                )
                            )
                except Exception:
                    pass

        if not v6_found:
            proc_ipv6 = Path("/proc/net/ipv6_route")
            if proc_ipv6.is_file():
                try:
                    v6_routes = cls.parse_proc_ipv6_route(proc_ipv6.read_text(encoding="utf-8"))
                    for r in v6_routes:
                        if r.destination == "default" and r.gateway not in ("on-link", "::", ""):
                            gateways.append(
                                GatewayInfo(
                                    gateway=r.gateway,
                                    family="IPv6",
                                    metric=r.metric,
                                    interface=r.interface,
                                    flags=[r.flags],
                                )
                            )
                except Exception:
                    pass

        return gateways

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
                family="IPv4",
            ),
            RouteEntry(
                destination="default",
                gateway="fe80::1",
                netmask="::/0",
                interface="eth0",
                metric=1024,
                flags="UG",
                family="IPv6",
            ),
            RouteEntry(
                destination="192.168.1.0",
                gateway="on-link",
                netmask="255.255.255.0",
                interface="eth0",
                metric=100,
                flags="U",
                family="IPv4",
            ),
            RouteEntry(
                destination="127.0.0.0",
                gateway="on-link",
                netmask="255.0.0.0",
                interface="lo",
                metric=0,
                flags="U",
                family="IPv4",
            ),
        ]
