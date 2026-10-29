"""Read-only network interface inspector with safe mock provider default."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol

from itsa_network_os.network.dns import DNSDiagnostics
from itsa_network_os.network.models import (
    DNSServerInfo,
    GatewayInfo,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)
from itsa_network_os.network.routes import RouteParser

if TYPE_CHECKING:
    from itsa_network_os.network.assets import AssetGraph, NetworkAsset


class NetworkProvider(Protocol):
    """Protocol for fetching interface configurations."""

    def get_interfaces(self) -> List[NetworkInterface]:
        """Fetch list of network interfaces."""
        ...


class MockNetworkProvider:
    """Provides realistic, offline-safe mock interfaces for isolated testing and development."""

    def get_interfaces(self) -> List[NetworkInterface]:
        return [
            NetworkInterface(
                name="lo",
                mac_address="00:00:00:00:00:00",
                state=InterfaceState.UP,
                interface_type=InterfaceType.LOOPBACK,
                mtu=65536,
                addresses=[
                    IPAddressInfo(address="127.0.0.1", prefix_length=8, family="IPv4", netmask="255.0.0.0"),
                    IPAddressInfo(address="::1", prefix_length=128, family="IPv6", netmask="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
                ],
                gateways=[],
                dns_servers=[],
            ),
            NetworkInterface(
                name="eth0",
                mac_address="02:42:0a:11:00:02",
                state=InterfaceState.UP,
                interface_type=InterfaceType.ETHERNET,
                mtu=1500,
                addresses=[
                    IPAddressInfo(address="192.168.1.105", prefix_length=24, family="IPv4", netmask="255.255.255.0"),
                    IPAddressInfo(address="fe80::42:aff:fe11:2", prefix_length=64, family="IPv6", netmask="ffff:ffff:ffff:ffff::"),
                ],
                gateways=[
                    GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0", protocol="dhcp", flags=["UG"]),
                    GatewayInfo(gateway="fe80::1", family="IPv6", metric=1024, interface="eth0", protocol="ra", flags=["UG"]),
                ],
                dns_servers=[
                    DNSServerInfo(address="192.168.1.1", scope="interface", interface="eth0", provenance="mock"),
                ],
            ),
            NetworkInterface(
                name="wlan0",
                mac_address="3c:52:82:1a:2b:3c",
                state=InterfaceState.DOWN,
                interface_type=InterfaceType.WIRELESS,
                mtu=1500,
                addresses=[],
                gateways=[],
                dns_servers=[],
            ),
        ]


class HostNetworkProvider:
    """Safe, strictly read-only interface and address inspector reading from Linux kernel APIs."""

    @classmethod
    def normalize_kernel_scope(cls, raw_scope: Optional[str], addr_str: Optional[str] = None) -> str:
        """Normalize Linux kernel RT_SCOPE metadata (e.g. 'global', 'link', 'host', 'site').
        
        NOTE: Kernel 'scope global' denotes non-link-local routing scope within the Linux
        network stack; it does NOT imply that the address is globally routable on the public Internet.
        """
        if raw_scope:
            raw_lower = str(raw_scope).lower().strip()
            if raw_lower in ("global", "universe"):
                return "global"
            if raw_lower in ("link", "link-local"):
                return "link"
            if raw_lower in ("host", "loopback"):
                return "host"
            if raw_lower in ("site", "site-local"):
                return "site"
            return raw_lower

        if addr_str:
            try:
                ip_obj = ipaddress.ip_address(addr_str)
                if ip_obj.is_loopback:
                    return "host"
                if ip_obj.is_link_local:
                    return "link"
                return "global"
            except ValueError:
                pass
        return "unknown"

    @classmethod
    def classify_address(cls, addr_str: str) -> str:
        """Classify IP address according to RFC architectural standards using standard library ipaddress.
        
        Distinguishes:
            - 'loopback' for 127.0.0.0/8 and ::1
            - 'link-local' for 169.254.0.0/16 and fe80::/10
            - 'private' for RFC 1918 IPv4 networks (10/8, 172.16/12, 192.168/16)
            - 'unique-local' for RFC 4193 IPv6 ULA (fc00::/7)
            - 'global-unicast' for public globally-routable IPv4 and IPv6 unicast addresses
            - 'site-local' for deprecated IPv6 site-local (fec0::/10)
            - 'multicast' for IPv4 224.0.0.0/4 and IPv6 ff00::/8
            - 'unspecified' for 0.0.0.0 and ::
            - 'reserved' for other IETF reserved blocks
            - 'unknown' for malformed address strings
        """
        try:
            ip_obj = ipaddress.ip_address(addr_str)
            if ip_obj.is_loopback:
                return "loopback"
            if ip_obj.is_link_local:
                return "link-local"
            if ip_obj.is_multicast:
                return "multicast"
            if ip_obj.is_unspecified:
                return "unspecified"

            if ip_obj.version == 4:
                if ip_obj.is_private:
                    return "private"
                if getattr(ip_obj, "is_global", False):
                    return "global-unicast"
                return "reserved"
            else:  # IPv6
                # Check RFC 4193 Unique Local Address fc00::/7 (covers fc00:: through fdff:...)
                if (ip_obj.packed[0] & 0xFE) == 0xFC:
                    return "unique-local"
                if getattr(ip_obj, "is_site_local", False):
                    return "site-local"
                if getattr(ip_obj, "is_global", False):
                    return "global-unicast"
                # Documentation prefix 2001:db8::/32 is global unicast format in RFC 4291
                if ip_obj.exploded.startswith("2001:0db8:"):
                    return "global-unicast"
                return "reserved"
        except ValueError:
            return "unknown"

    @classmethod
    def classify_ip_scope(cls, addr_str: str, kernel_scope: Optional[str] = None) -> str:
        """Backward-compatible scope helper.
        
        NOTE: Prefer using 'normalize_kernel_scope' for Linux kernel interface metadata
        and 'classify_address' for RFC architectural classification.
        """
        return cls.normalize_kernel_scope(kernel_scope, addr_str)

    @classmethod
    def calculate_netmask(cls, family: str, prefix_len: int) -> str:
        """Calculate netmask string from prefix length using standard library ipaddress."""
        try:
            if family == "IPv4" and 0 <= prefix_len <= 32:
                return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)
            elif family == "IPv6" and 0 <= prefix_len <= 128:
                return str(ipaddress.IPv6Network(f"::/{prefix_len}").netmask)
        except Exception:
            pass
        return ""

    @classmethod
    def classify_interface_type(cls, name: str, link_type: str = "") -> InterfaceType:
        """Classify interface into InterfaceType enum based on name and link_type."""
        link_lower = str(link_type).lower().strip()
        if link_lower == "loopback" or name == "lo":
            return InterfaceType.LOOPBACK
        if name.startswith("wl") or "wifi" in name or link_lower in ("wlan", "ieee80211"):
            return InterfaceType.WIRELESS
        if (
            name.startswith(("virbr", "docker", "br-", "lxcbr", "veth", "vnet", "bridge"))
            or (name.startswith("br") and len(name) > 2 and name[2].isdigit())
            or link_lower in ("bridge", "veth")
        ):
            return InterfaceType.VIRTUAL
        if name.startswith(("eth", "en", "em")) or link_lower in ("ether", "ethernet"):
            return InterfaceType.ETHERNET
        return InterfaceType.UNKNOWN

    @classmethod
    def classify_interface_state(cls, raw_state: Optional[str]) -> InterfaceState:
        """Classify operational state string into InterfaceState enum."""
        if not raw_state:
            return InterfaceState.UNKNOWN
        state_upper = str(raw_state).strip().upper()
        if state_upper == "UP":
            return InterfaceState.UP
        if state_upper == "DOWN":
            return InterfaceState.DOWN
        return InterfaceState.UNKNOWN

    @classmethod
    def _parse_ip_addr_json(cls, raw_json: str) -> List[NetworkInterface]:
        """Parse 'ip -j addr' JSON output safely into typed NetworkInterface models."""
        try:
            entries = json.loads(raw_json)
            if not isinstance(entries, list):
                return []
        except Exception:
            return []

        interfaces: List[NetworkInterface] = []
        for item in entries:
            if not isinstance(item, dict):
                continue

            name = item.get("ifname")
            if not name:
                continue

            mac = item.get("address") or "00:00:00:00:00:00"
            try:
                mtu = int(item.get("mtu", 1500))
            except (ValueError, TypeError):
                mtu = 1500

            state = cls.classify_interface_state(item.get("operstate"))
            if_type = cls.classify_interface_type(name, item.get("link_type", ""))

            addresses: List[IPAddressInfo] = []
            raw_addr_info = item.get("addr_info", [])
            if isinstance(raw_addr_info, list):
                for a in raw_addr_info:
                    if not isinstance(a, dict):
                        continue
                    local_ip = a.get("local")
                    if not local_ip:
                        continue

                    raw_fam = str(a.get("family", "")).lower()
                    family = "IPv6" if raw_fam == "inet6" else "IPv4" if raw_fam == "inet" else "UNKNOWN"

                    prefix_len = int(a.get("prefixlen", 0))
                    netmask = cls.calculate_netmask(family, prefix_len)

                    # Broadcast handling
                    broadcast = a.get("broadcast") if family == "IPv4" else None

                    # Linux kernel scope vs. RFC architectural classification
                    kernel_scope = cls.normalize_kernel_scope(a.get("scope"), local_ip)
                    classification = cls.classify_address(local_ip)

                    # Extract boolean flags
                    flag_keys = [
                        "dynamic",
                        "mngtmpaddr",
                        "noprefixroute",
                        "temporary",
                        "secondary",
                        "deprecated",
                        "tentative",
                        "homeaddress",
                    ]
                    flags = [k for k in flag_keys if a.get(k) is True]

                    addresses.append(
                        IPAddressInfo(
                            address=local_ip,
                            prefix_length=prefix_len,
                            family=family,
                            netmask=netmask,
                            broadcast=broadcast,
                            scope=kernel_scope,
                            classification=classification,
                            flags=flags,
                        )
                    )

            interfaces.append(
                NetworkInterface(
                    name=name,
                    mac_address=mac,
                    state=state,
                    interface_type=if_type,
                    mtu=mtu,
                    addresses=addresses,
                )
            )

        return interfaces

    @classmethod
    def _parse_if_inet6(cls, content: str) -> Dict[str, List[IPAddressInfo]]:
        """Parse Linux /proc/net/if_inet6 contents safely."""
        result: Dict[str, List[IPAddressInfo]] = {}
        scope_map = {
            0x00: "global",
            0x10: "host",
            0x20: "link-local",
            0x40: "site-local",
            0x80: "compatv4",
        }

        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) < 6:
                continue

            raw_ip, _idx_hex, prefix_hex, scope_hex, flags_hex, ifname = parts[:6]
            if len(raw_ip) != 32:
                continue

            try:
                grouped = ":".join(raw_ip[i : i + 4] for i in range(0, 32, 4))
                addr = str(ipaddress.IPv6Address(grouped))
                prefix_len = int(prefix_hex, 16)
                scope_code = int(scope_hex, 16)
                raw_scope = scope_map.get(scope_code, "unknown")
                kernel_scope = cls.normalize_kernel_scope(raw_scope, addr)
                classification = cls.classify_address(addr)
                netmask = cls.calculate_netmask("IPv6", prefix_len)
                flags = [f"0x{flags_hex}"]

                info = IPAddressInfo(
                    address=addr,
                    prefix_length=prefix_len,
                    family="IPv6",
                    netmask=netmask,
                    broadcast=None,
                    scope=kernel_scope,
                    classification=classification,
                    flags=flags,
                )
                result.setdefault(ifname, []).append(info)
            except Exception:
                continue

        return result

    @classmethod
    def _query_ipv4_ioctl(cls, ifname: str) -> List[IPAddressInfo]:
        """Query interface IPv4 address, netmask, and broadcast using ioctl (Linux SIOCGIF*)."""
        import fcntl
        import socket
        import struct

        SIOCGIFADDR = 0x8915
        SIOCGIFNETMASK = 0x891B
        SIOCGIFBRDADDR = 0x8919

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ifreq = struct.pack("256s", ifname.encode("utf-8")[:15])

            addr = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)[20:24])
            netmask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)[20:24])
            try:
                bcast_raw = fcntl.ioctl(sock.fileno(), SIOCGIFBRDADDR, ifreq)[20:24]
                broadcast = socket.inet_ntoa(bcast_raw)
            except Exception:
                broadcast = None

            prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            kernel_scope = "host" if ipaddress.IPv4Address(addr).is_loopback else "global"
            classification = cls.classify_address(addr)

            return [
                IPAddressInfo(
                    address=addr,
                    prefix_length=prefix_len,
                    family="IPv4",
                    netmask=netmask,
                    broadcast=broadcast,
                    scope=kernel_scope,
                    classification=classification,
                    flags=[],
                )
            ]
        except Exception:
            return []
        finally:
            if sock:
                sock.close()

    @classmethod
    def associate_gateways_and_dns(
        cls,
        interfaces: List[NetworkInterface],
        gateways: List[GatewayInfo],
        interface_dns: Dict[str, List[DNSServerInfo]],
        system_dns: List[DNSServerInfo],
    ) -> List[NetworkInterface]:
        """Associate discovered default gateways and DNS servers with matching interfaces.

        Semantic Rules:
            - Gateways: Associated strictly with the interface named by the default route.
            - Case B (Interface-specific DNS): Reliable OS metadata (NetworkManager / systemd-resolved)
              attaches DNS servers to the interface with scope='interface'.
            - Case A (System-wide DNS): If an interface holds a default gateway and no per-interface
              DNS exists, system-wide DNS (/etc/resolv.conf) is associated with scope='system' and
              interface=None to honestly reflect that the resolver is global.
            - Case C (Unknown/Unavailable): Non-routed interfaces (e.g. 'lo') or interfaces with
              no reliable DNS association receive an empty dns_servers list.
        """
        gateways_by_iface: Dict[str, List[GatewayInfo]] = {}
        for gw in gateways:
            if gw.interface:
                gateways_by_iface.setdefault(gw.interface, []).append(gw)

        updated_interfaces: List[NetworkInterface] = []
        for iface in interfaces:
            iface_gws = gateways_by_iface.get(iface.name, [])

            # Case B: Interface-specific DNS from reliable OS metadata
            if iface.name in interface_dns and interface_dns[iface.name]:
                iface_dns = interface_dns[iface.name]
            # Case A: System-wide DNS attached to default gateway interface(s)
            elif iface_gws and system_dns:
                iface_dns = [
                    DNSServerInfo(
                        address=s.address,
                        scope="system",
                        interface=None,
                        provenance=s.provenance,
                    )
                    for s in system_dns
                ]
            else:
                # Case C: Not associated
                iface_dns = []

            updated_interfaces.append(
                NetworkInterface(
                    name=iface.name,
                    mac_address=iface.mac_address,
                    state=iface.state,
                    interface_type=iface.interface_type,
                    mtu=iface.mtu,
                    addresses=iface.addresses,
                    gateways=iface_gws,
                    dns_servers=iface_dns,
                )
            )

        return updated_interfaces

    def get_interfaces(self) -> List[NetworkInterface]:
        """Fetch list of real host network interfaces and addresses safely."""
        interfaces: List[NetworkInterface] = []

        # Method 1: ip -j addr (high-fidelity JSON)
        try:
            res = subprocess.run(
                ["ip", "-j", "addr"],
                capture_output=True,
                text=True,
                check=False,
                timeout=2.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                interfaces = self._parse_ip_addr_json(res.stdout)
        except Exception:
            pass

        # Method 2: Kernel filesystem (/sys/class/net + /proc/net/if_inet6 + ioctl)
        if not interfaces:
            interfaces = self._discover_from_proc_and_sys()

        if not interfaces:
            return []

        # Discover default gateways and DNS resolvers safely
        try:
            gateways = RouteParser.get_default_gateways(use_mock=False)
        except Exception:
            gateways = []

        try:
            interface_dns = DNSDiagnostics.get_interface_dns_servers(use_mock=False)
        except Exception:
            interface_dns = {}

        try:
            system_dns = DNSDiagnostics.get_system_dns_servers(use_mock=False)
        except Exception:
            system_dns = []

        return self.associate_gateways_and_dns(interfaces, gateways, interface_dns, system_dns)

    def _discover_from_proc_and_sys(self) -> List[NetworkInterface]:
        """Discover interfaces and addresses from /sys/class/net and /proc/net/if_inet6."""
        interfaces: List[NetworkInterface] = []
        sys_net = Path("/sys/class/net")

        if not sys_net.is_dir():
            return []

        # Read IPv6 addresses from /proc/net/if_inet6
        inet6_map: Dict[str, List[IPAddressInfo]] = {}
        proc_inet6 = Path("/proc/net/if_inet6")
        if proc_inet6.is_file():
            try:
                inet6_map = self._parse_if_inet6(proc_inet6.read_text(encoding="utf-8"))
            except Exception:
                pass

        try:
            for iface_dir in sys_net.iterdir():
                if not iface_dir.is_dir():
                    continue

                name = iface_dir.name
                mac = "00:00:00:00:00:00"
                mtu = 1500
                state = InterfaceState.UNKNOWN
                operstate_file = iface_dir / "operstate"
                if operstate_file.is_file():
                    try:
                        content = operstate_file.read_text(encoding="utf-8").strip()
                        state = self.classify_interface_state(content)
                    except Exception:
                        pass

                address_file = iface_dir / "address"
                if address_file.is_file():
                    try:
                        mac = address_file.read_text(encoding="utf-8").strip() or mac
                    except Exception:
                        pass

                mtu_file = iface_dir / "mtu"
                if mtu_file.is_file():
                    try:
                        mtu = int(mtu_file.read_text(encoding="utf-8").strip())
                    except Exception:
                        pass

                if_type = self.classify_interface_type(name)

                addresses: List[IPAddressInfo] = []
                # IPv4 addresses via ioctl
                addresses.extend(self._query_ipv4_ioctl(name))
                # IPv6 addresses via /proc/net/if_inet6
                if name in inet6_map:
                    addresses.extend(inet6_map[name])

                interfaces.append(
                    NetworkInterface(
                        name=name,
                        mac_address=mac,
                        state=state,
                        interface_type=if_type,
                        mtu=mtu,
                        addresses=addresses,
                    )
                )
        except Exception:
            return []

        return interfaces


class NetworkInspector:
    """High-level read-only interface query orchestrator."""

    def __init__(self, use_mock: bool = True) -> None:
        self.use_mock = use_mock
        self.provider: NetworkProvider = MockNetworkProvider() if use_mock else HostNetworkProvider()

    def list_interfaces(self) -> List[NetworkInterface]:
        """Fetch list of network interfaces safely."""
        return self.provider.get_interfaces()

    def get_system_dns(self) -> List[DNSServerInfo]:
        """Fetch host system-wide DNS servers safely."""
        return DNSDiagnostics.get_system_dns_servers(use_mock=self.use_mock)

    def get_default_gateways(self) -> List[GatewayInfo]:
        """Fetch default gateways safely."""
        return RouteParser.get_default_gateways(use_mock=self.use_mock)

    def get_host_asset(self, host_system_name: str = "localhost", host_uuid: Optional[str] = None) -> NetworkAsset:
        """Translate inspected interfaces, gateways, and DNS resolvers into a unified NetworkAsset."""
        from itsa_network_os.network.assets import from_host_interfaces

        interfaces = self.list_interfaces()
        gateways = self.get_default_gateways()
        dns_servers = self.get_system_dns()
        return from_host_interfaces(
            interfaces=interfaces,
            host_system_name=host_system_name,
            host_uuid=host_uuid,
            gateways=gateways,
            dns_servers=dns_servers,
        )

    def get_asset_graph(
        self,
        host_system_name: str = "localhost",
        host_uuid: Optional[str] = None,
        include_configured_services: bool = True,
    ) -> AssetGraph:
        """Translate inspected network state into an AssetGraph with explicit configured relationships."""
        from itsa_network_os.network.assets import build_discovery_asset_graph

        interfaces = self.list_interfaces()
        gateways = self.get_default_gateways()
        dns_servers = self.get_system_dns()
        return build_discovery_asset_graph(
            interfaces=interfaces,
            gateways=gateways,
            dns_servers=dns_servers,
            host_system_name=host_system_name,
            host_uuid=host_uuid,
            include_configured_services=include_configured_services,
        )
