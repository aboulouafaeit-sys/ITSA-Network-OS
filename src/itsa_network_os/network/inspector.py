"""Read-only network interface inspector with safe mock provider default."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Protocol

from itsa_network_os.network.models import (
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)


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
            ),
            NetworkInterface(
                name="wlan0",
                mac_address="3c:52:82:1a:2b:3c",
                state=InterfaceState.DOWN,
                interface_type=InterfaceType.WIRELESS,
                mtu=1500,
                addresses=[],
            ),
        ]


class HostNetworkProvider:
    """Safe, strictly read-only interface inspector reading from Linux /sys/class/net."""

    def get_interfaces(self) -> List[NetworkInterface]:
        interfaces: List[NetworkInterface] = []
        sys_net = Path("/sys/class/net")

        if not sys_net.is_dir():
            # Not on Linux or /sys is unavailable; fallback to mock data safely
            return MockNetworkProvider().get_interfaces()

        try:
            for iface_dir in sys_net.iterdir():
                if not iface_dir.is_dir():
                    continue

                name = iface_dir.name
                mac = "00:00:00:00:00:00"
                state = InterfaceState.UNKNOWN
                if_type = InterfaceType.ETHERNET
                mtu = 1500

                # Read operstate
                operstate_file = iface_dir / "operstate"
                if operstate_file.is_file():
                    content = operstate_file.read_text(encoding="utf-8").strip().lower()
                    if content == "up":
                        state = InterfaceState.UP
                    elif content == "down":
                        state = InterfaceState.DOWN

                # Read MAC address
                address_file = iface_dir / "address"
                if address_file.is_file():
                    mac = address_file.read_text(encoding="utf-8").strip()

                # Read MTU
                mtu_file = iface_dir / "mtu"
                if mtu_file.is_file():
                    try:
                        mtu = int(mtu_file.read_text(encoding="utf-8").strip())
                    except ValueError:
                        mtu = 1500

                if name == "lo":
                    if_type = InterfaceType.LOOPBACK
                elif name.startswith("wl") or "wifi" in name:
                    if_type = InterfaceType.WIRELESS
                elif name.startswith(("virbr", "docker", "br-")):
                    if_type = InterfaceType.VIRTUAL

                interfaces.append(
                    NetworkInterface(
                        name=name,
                        mac_address=mac,
                        state=state,
                        interface_type=if_type,
                        mtu=mtu,
                        addresses=[],
                    )
                )
        except Exception:
            return MockNetworkProvider().get_interfaces()

        return interfaces if interfaces else MockNetworkProvider().get_interfaces()


class NetworkInspector:
    """High-level read-only interface query orchestrator."""

    def __init__(self, use_mock: bool = True) -> None:
        self.provider: NetworkProvider = MockNetworkProvider() if use_mock else HostNetworkProvider()

    def list_interfaces(self) -> List[NetworkInterface]:
        """Fetch list of network interfaces safely."""
        return self.provider.get_interfaces()
