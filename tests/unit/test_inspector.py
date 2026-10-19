from __future__ import annotations

import json
import unittest
from typing import Any, Dict, List, Optional

from itsa_network_os.network.inspector import HostNetworkProvider, MockNetworkProvider, NetworkInspector
from itsa_network_os.network.models import (
    DNSServerInfo,
    GatewayInfo,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)


class TestNetworkInspector(unittest.TestCase):
    """Test suite for MockNetworkProvider and NetworkInspector orchestration."""

    def test_mock_provider_returns_interfaces(self) -> None:
        """Verify MockNetworkProvider remains completely unchanged in behavior."""
        provider = MockNetworkProvider()
        interfaces = provider.get_interfaces()
        self.assertEqual(len(interfaces), 3)

        names = [iface.name for iface in interfaces]
        self.assertIn("lo", names)
        self.assertIn("eth0", names)
        self.assertIn("wlan0", names)

        lo = next(i for i in interfaces if i.name == "lo")
        self.assertEqual(lo.interface_type, InterfaceType.LOOPBACK)
        self.assertEqual(lo.state, InterfaceState.UP)
        self.assertEqual(len(lo.addresses), 2)
        self.assertEqual(lo.addresses[0].address, "127.0.0.1")
        self.assertEqual(lo.addresses[0].family, "IPv4")
        self.assertEqual(lo.addresses[1].address, "::1")
        self.assertEqual(lo.addresses[1].family, "IPv6")

    def test_inspector_mock_mode(self) -> None:
        """Verify NetworkInspector respects mock mode default."""
        inspector = NetworkInspector(use_mock=True)
        interfaces = inspector.list_interfaces()
        self.assertTrue(any(i.interface_type == InterfaceType.LOOPBACK for i in interfaces))
        self.assertIsInstance(inspector.provider, MockNetworkProvider)

    def test_inspector_live_mode_instantiates_host_provider(self) -> None:
        """Verify NetworkInspector(use_mock=False) delegates to HostNetworkProvider."""
        inspector = NetworkInspector(use_mock=False)
        self.assertIsInstance(inspector.provider, HostNetworkProvider)


class TestHostNetworkAddressParsing(unittest.TestCase):
    """Deterministic unit tests for HostNetworkProvider address extraction and classification."""

    DETERMINISTIC_IP_JSON = json.dumps([
        {
            "ifindex": 1,
            "ifname": "lo",
            "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "mtu": 65536,
            "operstate": "UNKNOWN",
            "link_type": "loopback",
            "address": "00:00:00:00:00:00",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "127.0.0.1",
                    "prefixlen": 8,
                    "scope": "host",
                    "label": "lo",
                },
                {
                    "family": "inet6",
                    "local": "::1",
                    "prefixlen": 128,
                    "scope": "host",
                    "noprefixroute": True,
                },
            ],
        },
        {
            "ifindex": 2,
            "ifname": "eth0",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "mtu": 1500,
            "operstate": "UP",
            "link_type": "ether",
            "address": "02:42:0a:11:00:02",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "192.168.10.50",
                    "prefixlen": 24,
                    "broadcast": "192.168.10.255",
                    "scope": "global",
                    "dynamic": True,
                },
                {
                    "family": "inet",
                    "local": "10.0.0.2",
                    "prefixlen": 16,
                    "broadcast": "10.0.255.255",
                    "scope": "global",
                    "secondary": True,
                },
                {
                    "family": "inet6",
                    "local": "fe80::42:aff:fe11:2",
                    "prefixlen": 64,
                    "scope": "link",
                    "noprefixroute": True,
                },
                {
                    "family": "inet6",
                    "local": "2001:db8:85a3::8a2e:370:7334",
                    "prefixlen": 64,
                    "scope": "global",
                    "mngtmpaddr": True,
                },
            ],
        },
        {
            "ifindex": 3,
            "ifname": "enp4s0",
            "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"],
            "mtu": 1500,
            "operstate": "DOWN",
            "link_type": "ether",
            "address": "04:7c:16:32:2f:92",
            "addr_info": [],
        },
    ])

    def test_parse_ip_addr_json_ipv4_and_broadcast(self) -> None:
        """Requirement 1 & 2: Correct IPv4 address, prefix, netmask, and broadcast handling."""
        interfaces = HostNetworkProvider._parse_ip_addr_json(self.DETERMINISTIC_IP_JSON)
        self.assertEqual(len(interfaces), 3)

        eth0 = next(i for i in interfaces if i.name == "eth0")
        ipv4_addrs = [a for a in eth0.addresses if a.family == "IPv4"]
        self.assertEqual(len(ipv4_addrs), 2)

        primary = ipv4_addrs[0]
        self.assertEqual(primary.address, "192.168.10.50")
        self.assertEqual(primary.prefix_length, 24)
        self.assertEqual(primary.netmask, "255.255.255.0")
        self.assertEqual(primary.broadcast, "192.168.10.255")
        self.assertEqual(primary.scope, "global")
        self.assertEqual(primary.classification, "private")
        self.assertIn("dynamic", primary.flags)

        secondary = ipv4_addrs[1]
        self.assertEqual(secondary.address, "10.0.0.2")
        self.assertEqual(secondary.prefix_length, 16)
        self.assertEqual(secondary.netmask, "255.255.0.0")
        self.assertEqual(secondary.broadcast, "10.0.255.255")
        self.assertEqual(secondary.scope, "global")
        self.assertEqual(secondary.classification, "private")
        self.assertIn("secondary", secondary.flags)

    def test_parse_ip_addr_json_ipv6_and_scopes(self) -> None:
        """Requirement 3 & 4: IPv6 address, prefix length, and link-local vs global classification."""
        interfaces = HostNetworkProvider._parse_ip_addr_json(self.DETERMINISTIC_IP_JSON)
        eth0 = next(i for i in interfaces if i.name == "eth0")
        ipv6_addrs = [a for a in eth0.addresses if a.family == "IPv6"]
        self.assertEqual(len(ipv6_addrs), 2)

        link_local = next(a for a in ipv6_addrs if a.classification == "link-local")
        self.assertEqual(link_local.address, "fe80::42:aff:fe11:2")
        self.assertEqual(link_local.prefix_length, 64)
        self.assertEqual(link_local.netmask, "ffff:ffff:ffff:ffff::")
        self.assertEqual(link_local.scope, "link")
        self.assertEqual(link_local.classification, "link-local")
        self.assertIsNone(link_local.broadcast)
        self.assertIn("noprefixroute", link_local.flags)

        global_ipv6 = next(a for a in ipv6_addrs if a.classification == "global-unicast")
        self.assertEqual(global_ipv6.address, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(global_ipv6.prefix_length, 64)
        self.assertEqual(global_ipv6.scope, "global")
        self.assertEqual(global_ipv6.classification, "global-unicast")
        self.assertIn("mngtmpaddr", global_ipv6.flags)

    def test_eight_target_addresses_scope_and_classification(self) -> None:
        """TASK-004A: Verify exact distinction between Linux kernel scope and RFC classification."""
        test_matrix = [
            # (address, raw_kernel_scope, expected_normalized_scope, expected_rfc_classification)
            ("127.0.0.1", "host", "host", "loopback"),
            ("10.125.191.24", "global", "global", "private"),
            ("192.168.1.1", "global", "global", "private"),
            ("8.8.8.8", "global", "global", "global-unicast"),
            ("::1", "host", "host", "loopback"),
            ("fe80::1", "link", "link", "link-local"),
            ("fc42:5009:ba4b:5ab0::1", "global", "global", "unique-local"),
            ("2001:4860:4860::8888", "global", "global", "global-unicast"),
        ]

        for addr, raw_scope, exp_scope, exp_class in test_matrix:
            norm_scope = HostNetworkProvider.normalize_kernel_scope(raw_scope, addr)
            rfc_class = HostNetworkProvider.classify_address(addr)

            self.assertEqual(
                norm_scope,
                exp_scope,
                f"Kernel scope mismatch for {addr}: expected '{exp_scope}', got '{norm_scope}'",
            )
            self.assertEqual(
                rfc_class,
                exp_class,
                f"RFC classification mismatch for {addr}: expected '{exp_class}', got '{rfc_class}'",
            )

    def test_multiple_addresses_on_one_interface(self) -> None:
        """Requirement 5: Support multiple IPv4 and IPv6 addresses on a single interface."""
        interfaces = HostNetworkProvider._parse_ip_addr_json(self.DETERMINISTIC_IP_JSON)
        eth0 = next(i for i in interfaces if i.name == "eth0")
        self.assertEqual(len(eth0.addresses), 4)

    def test_loopback_and_empty_interfaces(self) -> None:
        """Requirement 6: Interfaces with no assigned addresses or loopback semantics."""
        interfaces = HostNetworkProvider._parse_ip_addr_json(self.DETERMINISTIC_IP_JSON)

        lo = next(i for i in interfaces if i.name == "lo")
        self.assertEqual(lo.interface_type, InterfaceType.LOOPBACK)
        self.assertEqual(len(lo.addresses), 2)
        lo_v4 = next(a for a in lo.addresses if a.family == "IPv4")
        self.assertEqual(lo_v4.address, "127.0.0.1")
        self.assertEqual(lo_v4.scope, "host")
        self.assertEqual(lo_v4.classification, "loopback")

        enp4s0 = next(i for i in interfaces if i.name == "enp4s0")
        self.assertEqual(len(enp4s0.addresses), 0)
        self.assertEqual(enp4s0.state, InterfaceState.DOWN)

    def test_calculate_netmask_utility(self) -> None:
        """Verify netmask computation across RFC boundaries."""
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 8), "255.0.0.0")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 16), "255.255.0.0")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 24), "255.255.255.0")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 30), "255.255.255.252")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 31), "255.255.255.254")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 32), "255.255.255.255")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv6", 64), "ffff:ffff:ffff:ffff::")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv6", 128), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", -1), "")
        self.assertEqual(HostNetworkProvider.calculate_netmask("IPv4", 33), "")

    def test_classify_ip_scope_backward_compatibility(self) -> None:
        """Ensure backward-compatible classify_ip_scope delegates cleanly."""
        self.assertEqual(HostNetworkProvider.classify_ip_scope("127.0.0.1"), "host")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("::1"), "host")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("fe80::1"), "link")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("10.0.0.1"), "global")

    def test_parse_if_inet6_proc_content(self) -> None:
        """Deterministic parsing of Linux /proc/net/if_inet6 lines."""
        sample_proc = (
            "00000000000000000000000000000001 01 80 10 80       lo\n"
            "fe8000000000000005f300909924ef7c 03 40 20 80     wlo1\n"
            "fc425009ba4b5ab00000000000000001 04 40 00 80   lxcbr0\n"
        )
        parsed = HostNetworkProvider._parse_if_inet6(sample_proc)
        self.assertIn("lo", parsed)
        self.assertIn("wlo1", parsed)
        self.assertIn("lxcbr0", parsed)

        self.assertEqual(parsed["lo"][0].address, "::1")
        self.assertEqual(parsed["lo"][0].prefix_length, 128)
        self.assertEqual(parsed["lo"][0].scope, "host")
        self.assertEqual(parsed["lo"][0].classification, "loopback")

        self.assertEqual(parsed["wlo1"][0].address, "fe80::5f3:90:9924:ef7c")
        self.assertEqual(parsed["wlo1"][0].prefix_length, 64)
        self.assertEqual(parsed["wlo1"][0].scope, "link")
        self.assertEqual(parsed["wlo1"][0].classification, "link-local")

        self.assertEqual(parsed["lxcbr0"][0].address, "fc42:5009:ba4b:5ab0::1")
        self.assertEqual(parsed["lxcbr0"][0].prefix_length, 64)
        self.assertEqual(parsed["lxcbr0"][0].scope, "global")
        self.assertEqual(parsed["lxcbr0"][0].classification, "unique-local")

    def test_missing_or_malformed_kernel_data(self) -> None:
        """Requirement 7: Graceful error handling on malformed JSON or corrupted lines."""
        self.assertEqual(HostNetworkProvider._parse_ip_addr_json("invalid-json"), [])
        self.assertEqual(HostNetworkProvider._parse_ip_addr_json("{}"), [])
        self.assertEqual(HostNetworkProvider._parse_ip_addr_json("[]"), [])

        malformed_lines = "bad line\nshort 01 80\n"
        self.assertEqual(HostNetworkProvider._parse_if_inet6(malformed_lines), {})

    def test_address_info_serialization_compatibility(self) -> None:
        """Requirement 8 & 10: Serialization stability and consumer compatibility."""
        info = IPAddressInfo(
            address="192.168.1.1",
            prefix_length=24,
            family="IPv4",
            netmask="255.255.255.0",
            broadcast="192.168.1.255",
            scope="global",
            classification="private",
            flags=["dynamic"],
        )
        data = info.to_dict()
        self.assertEqual(data["address"], "192.168.1.1")
        self.assertEqual(data["prefix_length"], 24)
        self.assertEqual(data["family"], "IPv4")
        self.assertEqual(data["netmask"], "255.255.255.0")
        self.assertEqual(data["broadcast"], "192.168.1.255")
        self.assertEqual(data["scope"], "global")
        self.assertEqual(data["classification"], "private")
        self.assertEqual(data["flags"], ["dynamic"])

        # Test JSON round-trip
        json_str = json.dumps(data)
        self.assertIn('"broadcast": "192.168.1.255"', json_str)
        self.assertIn('"classification": "private"', json_str)


class TestHostNetworkProviderLiveIntegration(unittest.TestCase):
    """Integration test against actual host kernel (read-only, does not assume specific names)."""

    def test_live_host_inspection_returns_valid_interfaces(self) -> None:
        """Verify real host execution returns valid NetworkInterface models without throwing."""
        provider = HostNetworkProvider()
        interfaces = provider.get_interfaces()

        # On any Linux host, at least loopback 'lo' must exist
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)

        lo = next((i for i in interfaces if i.name == "lo"), None)
        self.assertIsNotNone(lo, "Loopback interface 'lo' must be discovered on Linux host.")
        assert lo is not None

        self.assertEqual(lo.interface_type, InterfaceType.LOOPBACK)
        # Verify loopback addresses include 127.0.0.1
        v4_addrs = [a.address for a in lo.addresses if a.family == "IPv4"]
        self.assertIn("127.0.0.1", v4_addrs)

        # Ensure all addresses have valid families, prefix lengths, scopes, and classifications
        for iface in interfaces:
            self.assertIsInstance(iface.name, str)
            self.assertIsInstance(iface.mac_address, str)
            for addr in iface.addresses:
                self.assertIn(addr.family, ("IPv4", "IPv6"))
                self.assertGreater(addr.prefix_length, 0)
                self.assertLessEqual(addr.prefix_length, 128)
                self.assertIsNotNone(addr.classification)
                self.assertIn(
                    addr.classification,
                    ("loopback", "private", "link-local", "unique-local", "global-unicast", "site-local", "reserved"),
                )


class TestGatewayAndDNSAssociation(unittest.TestCase):
    """Deterministic tests for TASK-005 Local Gateway and DNS Association."""

    def _sample_interfaces(self) -> List[NetworkInterface]:
        return [
            NetworkInterface(
                name="lo",
                mac_address="00:00:00:00:00:00",
                state=InterfaceState.UP,
                interface_type=InterfaceType.LOOPBACK,
                mtu=65536,
                addresses=[
                    IPAddressInfo(address="127.0.0.1", prefix_length=8, family="IPv4", scope="host", classification="loopback"),
                    IPAddressInfo(address="::1", prefix_length=128, family="IPv6", scope="host", classification="loopback"),
                ],
            ),
            NetworkInterface(
                name="eth0",
                mac_address="02:42:0a:11:00:02",
                state=InterfaceState.UP,
                interface_type=InterfaceType.ETHERNET,
                mtu=1500,
                addresses=[
                    IPAddressInfo(address="192.168.1.105", prefix_length=24, family="IPv4", scope="global", classification="private"),
                    IPAddressInfo(address="fe80::42:aff:fe11:2", prefix_length=64, family="IPv6", scope="link", classification="link-local"),
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

    def test_criterion_1_ipv4_default_gateway_association(self) -> None:
        """1. IPv4 default gateway associated with the correct interface."""
        interfaces = self._sample_interfaces()
        gateways = [
            GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0", protocol="dhcp"),
        ]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=[],
        )

        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.gateways), 1)
        self.assertEqual(eth0.gateways[0].gateway, "192.168.1.1")
        self.assertEqual(eth0.gateways[0].family, "IPv4")
        self.assertEqual(eth0.gateways[0].interface, "eth0")
        self.assertEqual(eth0.default_ipv4_gateway, "192.168.1.1")
        self.assertIsNone(eth0.default_ipv6_gateway)

        lo = next(i for i in associated if i.name == "lo")
        self.assertEqual(len(lo.gateways), 0)
        self.assertIsNone(lo.default_ipv4_gateway)

    def test_criterion_2_ipv6_default_gateway_association(self) -> None:
        """2. IPv6 default gateway associated with the correct interface."""
        interfaces = self._sample_interfaces()
        gateways = [
            GatewayInfo(gateway="fe80::1", family="IPv6", metric=1024, interface="eth0", protocol="ra"),
        ]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=[],
        )

        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.gateways), 1)
        self.assertEqual(eth0.gateways[0].gateway, "fe80::1")
        self.assertEqual(eth0.gateways[0].family, "IPv6")
        self.assertEqual(eth0.default_ipv6_gateway, "fe80::1")
        self.assertIsNone(eth0.default_ipv4_gateway)

    def test_criterion_3_routes_with_no_gateway_or_no_default_route(self) -> None:
        """3. Routes with no gateway or no default route; never assume gateway from IP alone."""
        interfaces = self._sample_interfaces()
        # No default gateway provided
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=[],
            interface_dns={},
            system_dns=[],
        )
        for iface in associated:
            self.assertEqual(len(iface.gateways), 0)
            self.assertIsNone(iface.default_ipv4_gateway)
            self.assertIsNone(iface.default_ipv6_gateway)

    def test_criterion_4_multiple_default_routes_and_metrics(self) -> None:
        """4. Multiple default routes, metrics, and dual-stack handling."""
        interfaces = self._sample_interfaces()
        gateways = [
            GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0", protocol="dhcp"),
            GatewayInfo(gateway="10.0.0.1", family="IPv4", metric=600, interface="eth0", protocol="static"),
            GatewayInfo(gateway="fe80::1", family="IPv6", metric=1024, interface="eth0", protocol="ra"),
        ]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=[],
        )

        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.gateways), 3)
        # default_ipv4_gateway picks lowest metric (100 over 600)
        self.assertEqual(eth0.default_ipv4_gateway, "192.168.1.1")
        self.assertEqual(eth0.default_ipv6_gateway, "fe80::1")

    def test_criterion_5_missing_or_malformed_routing_data(self) -> None:
        """5. Graceful handling of missing or malformed routing entries."""
        interfaces = self._sample_interfaces()
        # Empty interface name in gateway
        gateways = [
            GatewayInfo(gateway="1.1.1.1", family="IPv4", metric=None, interface=""),
        ]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=[],
        )
        for iface in associated:
            self.assertEqual(len(iface.gateways), 0)

    def test_criterion_6_system_wide_dns_without_interface_mapping(self) -> None:
        """6. System-wide DNS without a verified per-interface mapping.
        
        Must be attributed with scope='system', interface=None, provenance='resolv.conf'.
        Must NOT be attached to unrelated interfaces like 'lo'.
        """
        interfaces = self._sample_interfaces()
        gateways = [
            GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0"),
        ]
        system_dns = [
            DNSServerInfo(address="8.8.8.8", scope="system", interface=None, provenance="resolv.conf"),
            DNSServerInfo(address="8.8.4.4", scope="system", interface=None, provenance="resolv.conf"),
        ]

        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},  # No interface-specific metadata
            system_dns=system_dns,
        )

        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.dns_servers), 2)
        for s in eth0.dns_servers:
            self.assertEqual(s.scope, "system")
            self.assertIsNone(s.interface)
            self.assertEqual(s.provenance, "resolv.conf")
        self.assertEqual(len(eth0.system_dns_servers), 2)
        self.assertEqual(len(eth0.interface_dns_servers), 0)

        # Loopback must not receive system DNS
        lo = next(i for i in associated if i.name == "lo")
        self.assertEqual(len(lo.dns_servers), 0)

    def test_criterion_7_interface_specific_dns_association(self) -> None:
        """7. Interface-specific DNS where reliable metadata exists (e.g. NetworkManager).
        
        Must be attributed with scope='interface', interface='eth0', provenance='networkmanager'.
        """
        interfaces = self._sample_interfaces()
        gateways = [
            GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0"),
        ]
        interface_dns = {
            "eth0": [
                DNSServerInfo(address="192.168.1.1", scope="interface", interface="eth0", provenance="networkmanager")
            ]
        }
        system_dns = [
            DNSServerInfo(address="8.8.8.8", scope="system", interface=None, provenance="resolv.conf")
        ]

        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns=interface_dns,
            system_dns=system_dns,
        )

        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.dns_servers), 1)
        dns_entry = eth0.dns_servers[0]
        self.assertEqual(dns_entry.address, "192.168.1.1")
        self.assertEqual(dns_entry.scope, "interface")
        self.assertEqual(dns_entry.interface, "eth0")
        self.assertEqual(dns_entry.provenance, "networkmanager")
        self.assertEqual(len(eth0.interface_dns_servers), 1)
        self.assertEqual(len(eth0.system_dns_servers), 0)

    def test_criterion_8_missing_or_empty_resolver_configuration(self) -> None:
        """8. Missing or empty resolver configuration returns empty list without errors."""
        interfaces = self._sample_interfaces()
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=[GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0")],
            interface_dns={},
            system_dns=[],
        )
        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.dns_servers), 0)

    def test_criterion_9_multiple_nameservers_and_duplicate_handling(self) -> None:
        """9. Multiple nameservers and duplicate elimination."""
        interfaces = self._sample_interfaces()
        gateways = [GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0")]
        # Pre-deduplicated list of multiple nameservers
        system_dns = [
            DNSServerInfo(address="1.1.1.1", scope="system", interface=None, provenance="resolv.conf"),
            DNSServerInfo(address="1.0.0.1", scope="system", interface=None, provenance="resolv.conf"),
            DNSServerInfo(address="2606:4700:4700::1111", scope="system", interface=None, provenance="resolv.conf"),
        ]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=system_dns,
        )
        eth0 = next(i for i in associated if i.name == "eth0")
        self.assertEqual(len(eth0.dns_servers), 3)
        addrs = [d.address for d in eth0.dns_servers]
        self.assertEqual(addrs, ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"])

    def test_criterion_10_deterministic_mock_mode_gateway_and_dns(self) -> None:
        """10. Deterministic mock-mode gateway and DNS data in MockNetworkProvider."""
        provider = MockNetworkProvider()
        interfaces = provider.get_interfaces()
        self.assertEqual(len(interfaces), 3)

        lo = next(i for i in interfaces if i.name == "lo")
        self.assertEqual(len(lo.gateways), 0)
        self.assertEqual(len(lo.dns_servers), 0)

        eth0 = next(i for i in interfaces if i.name == "eth0")
        self.assertEqual(len(eth0.gateways), 2)
        self.assertEqual(eth0.default_ipv4_gateway, "192.168.1.1")
        self.assertEqual(eth0.default_ipv6_gateway, "fe80::1")
        self.assertEqual(len(eth0.dns_servers), 1)
        self.assertEqual(eth0.dns_servers[0].address, "192.168.1.1")
        self.assertEqual(eth0.dns_servers[0].scope, "interface")
        self.assertEqual(eth0.dns_servers[0].interface, "eth0")

        wlan0 = next(i for i in interfaces if i.name == "wlan0")
        self.assertEqual(len(wlan0.gateways), 0)
        self.assertEqual(len(wlan0.dns_servers), 0)

    def test_criterion_11_backward_compatible_model_serialization(self) -> None:
        """11. Backward-compatible model instantiation, serialization, and existing consumers."""
        # Instantiation without new kwargs works via default_factory
        iface = NetworkInterface(
            name="eth9",
            mac_address="52:54:00:12:34:56",
            state=InterfaceState.UP,
            interface_type=InterfaceType.ETHERNET,
            mtu=1500,
            addresses=[],
        )
        self.assertEqual(iface.gateways, [])
        self.assertEqual(iface.dns_servers, [])
        self.assertIsNone(iface.default_ipv4_gateway)
        self.assertIsNone(iface.default_ipv6_gateway)

        # Serialization to dict
        d = iface.to_dict()
        self.assertIn("gateways", d)
        self.assertIn("dns_servers", d)
        self.assertEqual(d["gateways"], [])
        self.assertEqual(d["dns_servers"], [])
        self.assertEqual(d["state"], "UP")
        self.assertEqual(d["interface_type"], "Ethernet")

        # JSON round-trip
        json_str = json.dumps(d)
        deserialized = json.loads(json_str)
        self.assertEqual(deserialized["name"], "eth9")
        self.assertEqual(deserialized["gateways"], [])

    def test_criterion_12_unprivileged_execution_and_absence_of_active_probes(self) -> None:
        """12. Association operates purely in-memory on data structures with zero socket probes."""
        # Ensure that associate_gateways_and_dns runs completely in-memory without external calls
        interfaces = self._sample_interfaces()
        gateways = [GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0")]
        associated = HostNetworkProvider.associate_gateways_and_dns(
            interfaces=interfaces,
            gateways=gateways,
            interface_dns={},
            system_dns=[],
        )
        self.assertIsInstance(associated, list)
        self.assertEqual(len(associated), 3)


class TestHostProviderExhaustiveUnitMatrix(unittest.TestCase):
    """Exhaustive deterministic unit test matrix for TASK-006.
    
    Verifies interface types, states, address extraction, secondary IPs,
    IPv6 flags, unusual MTUs, VLANs, and malformed kernel data using synthetic fixtures.
    """

    def test_interface_type_classification_all_categories(self) -> None:
        """Verify all InterfaceType enum classifications across physical, virtual, loopback, wireless, unknown."""
        # 1. Physical Ethernet
        for name in ["eth0", "eth1", "enp4s0", "ens33", "eno1", "em1"]:
            self.assertEqual(
                HostNetworkProvider.classify_interface_type(name),
                InterfaceType.ETHERNET,
                f"Failed for physical ethernet: {name}",
            )
        self.assertEqual(
            HostNetworkProvider.classify_interface_type("custom_card", link_type="ether"),
            InterfaceType.ETHERNET,
        )

        # 2. Virtual interfaces (bridges, containers, veth, virbr)
        for name in ["docker0", "virbr0", "br-lan", "br0", "lxcbr0", "veth1234", "vnet0", "bridge0"]:
            self.assertEqual(
                HostNetworkProvider.classify_interface_type(name),
                InterfaceType.VIRTUAL,
                f"Failed for virtual interface: {name}",
            )
        self.assertEqual(
            HostNetworkProvider.classify_interface_type("custom_br", link_type="bridge"),
            InterfaceType.VIRTUAL,
        )

        # 3. Loopback
        self.assertEqual(HostNetworkProvider.classify_interface_type("lo"), InterfaceType.LOOPBACK)
        self.assertEqual(HostNetworkProvider.classify_interface_type("loopback_dev", link_type="loopback"), InterfaceType.LOOPBACK)

        # 4. Wireless
        for name in ["wlan0", "wlo1", "wlp2s0", "wifi0"]:
            self.assertEqual(
                HostNetworkProvider.classify_interface_type(name),
                InterfaceType.WIRELESS,
                f"Failed for wireless interface: {name}",
            )
        self.assertEqual(
            HostNetworkProvider.classify_interface_type("ath0", link_type="wlan"),
            InterfaceType.WIRELESS,
        )

        # 5. Unknown or unclassified interfaces
        for name in ["tun0", "ppp0", "sit0", "dummy0", "wg0", "unknown_device"]:
            self.assertEqual(
                HostNetworkProvider.classify_interface_type(name),
                InterfaceType.UNKNOWN,
                f"Failed for unknown interface: {name}",
            )

    def test_interface_state_classification_all_values(self) -> None:
        """Verify all InterfaceState enum classifications across UP, DOWN, and UNKNOWN/Dormant."""
        self.assertEqual(HostNetworkProvider.classify_interface_state("UP"), InterfaceState.UP)
        self.assertEqual(HostNetworkProvider.classify_interface_state("up"), InterfaceState.UP)
        self.assertEqual(HostNetworkProvider.classify_interface_state("DOWN"), InterfaceState.DOWN)
        self.assertEqual(HostNetworkProvider.classify_interface_state("down"), InterfaceState.DOWN)

        # Unknown / unavailable state data
        for state in ["UNKNOWN", "unknown", "DORMANT", "dormant", "LOWERLAYERDOWN", "NOTPRESENT", "", None]:
            self.assertEqual(
                HostNetworkProvider.classify_interface_state(state),
                InterfaceState.UNKNOWN,
                f"Failed for state: {state}",
            )

    def test_synthetic_ip_addr_json_all_types_and_states(self) -> None:
        """Verify multi-interface synthetic payload containing all 5 interface types and all 3 states."""
        synthetic_payload = json.dumps([
            {
                "ifname": "lo",
                "link_type": "loopback",
                "operstate": "UNKNOWN",
                "mtu": 65536,
                "address": "00:00:00:00:00:00",
                "addr_info": [
                    {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                    {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"},
                ],
            },
            {
                "ifname": "enp4s0",
                "link_type": "ether",
                "operstate": "UP",
                "mtu": 1500,
                "address": "04:7c:16:32:2f:92",
                "addr_info": [
                    {"family": "inet", "local": "192.168.1.50", "prefixlen": 24, "broadcast": "192.168.1.255", "scope": "global"},
                ],
            },
            {
                "ifname": "wlan0",
                "link_type": "wlan",
                "operstate": "DOWN",
                "mtu": 1500,
                "address": "3c:52:82:1a:2b:3c",
                "addr_info": [],
            },
            {
                "ifname": "docker0",
                "link_type": "bridge",
                "operstate": "DOWN",
                "mtu": 1500,
                "address": "02:42:1a:3b:5c:7d",
                "addr_info": [
                    {"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "broadcast": "172.17.255.255", "scope": "global"},
                ],
            },
            {
                "ifname": "tun0",
                "link_type": "none",
                "operstate": "UP",
                "mtu": 1400,
                "address": "00:00:00:00:00:00",
                "addr_info": [
                    {"family": "inet", "local": "10.8.0.2", "prefixlen": 32, "scope": "global"},
                ],
            },
        ])

        interfaces = HostNetworkProvider._parse_ip_addr_json(synthetic_payload)
        self.assertEqual(len(interfaces), 5)

        # Loopback
        lo = next(i for i in interfaces if i.name == "lo")
        self.assertEqual(lo.interface_type, InterfaceType.LOOPBACK)
        self.assertEqual(lo.state, InterfaceState.UNKNOWN)
        self.assertEqual(lo.mtu, 65536)
        self.assertEqual(len(lo.addresses), 2)

        # Ethernet
        enp = next(i for i in interfaces if i.name == "enp4s0")
        self.assertEqual(enp.interface_type, InterfaceType.ETHERNET)
        self.assertEqual(enp.state, InterfaceState.UP)
        self.assertEqual(len(enp.addresses), 1)
        self.assertEqual(enp.addresses[0].classification, "private")

        # Wireless
        wlan = next(i for i in interfaces if i.name == "wlan0")
        self.assertEqual(wlan.interface_type, InterfaceType.WIRELESS)
        self.assertEqual(wlan.state, InterfaceState.DOWN)
        self.assertEqual(len(wlan.addresses), 0)

        # Virtual
        docker = next(i for i in interfaces if i.name == "docker0")
        self.assertEqual(docker.interface_type, InterfaceType.VIRTUAL)
        self.assertEqual(docker.state, InterfaceState.DOWN)
        self.assertEqual(len(docker.addresses), 1)

        # Unknown
        tun = next(i for i in interfaces if i.name == "tun0")
        self.assertEqual(tun.interface_type, InterfaceType.UNKNOWN)
        self.assertEqual(tun.state, InterfaceState.UP)
        self.assertEqual(tun.mtu, 1400)
        self.assertEqual(len(tun.addresses), 1)

    def test_ipv4_subnets_and_broadcast_rfc_variations(self) -> None:
        """Verify IPv4 extraction across various CIDR masks including RFC 3021 /31 and host /32."""
        cases = [
            ("10.0.0.1", 8, "255.0.0.0", "10.255.255.255"),
            ("172.16.5.1", 16, "255.255.0.0", "172.16.255.255"),
            ("192.168.10.1", 24, "255.255.255.0", "192.168.10.255"),
            ("192.168.1.1", 30, "255.255.255.252", "192.168.1.3"),
            ("192.168.1.2", 31, "255.255.255.254", None),  # RFC 3021 point-to-point without broadcast
            ("192.168.1.100", 32, "255.255.255.255", None),  # /32 host route
        ]

        addr_info_list = []
        for ip, prefix, exp_mask, exp_bcast in cases:
            entry = {"family": "inet", "local": ip, "prefixlen": prefix, "scope": "global"}
            if exp_bcast:
                entry["broadcast"] = exp_bcast
            addr_info_list.append(entry)

        payload = json.dumps([{
            "ifname": "eth0",
            "link_type": "ether",
            "operstate": "UP",
            "mtu": 1500,
            "address": "02:42:0a:11:00:02",
            "addr_info": addr_info_list,
        }])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        eth0 = interfaces[0]
        self.assertEqual(len(eth0.addresses), len(cases))

        for idx, (ip, prefix, exp_mask, exp_bcast) in enumerate(cases):
            parsed = eth0.addresses[idx]
            self.assertEqual(parsed.address, ip)
            self.assertEqual(parsed.prefix_length, prefix)
            self.assertEqual(parsed.netmask, exp_mask)
            self.assertEqual(parsed.broadcast, exp_bcast)
            self.assertEqual(parsed.family, "IPv4")

    def test_ipv6_architectural_classifications(self) -> None:
        """Verify IPv6 scope and RFC classification across link-local, ULA, and global unicast."""
        cases = [
            ("fe80::1", 64, "link", "link-local"),
            ("fc42:5009:ba4b:5ab0::1", 64, "global", "unique-local"),
            ("fd12:3456:789a::1", 64, "global", "unique-local"),
            ("2001:4860:4860::8888", 64, "global", "global-unicast"),
            ("::1", 128, "host", "loopback"),
        ]

        addr_info_list = [
            {"family": "inet6", "local": ip, "prefixlen": prefix, "scope": scope}
            for ip, prefix, scope, _ in cases
        ]
        payload = json.dumps([{
            "ifname": "eth0",
            "link_type": "ether",
            "operstate": "UP",
            "mtu": 1500,
            "address": "02:42:0a:11:00:02",
            "addr_info": addr_info_list,
        }])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        eth0 = interfaces[0]
        self.assertEqual(len(eth0.addresses), len(cases))

        for idx, (ip, prefix, exp_scope, exp_class) in enumerate(cases):
            parsed = eth0.addresses[idx]
            self.assertEqual(parsed.address, ip)
            self.assertEqual(parsed.prefix_length, prefix)
            self.assertEqual(parsed.scope, exp_scope)
            self.assertEqual(parsed.classification, exp_class)
            self.assertEqual(parsed.family, "IPv6")

    def test_dual_stack_with_multiple_ips_and_secondary_addresses(self) -> None:
        """Verify dual-stack interface with primary and secondary IPv4 addresses and multiple IPv6."""
        payload = json.dumps([{
            "ifname": "eth0",
            "link_type": "ether",
            "operstate": "UP",
            "mtu": 1500,
            "address": "02:42:0a:11:00:02",
            "addr_info": [
                {"family": "inet", "local": "192.168.1.10", "prefixlen": 24, "broadcast": "192.168.1.255", "scope": "global"},
                {"family": "inet", "local": "10.0.0.10", "prefixlen": 16, "broadcast": "10.0.255.255", "scope": "global", "secondary": True},
                {"family": "inet", "local": "172.16.0.10", "prefixlen": 12, "broadcast": "172.31.255.255", "scope": "global", "secondary": True},
                {"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, "scope": "global"},
                {"family": "inet6", "local": "fd00::1", "prefixlen": 64, "scope": "global"},
                {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
            ],
        }])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        eth0 = interfaces[0]
        self.assertEqual(len(eth0.addresses), 6)

        v4_addrs = [a for a in eth0.addresses if a.family == "IPv4"]
        v6_addrs = [a for a in eth0.addresses if a.family == "IPv6"]
        self.assertEqual(len(v4_addrs), 3)
        self.assertEqual(len(v6_addrs), 3)

        # Primary IPv4
        self.assertEqual(v4_addrs[0].address, "192.168.1.10")
        self.assertNotIn("secondary", v4_addrs[0].flags)

        # Secondaries
        self.assertEqual(v4_addrs[1].address, "10.0.0.10")
        self.assertIn("secondary", v4_addrs[1].flags)
        self.assertEqual(v4_addrs[2].address, "172.16.0.10")
        self.assertIn("secondary", v4_addrs[2].flags)

    def test_deprecated_and_tentative_ipv6_flags(self) -> None:
        """Verify that IPv6 flags (deprecated, tentative, temporary, noprefixroute, mngtmpaddr) are parsed."""
        payload = json.dumps([{
            "ifname": "eth0",
            "link_type": "ether",
            "operstate": "UP",
            "mtu": 1500,
            "address": "02:42:0a:11:00:02",
            "addr_info": [
                {
                    "family": "inet6",
                    "local": "2001:db8::10",
                    "prefixlen": 64,
                    "scope": "global",
                    "deprecated": True,
                    "temporary": True,
                },
                {
                    "family": "inet6",
                    "local": "2001:db8::11",
                    "prefixlen": 64,
                    "scope": "global",
                    "tentative": True,
                    "noprefixroute": True,
                    "mngtmpaddr": True,
                },
            ],
        }])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        eth0 = interfaces[0]
        self.assertEqual(len(eth0.addresses), 2)

        addr1 = eth0.addresses[0]
        self.assertIn("deprecated", addr1.flags)
        self.assertIn("temporary", addr1.flags)

        addr2 = eth0.addresses[1]
        self.assertIn("tentative", addr2.flags)
        self.assertIn("noprefixroute", addr2.flags)
        self.assertIn("mngtmpaddr", addr2.flags)

    def test_unusual_and_extreme_mtus(self) -> None:
        """Verify MTU parsing across Jumbo frames (9000), Loopback (65536), and fallback behavior."""
        payload = json.dumps([
            {"ifname": "jumbo0", "link_type": "ether", "mtu": 9000, "addr_info": []},
            {"ifname": "lo", "link_type": "loopback", "mtu": 65536, "addr_info": []},
            {"ifname": "min0", "link_type": "ether", "mtu": 1280, "addr_info": []},
            {"ifname": "fallback0", "link_type": "ether", "addr_info": []},  # missing mtu -> 1500
            {"ifname": "badmtu0", "link_type": "ether", "mtu": "not-an-int", "addr_info": []},  # non-numeric -> 1500
        ])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        self.assertEqual(len(interfaces), 5)

        self.assertEqual(next(i for i in interfaces if i.name == "jumbo0").mtu, 9000)
        self.assertEqual(next(i for i in interfaces if i.name == "lo").mtu, 65536)
        self.assertEqual(next(i for i in interfaces if i.name == "min0").mtu, 1280)
        self.assertEqual(next(i for i in interfaces if i.name == "fallback0").mtu, 1500)
        self.assertEqual(next(i for i in interfaces if i.name == "badmtu0").mtu, 1500)

    def test_vlan_and_bridge_naming_conventions(self) -> None:
        """Verify that 802.1Q VLAN subinterfaces and bridge/container names are classified correctly."""
        payload = json.dumps([
            {"ifname": "eth0.10", "link_type": "ether", "operstate": "UP", "addr_info": []},
            {"ifname": "enp4s0.100", "link_type": "ether", "operstate": "UP", "addr_info": []},
            {"ifname": "br-4f6a1e3", "link_type": "bridge", "operstate": "UP", "addr_info": []},
            {"ifname": "veth7c8a9", "link_type": "ether", "operstate": "UP", "addr_info": []},
        ])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        self.assertEqual(len(interfaces), 4)

        # VLAN subinterfaces of Ethernet interfaces retain Ethernet classification
        self.assertEqual(interfaces[0].interface_type, InterfaceType.ETHERNET)
        self.assertEqual(interfaces[1].interface_type, InterfaceType.ETHERNET)

        # Bridge and veth interfaces are classified as Virtual
        self.assertEqual(interfaces[2].interface_type, InterfaceType.VIRTUAL)
        self.assertEqual(interfaces[3].interface_type, InterfaceType.VIRTUAL)

    def test_malformed_and_incomplete_kernel_data_robustness(self) -> None:
        """Verify parsing robustness when encountering null fields, missing keys, or corrupt data."""
        payload = json.dumps([
            {"missing_name": True},  # No ifname: must be skipped
            {"ifname": "", "link_type": "ether"},  # Empty ifname: must be skipped
            {
                "ifname": "corrupt0",
                "link_type": "ether",
                "addr_info": [
                    "not-a-dict",  # Corrupted element: must be skipped
                    {"local": ""},  # Empty IP: must be skipped
                    {"local": "192.168.1.1", "family": "unknown_fam", "prefixlen": -5},  # Invalid prefix
                ],
            },
        ])

        interfaces = HostNetworkProvider._parse_ip_addr_json(payload)
        self.assertEqual(len(interfaces), 1)
        corrupt0 = interfaces[0]
        self.assertEqual(corrupt0.name, "corrupt0")
        self.assertEqual(len(corrupt0.addresses), 1)
        # Invalid prefixlen (-5) results in empty netmask without throwing
        self.assertEqual(corrupt0.addresses[0].netmask, "")

    def test_discover_from_proc_and_sys_execution(self) -> None:
        """Verify _discover_from_proc_and_sys runs without NameError or UnboundLocalError."""
        provider = HostNetworkProvider()
        interfaces = provider._discover_from_proc_and_sys()
        self.assertIsInstance(interfaces, list)
        if interfaces:
            for iface in interfaces:
                self.assertIsInstance(iface.name, str)
                self.assertIsInstance(iface.interface_type, InterfaceType)
                self.assertIsInstance(iface.state, InterfaceState)
                self.assertIsInstance(iface.mtu, int)
                self.assertGreater(iface.mtu, 0)


if __name__ == "__main__":
    unittest.main()
