"""Unit and integration tests for network interface inspector and address discovery."""

import json
import unittest
from itsa_network_os.network.inspector import HostNetworkProvider, MockNetworkProvider, NetworkInspector
from itsa_network_os.network.models import InterfaceState, InterfaceType, IPAddressInfo, NetworkInterface


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
        self.assertIn("dynamic", primary.flags)

        secondary = ipv4_addrs[1]
        self.assertEqual(secondary.address, "10.0.0.2")
        self.assertEqual(secondary.prefix_length, 16)
        self.assertEqual(secondary.netmask, "255.255.0.0")
        self.assertEqual(secondary.broadcast, "10.0.255.255")
        self.assertIn("secondary", secondary.flags)

    def test_parse_ip_addr_json_ipv6_and_scopes(self) -> None:
        """Requirement 3 & 4: IPv6 address, prefix length, and link-local vs global classification."""
        interfaces = HostNetworkProvider._parse_ip_addr_json(self.DETERMINISTIC_IP_JSON)
        eth0 = next(i for i in interfaces if i.name == "eth0")
        ipv6_addrs = [a for a in eth0.addresses if a.family == "IPv6"]
        self.assertEqual(len(ipv6_addrs), 2)

        link_local = next(a for a in ipv6_addrs if a.scope == "link-local")
        self.assertEqual(link_local.address, "fe80::42:aff:fe11:2")
        self.assertEqual(link_local.prefix_length, 64)
        self.assertEqual(link_local.netmask, "ffff:ffff:ffff:ffff::")
        self.assertIsNone(link_local.broadcast)
        self.assertIn("noprefixroute", link_local.flags)

        global_ipv6 = next(a for a in ipv6_addrs if a.scope == "global")
        self.assertEqual(global_ipv6.address, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(global_ipv6.prefix_length, 64)
        self.assertIn("mngtmpaddr", global_ipv6.flags)

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

    def test_classify_ip_scope_standard_library(self) -> None:
        """Requirement 4: Non-heuristic scope classification using ipaddress."""
        self.assertEqual(HostNetworkProvider.classify_ip_scope("127.0.0.1"), "host")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("::1"), "host")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("fe80::1"), "link-local")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("fe80::dead:beef"), "link-local")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("169.254.1.1"), "link-local")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("2001:db8::1"), "global")
        self.assertEqual(HostNetworkProvider.classify_ip_scope("invalid-ip"), "unknown")

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

        self.assertEqual(parsed["wlo1"][0].address, "fe80::5f3:90:9924:ef7c")
        self.assertEqual(parsed["wlo1"][0].prefix_length, 64)
        self.assertEqual(parsed["wlo1"][0].scope, "link-local")

        self.assertEqual(parsed["lxcbr0"][0].address, "fc42:5009:ba4b:5ab0::1")
        self.assertEqual(parsed["lxcbr0"][0].prefix_length, 64)
        self.assertEqual(parsed["lxcbr0"][0].scope, "global")

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
            flags=["dynamic"],
        )
        data = info.to_dict()
        self.assertEqual(data["address"], "192.168.1.1")
        self.assertEqual(data["prefix_length"], 24)
        self.assertEqual(data["family"], "IPv4")
        self.assertEqual(data["netmask"], "255.255.255.0")
        self.assertEqual(data["broadcast"], "192.168.1.255")
        self.assertEqual(data["scope"], "global")
        self.assertEqual(data["flags"], ["dynamic"])

        # Test JSON round-trip
        json_str = json.dumps(data)
        self.assertIn('"broadcast": "192.168.1.255"', json_str)


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

        # Ensure all addresses have valid families and prefix lengths
        for iface in interfaces:
            self.assertIsInstance(iface.name, str)
            self.assertIsInstance(iface.mac_address, str)
            for addr in iface.addresses:
                self.assertIn(addr.family, ("IPv4", "IPv6"))
                self.assertGreater(addr.prefix_length, 0)
                self.assertLessEqual(addr.prefix_length, 128)


if __name__ == "__main__":
    unittest.main()
