"""Unit tests for routing table and VLAN inspection."""

import json
import unittest
from itsa_network_os.network.models import GatewayInfo
from itsa_network_os.network.routes import RouteEntry, RouteParser, VlanInfo


class TestRouteParser(unittest.TestCase):
    """Test routing table parsing and VLAN detection."""

    def test_mock_routes(self) -> None:
        routes = RouteParser.get_routes(use_mock=True)
        self.assertGreaterEqual(len(routes), 2)
        for r in routes:
            self.assertIsInstance(r, RouteEntry)
            self.assertIn(r.interface, ["eth0", "lo"])

    def test_vlan_detection(self) -> None:
        ifaces = ["eth0", "eth0.10", "eth0.20", "wlan0", "lo", "docker0"]
        vlans = RouteParser.detect_vlans(ifaces)
        self.assertEqual(len(vlans), 2)
        self.assertEqual(vlans[0].parent_interface, "eth0")
        self.assertEqual(vlans[0].vlan_id, 10)
        self.assertEqual(vlans[1].vlan_id, 20)

    def test_hex_to_ip_conversion(self) -> None:
        # 0x0101A8C0 in little-endian hex is 192.168.1.1
        ip = RouteParser._hex_to_ip("0101A8C0")
        self.assertEqual(ip, "192.168.1.1")

    def test_hex_to_ipv6_conversion(self) -> None:
        # fe80::1 representation in 32 hex chars
        hex_fe80 = "fe800000000000000000000000000001"
        ip6 = RouteParser._hex_to_ipv6(hex_fe80)
        self.assertEqual(ip6, "fe80::1")

        # invalid hex returns default fallback "::"
        self.assertEqual(RouteParser._hex_to_ipv6("invalid"), "::")

    def test_parse_proc_route_ipv4_table(self) -> None:
        sample_proc = (
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
            "wlo1\t00000000\t05BF7D0A\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
            "lxcbr0\t0003000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        )
        routes = RouteParser.parse_proc_route(sample_proc)
        self.assertEqual(len(routes), 2)

        default_route = routes[0]
        self.assertEqual(default_route.destination, "default")
        self.assertEqual(default_route.gateway, "10.125.191.5")
        self.assertEqual(default_route.interface, "wlo1")
        self.assertEqual(default_route.metric, 600)
        self.assertEqual(default_route.flags, "UG")
        self.assertEqual(default_route.family, "IPv4")

        onlink_route = routes[1]
        self.assertEqual(onlink_route.gateway, "on-link")
        self.assertEqual(onlink_route.flags, "U")

    def test_parse_proc_ipv6_route_table(self) -> None:
        sample_proc_ipv6 = (
            # 1. Reject route on lo (should be filtered out)
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"
            # 2. Real default route via fe80::1 on eth0
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
            # 3. Subnet route
            "fc425009ba4b5ab00000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001 lxcbr0\n"
        )
        routes = RouteParser.parse_proc_ipv6_route(sample_proc_ipv6)
        self.assertEqual(len(routes), 2)

        default_v6 = routes[0]
        self.assertEqual(default_v6.destination, "default")
        self.assertEqual(default_v6.gateway, "fe80::1")
        self.assertEqual(default_v6.interface, "eth0")
        self.assertEqual(default_v6.metric, 1024)
        self.assertEqual(default_v6.flags, "UG")
        self.assertEqual(default_v6.family, "IPv6")

    def test_parse_ip_route_json(self) -> None:
        sample_json = json.dumps([
            {"dst": "default", "gateway": "192.168.10.1", "dev": "eth0", "metric": 100, "flags": ["onlink"]},
            {"dst": "192.168.10.0/24", "dev": "eth0", "metric": 100, "flags": []},
        ])
        routes = RouteParser.parse_ip_route_json(sample_json, family="IPv4")
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0].destination, "default")
        self.assertEqual(routes[0].gateway, "192.168.10.1")
        self.assertEqual(routes[0].interface, "eth0")
        self.assertEqual(routes[0].metric, 100)

    def test_mock_default_gateways(self) -> None:
        gws = RouteParser.get_default_gateways(use_mock=True)
        self.assertEqual(len(gws), 2)

        v4 = next(g for g in gws if g.family == "IPv4")
        self.assertEqual(v4.gateway, "192.168.1.1")
        self.assertEqual(v4.interface, "eth0")
        self.assertEqual(v4.metric, 100)

        v6 = next(g for g in gws if g.family == "IPv6")
        self.assertEqual(v6.gateway, "fe80::1")
        self.assertEqual(v6.interface, "eth0")
        self.assertEqual(v6.metric, 1024)


if __name__ == "__main__":
    unittest.main()
