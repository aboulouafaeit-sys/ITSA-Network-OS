"""Unit tests for routing table and VLAN inspection."""

import unittest
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


if __name__ == "__main__":
    unittest.main()
