"""Unit tests for CIDR subnet calculation engine."""

import unittest
from itsa_network_os.network.subnet import SubnetCalculationError, SubnetCalculator


class TestSubnetCalculator(unittest.TestCase):
    """Test RFC-compliant IPv4 and IPv6 subnet calculations."""

    def test_standard_class_c_slash_24(self) -> None:
        res = SubnetCalculator.calculate("192.168.1.0/24")
        self.assertEqual(res.network_address, "192.168.1.0")
        self.assertEqual(res.netmask, "255.255.255.0")
        self.assertEqual(res.wildcard_mask, "0.0.0.255")
        self.assertEqual(res.broadcast_address, "192.168.1.255")
        self.assertEqual(res.total_hosts, 256)
        self.assertEqual(res.usable_hosts, 254)
        self.assertEqual(res.first_usable_ip, "192.168.1.1")
        self.assertEqual(res.last_usable_ip, "192.168.1.254")

    def test_class_b_slash_16(self) -> None:
        res = SubnetCalculator.calculate("172.16.0.0/16")
        self.assertEqual(res.netmask, "255.255.0.0")
        self.assertEqual(res.total_hosts, 65536)
        self.assertEqual(res.usable_hosts, 65534)
        self.assertEqual(res.first_usable_ip, "172.16.0.1")
        self.assertEqual(res.last_usable_ip, "172.16.255.254")

    def test_point_to_point_rfc3021_slash_31(self) -> None:
        res = SubnetCalculator.calculate("10.10.10.0/31")
        self.assertEqual(res.total_hosts, 2)
        self.assertEqual(res.usable_hosts, 2)
        self.assertEqual(res.first_usable_ip, "10.10.10.0")
        self.assertEqual(res.last_usable_ip, "10.10.10.1")

    def test_host_route_slash_32(self) -> None:
        res = SubnetCalculator.calculate("10.0.0.5/32")
        self.assertEqual(res.total_hosts, 1)
        self.assertEqual(res.usable_hosts, 1)
        self.assertEqual(res.first_usable_ip, "10.0.0.5")
        self.assertEqual(res.last_usable_ip, "10.0.0.5")

    def test_slash_22(self) -> None:
        res = SubnetCalculator.calculate("10.0.0.0/22")
        self.assertEqual(res.total_hosts, 1024)
        self.assertEqual(res.usable_hosts, 1022)
        self.assertEqual(res.first_usable_ip, "10.0.0.1")
        self.assertEqual(res.last_usable_ip, "10.0.3.254")
        self.assertEqual(res.broadcast_address, "10.0.3.255")

    def test_ipv6_calculation(self) -> None:
        res = SubnetCalculator.calculate("2001:db8::/64")
        self.assertEqual(res.ip_version, 6)
        self.assertEqual(res.network_address, "2001:db8::")
        self.assertEqual(res.first_usable_ip, "2001:db8::")

    def test_invalid_cidr_raises(self) -> None:
        with self.assertRaises(SubnetCalculationError):
            SubnetCalculator.calculate("999.999.999.0/24")


if __name__ == "__main__":
    unittest.main()
