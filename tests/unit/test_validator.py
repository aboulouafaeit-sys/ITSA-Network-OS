"""Unit tests for input validator."""

import unittest
from pathlib import Path
from itsa_network_os.security.validator import InputValidator, SecurityValidationError


class TestInputValidator(unittest.TestCase):
    """Test input validation and boundary protections."""

    def test_valid_ipv4_addresses(self) -> None:
        ip = InputValidator.validate_ipv4_address("192.168.1.1")
        self.assertEqual(str(ip), "192.168.1.1")

    def test_invalid_ipv4_addresses(self) -> None:
        invalid_ips = ["999.999.999.999", "192.168.1.300", "invalid", "192.168.1.1/24; rm -rf /"]
        for item in invalid_ips:
            with self.assertRaises(SecurityValidationError):
                InputValidator.validate_ipv4_address(item)

    def test_valid_cidr_networks(self) -> None:
        net = InputValidator.validate_ipv4_network("10.0.0.0/8")
        self.assertEqual(str(net), "10.0.0.0/8")

    def test_invalid_cidr_networks(self) -> None:
        invalid_cidrs = ["10.0.0.0/33", "192.168.1.1/abc", "random_string"]
        for item in invalid_cidrs:
            with self.assertRaises(SecurityValidationError):
                InputValidator.validate_ipv4_network(item)

    def test_valid_interface_names(self) -> None:
        for name in ["eth0", "wlan0", "enp3s0", "lo", "tun-1"]:
            self.assertEqual(InputValidator.validate_interface_name(name), name)

    def test_invalid_interface_names(self) -> None:
        for bad in ["eth0; whoami", "../etc/passwd", "name with spaces", "a" * 20]:
            with self.assertRaises(SecurityValidationError):
                InputValidator.validate_interface_name(bad)


if __name__ == "__main__":
    unittest.main()
