"""Unit tests for network interface inspector."""

import unittest
from itsa_network_os.network.inspector import MockNetworkProvider, NetworkInspector
from itsa_network_os.network.models import InterfaceType


class TestNetworkInspector(unittest.TestCase):
    """Test safe mock interface reader."""

    def test_mock_provider_returns_interfaces(self) -> None:
        provider = MockNetworkProvider()
        interfaces = provider.get_interfaces()
        self.assertGreaterEqual(len(interfaces), 2)

        names = [iface.name for iface in interfaces]
        self.assertIn("lo", names)
        self.assertIn("eth0", names)

    def test_inspector_mock_mode(self) -> None:
        inspector = NetworkInspector(use_mock=True)
        interfaces = inspector.list_interfaces()
        self.assertTrue(any(i.interface_type == InterfaceType.LOOPBACK for i in interfaces))


if __name__ == "__main__":
    unittest.main()
