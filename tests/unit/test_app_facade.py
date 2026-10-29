"""Unit tests for Application asset facade and domain access methods."""

import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    AssetIdentity,
    EntityStatus,
    NetworkAsset,
)
from itsa_network_os.network.vendor_manager import (
    DeviceCategory,
    DeviceSecurityStatus,
    DiscoveryMode,
    DiscoveryStatus,
    ManagedDevice,
    VendorDiscoveryReport,
)


class TestAppAssetFacade(unittest.TestCase):
    """Test Application asset access, caching, and discovery integration methods."""

    def setUp(self) -> None:
        self.config = AppConfig(database_file=":memory:")
        self.app = Application(config=self.config)

    def test_get_host_asset(self) -> None:
        host = self.app.get_host_asset()
        self.assertIsInstance(host, NetworkAsset)
        self.assertEqual(host.name, "localhost")
        self.assertIn("eth0", host.interfaces)
        self.assertEqual(host.status, EntityStatus.ONLINE)

    def test_get_asset_graph_caching(self) -> None:
        graph1 = self.app.get_asset_graph()
        self.assertIsInstance(graph1, AssetGraph)
        self.assertGreater(len(graph1.assets), 0)

        # Second call returns identical cached instance
        graph2 = self.app.get_asset_graph()
        self.assertIs(graph1, graph2)

        # Refresh returns a fresh graph
        graph3 = self.app.get_asset_graph(refresh=True)
        self.assertIsNot(graph1, graph3)
        self.assertGreater(len(graph3.assets), 0)

    def test_update_asset_graph(self) -> None:
        custom_id = AssetIdentity(system_name="CustomRouter", vendor_guess="Cisco")
        custom_asset = NetworkAsset(identity=custom_id, category=AssetCategory.ROUTER)
        
        self.app.update_asset_graph(custom_asset)
        graph = self.app.get_asset_graph()
        self.assertIn(custom_asset.id, graph.assets)
        self.assertEqual(graph.get_asset(custom_asset.id).name, "CustomRouter")

    def test_integrate_discovery_report(self) -> None:
        dev = ManagedDevice(
            device_id="cam-test-1",
            name="Front Gate Camera",
            category=DeviceCategory.IP_CAMERA,
            vendor="Hikvision",
            model="DS-2CD2042WD-I",
            ip_address="192.168.1.180",
            mac_address="00:12:34:56:78:9a",
            firmware_version="V5.5.0",
            discovery_protocol="ONVIF",
            security_status=DeviceSecurityStatus.SECURE,
        )
        report = VendorDiscoveryReport(
            total_devices=1,
            category_counts={"IP Camera / CCTV": 1},
            devices=[dev],
            vulnerable_device_count=0,
            mode=DiscoveryMode.MOCK,
            status=DiscoveryStatus.COMPLETED,
        )

        added = self.app.integrate_discovery_report(report)
        self.assertEqual(added, 1)

        graph = self.app.get_asset_graph()
        found = graph.find_by_mac("00:12:34:56:78:9a")
        self.assertIsNotNone(found)
        self.assertEqual(found.name, "Front Gate Camera")
        self.assertEqual(found.category, AssetCategory.IP_CAMERA)

    def test_discover_vendor_devices_auto_integrates(self) -> None:
        report = self.app.discover_vendor_devices(mode=DiscoveryMode.MOCK)
        self.assertEqual(report.status, DiscoveryStatus.COMPLETED)

        graph = self.app.get_asset_graph()
        # Mock devices should be in graph
        cams = [a for a in graph.assets.values() if a.category == AssetCategory.IP_CAMERA]
        self.assertGreater(len(cams), 0)


if __name__ == "__main__":
    unittest.main()
