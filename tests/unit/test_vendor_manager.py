"""Unit tests for Multi-Vendor Hardware & IP Surveillance Camera manager."""

from __future__ import annotations

import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.vendor_manager import (
    CameraTelemetry,
    DeviceCategory,
    DeviceSecurityStatus,
    ManagedDevice,
    RouterOSTelemetry,
    VendorDiscoveryReport,
    VendorManagerEngine,
    WirelessLinkTelemetry,
)


class TestVendorManager(unittest.TestCase):
    """Test suite for vendor discovery engine, ONVIF/RTSP cameras, and CPE telemetry."""

    def test_mock_devices_population(self) -> None:
        """Verify default mock discovery returns 8 multi-vendor hardware units."""
        report = VendorManagerEngine.discover_devices(use_mock=True)

        self.assertIsInstance(report, VendorDiscoveryReport)
        self.assertEqual(report.total_devices, 8)
        self.assertGreater(report.vulnerable_device_count, 0)

        categories = {d.category for d in report.devices}
        self.assertIn(DeviceCategory.IP_CAMERA, categories)
        self.assertIn(DeviceCategory.MIKROTIK, categories)
        self.assertIn(DeviceCategory.UBIQUITI, categories)
        self.assertIn(DeviceCategory.TPLINK_CPE, categories)
        self.assertIn(DeviceCategory.LINUX_SERVER, categories)

    def test_camera_telemetry(self) -> None:
        """Verify IP surveillance camera telemetry, RTSP URIs, and default credentials."""
        cams = [d for d in VendorManagerEngine.get_mock_devices() if d.category == DeviceCategory.IP_CAMERA]
        self.assertEqual(len(cams), 2)

        hik = next(c for c in cams if c.vendor == "Hikvision")
        self.assertIsNotNone(hik.camera_info)
        assert hik.camera_info is not None
        self.assertIn("rtsp://", hik.camera_info.rtsp_uri)
        self.assertEqual(hik.camera_info.onvif_port, 80)
        self.assertIn("4K", hik.camera_info.resolution)
        self.assertFalse(hik.camera_info.has_default_credentials)

        dahua = next(c for c in cams if c.vendor == "Dahua")
        self.assertIsNotNone(dahua.camera_info)
        assert dahua.camera_info is not None
        self.assertTrue(dahua.camera_info.has_default_credentials)
        self.assertTrue(dahua.camera_info.ptz_supported)
        self.assertEqual(dahua.security_status, DeviceSecurityStatus.WARNING)

    def test_wireless_link_telemetry(self) -> None:
        """Verify outdoor wireless CPE link parameters for Ubiquiti and TP-Link."""
        devices = VendorManagerEngine.get_mock_devices()
        cpes = [d for d in devices if d.wireless_info is not None]
        self.assertEqual(len(cpes), 2)

        ubnt = next(c for c in cpes if c.vendor == "Ubiquiti")
        self.assertIsNotNone(ubnt.wireless_info)
        assert ubnt.wireless_info is not None
        self.assertLess(ubnt.wireless_info.signal_rssi_dbm, -40)
        self.assertGreaterEqual(ubnt.wireless_info.ccq_percent, 95.0)
        self.assertGreater(ubnt.wireless_info.distance_km, 1.0)
        self.assertIn("PtP", ubnt.wireless_info.wireless_mode)

        tpl = next(c for c in cpes if c.vendor == "TP-Link")
        self.assertIsNotNone(tpl.wireless_info)
        assert tpl.wireless_info is not None
        self.assertEqual(tpl.model, "Pharos CPE510 v3.20")
        self.assertIn("Station", tpl.wireless_info.wireless_mode)

    def test_mikrotik_routeros_telemetry(self) -> None:
        """Verify MikroTik RouterBOARD and RouterOS system metrics."""
        devices = VendorManagerEngine.get_mock_devices()
        miks = [d for d in devices if d.category == DeviceCategory.MIKROTIK]
        self.assertEqual(len(miks), 2)

        hex_s = next(m for m in miks if m.device_id == "MIK-01")
        self.assertIsNotNone(hex_s.router_info)
        assert hex_s.router_info is not None
        self.assertEqual(hex_s.router_info.board_name, "RB760iGS")
        self.assertGreater(hex_s.router_info.cpu_load_percent, 0)
        self.assertGreater(hex_s.router_info.free_memory_mb, 100.0)
        self.assertIn("MNDP", hex_s.discovery_protocol)

    def test_category_filtering(self) -> None:
        """Verify filtering by specific hardware vendor category."""
        report_cams = VendorManagerEngine.discover_devices(category_filter=DeviceCategory.IP_CAMERA)
        self.assertEqual(report_cams.total_devices, 2)
        for d in report_cams.devices:
            self.assertEqual(d.category, DeviceCategory.IP_CAMERA)

        report_mik = VendorManagerEngine.discover_devices(category_filter=DeviceCategory.MIKROTIK)
        self.assertEqual(report_mik.total_devices, 2)
        for d in report_mik.devices:
            self.assertEqual(d.category, DeviceCategory.MIKROTIK)

    def test_application_service_dispatch(self) -> None:
        """Verify Application service layer filters vendor discovery cleanly."""
        app = Application(config=AppConfig(database_file=":memory:"))

        rep_all = app.discover_vendor_devices()
        self.assertEqual(rep_all.total_devices, 8)

        rep_cams = app.discover_vendor_devices(category="cams")
        self.assertEqual(rep_cams.total_devices, 2)

        rep_mik = app.discover_vendor_devices(category="mikrotik")
        self.assertEqual(rep_mik.total_devices, 2)

        rep_ubnt = app.discover_vendor_devices(category="ubiquiti")
        self.assertEqual(rep_ubnt.total_devices, 2)

    def test_serialization(self) -> None:
        """Verify JSON serializability of VendorDiscoveryReport."""
        rep = VendorManagerEngine.discover_devices()
        data = rep.to_dict()

        self.assertEqual(data["total_devices"], 8)
        self.assertIsInstance(data["devices"], list)
        self.assertIn("category_counts", data)
        self.assertIn("camera_info", data["devices"][0])


if __name__ == "__main__":
    unittest.main()
