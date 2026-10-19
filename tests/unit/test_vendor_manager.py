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


class MockDatagramSocket:
    """Mock socket implementing recvmsg and setsockopt for deterministic testing."""

    def __init__(self, *args, **kwargs):
        self.closed = False
        self.bound_addr = None
        self.sockopts = {}
        self.packets_queue = []
        self.fail_pktinfo = False

    def fileno(self):
        return 42

    def setblocking(self, flag):
        pass

    def settimeout(self, timeout):
        pass

    def close(self):
        self.closed = True

    def bind(self, addr):
        self.bound_addr = addr

    def setsockopt(self, level, optname, val):
        import socket
        if self.fail_pktinfo and level == socket.IPPROTO_IP and optname == getattr(socket, "IP_PKTINFO", 8):
            raise OSError("IP_PKTINFO not supported on this platform")
        self.sockopts[(level, optname)] = val

    def queue_packet(self, data: bytes, sender_ip: str, sender_port: int, ifindex: int = 1):
        """Queue a datagram to be returned by recvmsg."""
        import socket
        import struct
        cmsg = [(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), struct.pack("iii", ifindex, 0, 0))]
        self.packets_queue.append((data, cmsg, 0, (sender_ip, sender_port)))

    def recvmsg(self, bufsize, ancbufsize=1024):
        if self.packets_queue:
            return self.packets_queue.pop(0)
        raise BlockingIOError("No packets available")


class TestLiveVendorDiscovery(unittest.TestCase):
    """Integration test suite for live passive broadcast discovery (TASK-009)."""

    def setUp(self) -> None:
        from itsa_network_os.network.mndp import build_mndp_test_packet
        from itsa_network_os.network.onvif import build_ws_discovery_test_xml

        self.MockDatagramSocket = MockDatagramSocket
        self.mndp_pkt = build_mndp_test_packet(
            mac="48:8F:5A:11:22:33",
            board_name="RB760iGS",
            version="7.14.3",
            identity="CoreRouter",
            ipv4="192.168.88.1",
        )
        self.onvif_xml_hello = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
            hardware_model="DS-2CD2042WD-I",
            xaddr="http://192.168.1.108:80/onvif/device_service",
        )
        self.onvif_xml_bye = build_ws_discovery_test_xml(
            message_type="Bye",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
            hardware_model="DS-2CD2042WD-I",
        )

    @staticmethod
    def _mock_select(rlist, wlist, xlist, timeout):
        readable = [s for s in rlist if getattr(s, "packets_queue", None)]
        return (readable, [], [])

    def test_live_discovery_silent_network_returns_zero_devices(self) -> None:
        """Requirement: live scan on silent network returns total_devices == 0, never mock fallback."""
        sock_mndp = self.MockDatagramSocket()
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            report = VendorManagerEngine.discover_devices(
                use_mock=False,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )

        self.assertEqual(report.total_devices, 0)
        self.assertEqual(len(report.devices), 0)
        self.assertEqual(report.vulnerable_device_count, 0)

    def test_live_discovery_with_mndp_observation(self) -> None:
        """Requirement: live scan parses MNDP datagram and distinguishes facts from claims."""
        sock_mndp = self.MockDatagramSocket()
        sock_mndp.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            with patch("socket.if_indextoname", return_value="eth0"):
                report = VendorManagerEngine.discover_devices(
                    use_mock=False,
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        self.assertEqual(report.total_devices, 1)
        dev = report.devices[0]
        self.assertEqual(dev.category, DeviceCategory.MIKROTIK)
        self.assertEqual(dev.mac_address, "48:8F:5A:11:22:33")
        self.assertEqual(dev.model, "RB760iGS")
        self.assertEqual(dev.name, "CoreRouter")

        # Verify evidence provenance
        self.assertGreater(len(dev.evidence), 0)
        fact_records = [e for e in dev.evidence if e.is_verified_fact]
        claim_records = [e for e in dev.evidence if not e.is_verified_fact]

        # Datagram reception is verified fact (confidence=1.0)
        self.assertTrue(any(f.attribute == "packet_reception" and f.confidence == 1.0 for f in fact_records))

        # Claimed model and firmware are unverified claims (confidence=0.85)
        self.assertTrue(any(c.attribute == "model" and c.confidence == 0.85 for c in claim_records))
        self.assertTrue(any(c.attribute == "firmware_version" and c.confidence == 0.85 for c in claim_records))

    def test_live_discovery_with_onvif_observation(self) -> None:
        """Requirement: live scan parses ONVIF Hello and populates camera telemetry."""
        sock_mndp = self.MockDatagramSocket()
        sock_onvif = self.MockDatagramSocket()
        sock_onvif.queue_packet(self.onvif_xml_hello, sender_ip="192.168.1.108", sender_port=3702, ifindex=1)

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            with patch("socket.if_indextoname", return_value="eth0"):
                report = VendorManagerEngine.discover_devices(
                    use_mock=False,
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        self.assertEqual(report.total_devices, 1)
        dev = report.devices[0]
        self.assertEqual(dev.category, DeviceCategory.IP_CAMERA)
        self.assertIn("DS-2CD2042WD-I", dev.model)
        self.assertIsNotNone(dev.camera_info)
        assert dev.camera_info is not None
        self.assertEqual(dev.camera_info.onvif_port, 80)

        # Verified fact vs claims
        facts = [e for e in dev.evidence if e.is_verified_fact]
        self.assertTrue(len(facts) >= 1)

    def test_live_discovery_deduplication_by_mac(self) -> None:
        """Requirement: duplicate MNDP packets with same MAC address merge into 1 device."""
        sock_mndp = self.MockDatagramSocket()
        sock_mndp.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)
        sock_mndp.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            with patch("socket.if_indextoname", return_value="eth0"):
                report = VendorManagerEngine.discover_devices(
                    use_mock=False,
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        self.assertEqual(report.total_devices, 1)

    def test_live_discovery_scope_guard_rejection(self) -> None:
        """Requirement: ScopeGuard drops observations from unauthorized sender IPs."""
        from itsa_network_os.network.scope import ScopeEnclosure, ScopeGuard

        scope_guard = ScopeGuard(
            enclosure=ScopeEnclosure.from_strings(cidrs="192.168.88.0/24")
        )

        sock_mndp = self.MockDatagramSocket()
        # Packet from unauthorized IP 10.10.10.1
        sock_mndp.queue_packet(self.mndp_pkt, sender_ip="10.10.10.1", sender_port=5678, ifindex=1)
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            with patch("socket.if_indextoname", return_value="eth0"):
                report = VendorManagerEngine.discover_devices(
                    use_mock=False,
                    timeout=0.1,
                    scope_guard=scope_guard,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        # Dropped because 10.10.10.1 is not in 192.168.88.0/24
        self.assertEqual(report.total_devices, 0)

    def test_live_discovery_scope_guard_interface_mismatch_fails_closed(self) -> None:
        """Requirement: requesting an interface not authorized in ScopeEnclosure raises ScopeViolationError."""
        from itsa_network_os.network.scope import ScopeEnclosure, ScopeGuard, ScopeViolationError

        scope_guard = ScopeGuard(
            enclosure=ScopeEnclosure.from_strings(cidrs="192.168.88.0/24", interfaces="eth0")
        )

        with self.assertRaises(ScopeViolationError):
            VendorManagerEngine.discover_devices(
                use_mock=False,
                interface="wlan0",
                scope_guard=scope_guard,
            )

    def test_live_discovery_onvif_bye_lifecycle(self) -> None:
        """Requirement: ONVIF Bye announcement notes departure without losing historical evidence."""
        sock_mndp = self.MockDatagramSocket()
        sock_onvif = self.MockDatagramSocket()
        sock_onvif.queue_packet(self.onvif_xml_hello, sender_ip="192.168.1.108", sender_port=3702, ifindex=1)
        sock_onvif.queue_packet(self.onvif_xml_bye, sender_ip="192.168.1.108", sender_port=3702, ifindex=1)

        from unittest.mock import patch
        with patch("select.select", side_effect=self._mock_select):
            with patch("socket.if_indextoname", return_value="eth0"):
                report = VendorManagerEngine.discover_devices(
                    use_mock=False,
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        self.assertEqual(report.total_devices, 1)
        dev = report.devices[0]
        self.assertTrue(any("departure" in n.lower() for n in dev.security_notes))
        # Historical evidence preserved
        self.assertTrue(len(dev.evidence) >= 2)



if __name__ == "__main__":
    unittest.main()

