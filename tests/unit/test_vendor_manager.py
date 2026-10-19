"""Unit tests for Multi-Vendor Hardware & IP Surveillance Camera manager."""

from __future__ import annotations

import json
import threading
import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.vendor_manager import (
    CameraTelemetry,
    DeviceCategory,
    DeviceSecurityStatus,
    DiscoveryMode,
    DiscoveryStatus,
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
        self._lock = threading.Lock()
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
        with self._lock:
            self.packets_queue.append((data, cmsg, 0, (sender_ip, sender_port)))

    def recvmsg(self, bufsize, ancbufsize=1024):
        with self._lock:
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
        readable = []
        for s in rlist:
            lock = getattr(s, "_lock", None)
            if lock:
                with lock:
                    if getattr(s, "packets_queue", None):
                        readable.append(s)
            else:
                if getattr(s, "packets_queue", None):
                    readable.append(s)
        if not readable and timeout:
            import time
            time.sleep(min(float(timeout), 0.02))
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
                    timeout=0.2,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

        self.assertEqual(report.total_devices, 1)
        dev = report.devices[0]
        self.assertTrue(any("departure" in n.lower() for n in dev.security_notes))
        # Historical evidence preserved
        self.assertTrue(len(dev.evidence) >= 2)

    def test_live_discovery_nonexistent_interface_fails_closed(self) -> None:
        """Requirement: requesting a non-existent interface fails closed with InterfaceConstraintError."""
        from itsa_network_os.network.models import InterfaceConstraintError

        sock_mndp = self.MockDatagramSocket()
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("socket.if_nametoindex", side_effect=OSError("No such device")):
            with self.assertRaises(InterfaceConstraintError):
                VendorManagerEngine.discover_devices(
                    use_mock=False,
                    interface="nonexistent0",
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

    def test_live_discovery_unsupported_pktinfo_fails_closed(self) -> None:
        """Requirement: requesting interface filter when IP_PKTINFO is unsupported fails closed."""
        from itsa_network_os.network.models import InterfaceConstraintError

        sock_mndp = self.MockDatagramSocket()
        sock_mndp.fail_pktinfo = True
        sock_onvif = self.MockDatagramSocket()

        from unittest.mock import patch
        with patch("socket.if_nametoindex", return_value=1):
            with self.assertRaises(InterfaceConstraintError):
                VendorManagerEngine.discover_devices(
                    use_mock=False,
                    interface="eth0",
                    timeout=0.1,
                    mndp_socket_factory=lambda *a, **k: sock_mndp,
                    onvif_socket_factory=lambda *a, **k: sock_onvif,
                )

class TestVendorDiscoveryReportProvenance(unittest.TestCase):
    """Test suite for canonical discovery provenance, status tracking, and serialization (TASK-010A)."""

    def test_discovery_mode_and_status_enum_values(self) -> None:
        """Requirement: DiscoveryMode and DiscoveryStatus enums expose expected values."""
        self.assertEqual(DiscoveryMode.LIVE_PASSIVE.value, "live_passive")
        self.assertEqual(DiscoveryMode.MOCK.value, "mock")
        self.assertEqual(DiscoveryStatus.COMPLETED.value, "completed")
        self.assertEqual(DiscoveryStatus.FAILED.value, "failed")
        self.assertEqual(DiscoveryStatus.CANCELLED.value, "cancelled")
        self.assertEqual(DiscoveryStatus.TIMED_OUT.value, "timed_out")

    def test_default_construction_defaults_to_mock_provenance(self) -> None:
        """Requirement: Default report construction without explicit mode defaults to MOCK, never live."""
        report = VendorDiscoveryReport(
            total_devices=0,
            category_counts={},
            devices=[],
            vulnerable_device_count=0,
        )
        self.assertEqual(report.mode, DiscoveryMode.MOCK)
        self.assertEqual(report.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(report.is_mock)
        self.assertFalse(report.is_live)
        self.assertIsNone(report.error_message)

    def test_derived_provenance_properties_are_consistent_and_readonly(self) -> None:
        """Requirement: is_live and is_mock are strictly derived from mode and are read-only."""
        live_report = VendorDiscoveryReport(
            total_devices=0,
            category_counts={},
            devices=[],
            vulnerable_device_count=0,
            mode=DiscoveryMode.LIVE_PASSIVE,
            status=DiscoveryStatus.COMPLETED,
        )
        self.assertTrue(live_report.is_live)
        self.assertFalse(live_report.is_mock)

        # Confirm properties are read-only
        with self.assertRaises(AttributeError):
            live_report.is_live = False  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            live_report.is_mock = True  # type: ignore[misc]

        mock_report = VendorDiscoveryReport(
            total_devices=0,
            category_counts={},
            devices=[],
            vulnerable_device_count=0,
            mode=DiscoveryMode.MOCK,
            status=DiscoveryStatus.COMPLETED,
        )
        self.assertFalse(mock_report.is_live)
        self.assertTrue(mock_report.is_mock)

    def test_string_mode_and_status_normalized_to_enum(self) -> None:
        """Requirement: String values for mode and status are normalized to valid enums."""
        rep = VendorDiscoveryReport(
            total_devices=0,
            category_counts={},
            devices=[],
            vulnerable_device_count=0,
            mode="live_passive",  # type: ignore[arg-type]
            status="failed",      # type: ignore[arg-type]
            error_message="Connection timed out",
        )
        self.assertIs(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertIs(rep.status, DiscoveryStatus.FAILED)
        self.assertEqual(rep.error_message, "Connection timed out")

    def test_invalid_mode_or_status_rejected(self) -> None:
        """Requirement: Invalid mode or status strings/types raise ValueError or TypeError."""
        with self.assertRaises(ValueError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                mode="active_scan",  # type: ignore[arg-type]
            )

        with self.assertRaises(TypeError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                mode=123,  # type: ignore[arg-type]
            )

        with self.assertRaises(ValueError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                status="unknown_status",  # type: ignore[arg-type]
            )

        with self.assertRaises(TypeError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                status=False,  # type: ignore[arg-type]
            )

        with self.assertRaises(TypeError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                error_message=999,  # type: ignore[arg-type]
            )

    def test_unexpected_provenance_kwargs_rejected_by_constructor(self) -> None:
        """Requirement: Attempting to pass contradictory kwargs like is_live or is_mock raises TypeError."""
        with self.assertRaises(TypeError):
            VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                mode=DiscoveryMode.MOCK,
                is_live=True,  # type: ignore[call-arg]
            )

    def test_serialization_preserves_existing_keys_and_adds_provenance(self) -> None:
        """Requirement: to_dict() preserves existing fields and types while adding JSON-safe provenance."""
        rep = VendorDiscoveryReport(
            total_devices=0,
            category_counts={"IP Camera / CCTV": 0},
            devices=[],
            vulnerable_device_count=0,
            mode=DiscoveryMode.LIVE_PASSIVE,
            status=DiscoveryStatus.COMPLETED,
            error_message=None,
        )
        d = rep.to_dict()

        # Existing keys and types
        self.assertEqual(d["total_devices"], 0)
        self.assertEqual(d["category_counts"], {"IP Camera / CCTV": 0})
        self.assertEqual(d["devices"], [])
        self.assertEqual(d["vulnerable_device_count"], 0)

        # New provenance keys and types
        self.assertEqual(d["mode"], "live_passive")
        self.assertEqual(d["status"], "completed")
        self.assertIs(d["is_live"], True)
        self.assertIs(d["is_mock"], False)
        self.assertIsNone(d["error_message"])

        # JSON serializability check
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["mode"], "live_passive")
        self.assertEqual(parsed["status"], "completed")
        self.assertTrue(parsed["is_live"])
        self.assertFalse(parsed["is_mock"])

    def test_engine_discover_devices_attaches_correct_mode(self) -> None:
        """Requirement: VendorManagerEngine.discover_devices attaches MOCK or LIVE_PASSIVE mode."""
        mock_rep = VendorManagerEngine.discover_devices(use_mock=True)
        self.assertEqual(mock_rep.mode, DiscoveryMode.MOCK)
        self.assertEqual(mock_rep.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(mock_rep.is_mock)
        self.assertFalse(mock_rep.is_live)
        self.assertIsNone(mock_rep.error_message)

        # Offline silent network live discovery
        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            live_rep = VendorManagerEngine.discover_devices(
                use_mock=False,
                timeout=0.1,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
        self.assertEqual(live_rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertEqual(live_rep.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(live_rep.is_live)
        self.assertFalse(live_rep.is_mock)
        self.assertEqual(live_rep.total_devices, 0)


class TestVendorDiscoveryServiceAndOperationalCorrectness(unittest.TestCase):
    """Test suite for service and vendor-manager operational correctness (TASK-010B)."""

    def setUp(self) -> None:
        from itsa_network_os.network.mndp import build_mndp_test_packet
        from itsa_network_os.network.onvif import build_ws_discovery_test_xml

        self.mndp_pkt = build_mndp_test_packet(
            mac="48:8F:5A:99:88:77",
            board_name="RB5009UG+S+IN",
            version="7.15",
            identity="EdgeGateway",
            ipv4="192.168.10.1",
        )
        self.onvif_xml = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:12345678-1234-5678-1234-567812345678",
            hardware_model="IPC-HFW4431R-Z",
            xaddr="http://192.168.10.50:80/onvif/device_service",
        )

    def test_explicit_mock_mode_produces_only_mock_fixtures_and_truthful_provenance(self) -> None:
        """Requirement: Explicit mock mode produces only mock fixtures with mock provenance."""
        # Using enum
        rep1 = VendorManagerEngine.discover_devices(mode=DiscoveryMode.MOCK)
        self.assertEqual(rep1.mode, DiscoveryMode.MOCK)
        self.assertEqual(rep1.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(rep1.is_mock)
        self.assertFalse(rep1.is_live)
        self.assertEqual(rep1.total_devices, 8)
        self.assertEqual(len(rep1.devices), 8)
        self.assertIsNone(rep1.error_message)

        # Using string
        rep2 = VendorManagerEngine.discover_devices(mode="mock")
        self.assertEqual(rep2.mode, DiscoveryMode.MOCK)
        self.assertEqual(rep2.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(rep2.is_mock)
        self.assertFalse(rep2.is_live)

    def test_explicit_live_mode_produces_no_mock_fixtures(self) -> None:
        """Requirement: Explicit live mode produces zero mock fixtures."""
        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            rep = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )

        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertEqual(rep.status, DiscoveryStatus.COMPLETED)
        self.assertTrue(rep.is_live)
        self.assertFalse(rep.is_mock)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertIsNone(rep.error_message)

    def test_successful_empty_live_discovery_remains_empty_and_completed(self) -> None:
        """Requirement: Successful live discovery on quiet network returns empty completed report."""
        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            rep = VendorManagerEngine.discover_devices(
                use_mock=False,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )

        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertEqual(rep.status, DiscoveryStatus.COMPLETED)
        self.assertEqual(rep.devices, [])
        self.assertEqual(rep.total_devices, 0)
        self.assertTrue(rep.is_live)
        self.assertFalse(rep.is_mock)
        self.assertIsNone(rep.error_message)

    def test_worker_exception_both_listeners_fail_reported_as_failed(self) -> None:
        """Requirement: When both listeners encounter worker exceptions, status is FAILED."""
        def failing_mndp_factory(*a, **k):
            raise OSError(98, "Address already in use")

        def failing_onvif_factory(*a, **k):
            raise PermissionError(13, "Permission denied")

        rep = VendorManagerEngine.discover_devices(
            mode=DiscoveryMode.LIVE_PASSIVE,
            timeout=0.05,
            mndp_socket_factory=failing_mndp_factory,
            onvif_socket_factory=failing_onvif_factory,
        )

        self.assertEqual(rep.status, DiscoveryStatus.FAILED)
        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertTrue(rep.is_live)
        self.assertFalse(rep.is_mock)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertIsNotNone(rep.error_message)
        self.assertIn("Both discovery listeners failed", rep.error_message or "")
        self.assertIn("MNDP", rep.error_message or "")
        self.assertIn("ONVIF", rep.error_message or "")

    def test_one_listener_fails_and_other_succeeds_empty_reported_as_partial(self) -> None:
        """Requirement: One listener failure with other completing empty returns PARTIAL status."""
        def failing_mndp_factory(*a, **k):
            raise OSError(98, "Address already in use")

        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            rep = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=failing_mndp_factory,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )

        self.assertEqual(rep.status, DiscoveryStatus.PARTIAL)
        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertTrue(rep.is_live)
        self.assertFalse(rep.is_mock)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertIsNotNone(rep.error_message)
        self.assertIn("MNDP listener failed", rep.error_message or "")
        self.assertIn("ONVIF listener completed normally", rep.error_message or "")

    def test_one_listener_fails_and_other_succeeds_with_devices_reported_as_partial(self) -> None:
        """Requirement: One listener failure preserves valid observations from the healthy listener."""
        sock_mndp = MockDatagramSocket()
        sock_mndp.queue_packet(self.mndp_pkt, sender_ip="192.168.10.1", sender_port=5678)

        def failing_onvif_factory(*a, **k):
            raise OSError(105, "No buffer space available")

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            rep = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=failing_onvif_factory,
            )

        self.assertEqual(rep.status, DiscoveryStatus.PARTIAL)
        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertTrue(rep.is_live)
        self.assertFalse(rep.is_mock)
        self.assertEqual(rep.total_devices, 1)
        self.assertEqual(len(rep.devices), 1)
        self.assertEqual(rep.devices[0].category, DeviceCategory.MIKROTIK)
        self.assertIsNotNone(rep.error_message)
        self.assertIn("ONVIF listener failed", rep.error_message or "")
        self.assertIn("MNDP listener completed normally", rep.error_message or "")

    def test_socket_binding_error_reported_truthfully(self) -> None:
        """Requirement: Socket binding exceptions are not swallowed into quiet network."""
        class FailingBindSocket(MockDatagramSocket):
            def bind(self, addr):
                raise OSError(98, "Address already in use")

        sock_mndp = FailingBindSocket()
        sock_onvif = FailingBindSocket()

        rep = VendorManagerEngine.discover_devices(
            mode=DiscoveryMode.LIVE_PASSIVE,
            timeout=0.05,
            mndp_socket_factory=lambda *a, **k: sock_mndp,
            onvif_socket_factory=lambda *a, **k: sock_onvif,
        )

        self.assertEqual(rep.status, DiscoveryStatus.FAILED)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertIn("Address already in use", rep.error_message or "")

    def test_cancellation_reported_as_cancelled(self) -> None:
        """Requirement: Explicit cancellation via stop_event produces CANCELLED status."""
        stop_event = threading.Event()
        stop_event.set()

        rep = VendorManagerEngine.discover_devices(
            mode=DiscoveryMode.LIVE_PASSIVE,
            stop_event=stop_event,
        )

        self.assertEqual(rep.status, DiscoveryStatus.CANCELLED)
        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertEqual(rep.error_message, "Discovery operation was cancelled")

    def test_timeout_status_distinguishable(self) -> None:
        """Requirement: Worker join timeout produces TIMED_OUT status."""
        from unittest.mock import patch
        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        # Simulate worker thread remaining alive after join timeout
        with patch.object(threading.Thread, "is_alive", return_value=True):
            rep = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.01,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )

        self.assertEqual(rep.status, DiscoveryStatus.TIMED_OUT)
        self.assertEqual(rep.mode, DiscoveryMode.LIVE_PASSIVE)
        self.assertEqual(rep.total_devices, 0)
        self.assertEqual(rep.devices, [])
        self.assertIn("timed out", rep.error_message or "")

    def test_interface_constraint_error_preserves_fail_closed(self) -> None:
        """Requirement: Interface constraint errors raise InterfaceConstraintError directly."""
        from itsa_network_os.network.models import InterfaceConstraintError
        from unittest.mock import patch

        with patch("socket.if_nametoindex", side_effect=OSError("No such device")):
            with self.assertRaises(InterfaceConstraintError):
                VendorManagerEngine.discover_devices(
                    mode=DiscoveryMode.LIVE_PASSIVE,
                    interface="nonexistent_dev",
                    timeout=0.05,
                )

    def test_contradictory_mode_and_legacy_flags_rejected_by_engine(self) -> None:
        """Requirement: Contradictory mode and use_mock arguments raise ValueError."""
        with self.assertRaises(ValueError):
            VendorManagerEngine.discover_devices(mode=DiscoveryMode.LIVE_PASSIVE, use_mock=True)

        with self.assertRaises(ValueError):
            VendorManagerEngine.discover_devices(mode=DiscoveryMode.MOCK, use_mock=False)

        with self.assertRaises(ValueError):
            VendorManagerEngine.discover_devices(mode="invalid_mode")

        with self.assertRaises(TypeError):
            VendorManagerEngine.discover_devices(mode=999)  # type: ignore[arg-type]

    def test_contradictory_mode_and_legacy_flags_rejected_by_application(self) -> None:
        """Requirement: Application service layer rejects conflicting mode selections."""
        app = Application(config=AppConfig(database_file=":memory:"))

        with self.assertRaises(ValueError):
            app.discover_vendor_devices(mode=DiscoveryMode.LIVE_PASSIVE, use_mock=True)

        with self.assertRaises(ValueError):
            app.discover_vendor_devices(mode=DiscoveryMode.MOCK, use_mock=False)

        with self.assertRaises(ValueError):
            app.discover_vendor_devices(force_live=True, use_mock=True)

        with self.assertRaises(ValueError):
            app.discover_vendor_devices(force_live=True, mode=DiscoveryMode.MOCK)

        with self.assertRaises(ValueError):
            app.discover_vendor_devices(mode="unsupported_mode")

        with self.assertRaises(TypeError):
            app.discover_vendor_devices(mode=123)  # type: ignore[arg-type]

    def test_vendor_manager_tests_use_isolated_database_configuration(self) -> None:
        """Regression guard (TASK-011D): Ensure vendor manager test configurations are isolated from production DB."""
        from itsa_network_os.core.config import get_default_config

        default_prod_db = get_default_config().database_file

        test_config = AppConfig(database_file=":memory:")
        self.assertNotEqual(test_config.database_file, default_prod_db)
        self.assertEqual(test_config.database_file, ":memory:")

        app = Application(config=test_config)
        self.assertEqual(app.database.db_path, ":memory:")
        self.assertNotEqual(app.database.db_path, default_prod_db)

    def test_application_service_explicit_live_cannot_be_overridden_by_config(self) -> None:
        """Requirement: config.use_mock_network cannot override explicit live discovery request."""
        from itsa_network_os.core.config import AppConfig

        mock_config = AppConfig(use_mock_network=True, database_file=":memory:")
        app = Application(config=mock_config)

        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            # force_live=True overrides config.use_mock_network=True
            rep_force = app.discover_vendor_devices(
                force_live=True,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
            self.assertEqual(rep_force.mode, DiscoveryMode.LIVE_PASSIVE)
            self.assertTrue(rep_force.is_live)
            self.assertFalse(rep_force.is_mock)
            self.assertEqual(rep_force.total_devices, 0)

            # mode=DiscoveryMode.LIVE_PASSIVE overrides config.use_mock_network=True
            rep_mode = app.discover_vendor_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
            self.assertEqual(rep_mode.mode, DiscoveryMode.LIVE_PASSIVE)
            self.assertTrue(rep_mode.is_live)
            self.assertFalse(rep_mode.is_mock)

            # use_mock=False overrides config.use_mock_network=True
            rep_nomock = app.discover_vendor_devices(
                use_mock=False,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
            self.assertEqual(rep_nomock.mode, DiscoveryMode.LIVE_PASSIVE)
            self.assertTrue(rep_nomock.is_live)

        # Default without live request respects config.use_mock_network=True
        rep_default = app.discover_vendor_devices()
        self.assertEqual(rep_default.mode, DiscoveryMode.MOCK)
        self.assertTrue(rep_default.is_mock)
        self.assertFalse(rep_default.is_live)

    def test_report_device_counts_strictly_agree_with_device_list(self) -> None:
        """Requirement: report device counts strictly agree with actual device list."""
        mock_rep = VendorManagerEngine.discover_devices(use_mock=True)
        self.assertEqual(mock_rep.total_devices, len(mock_rep.devices))
        self.assertEqual(sum(mock_rep.category_counts.values()), len(mock_rep.devices))

        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()
        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            empty_rep = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
        self.assertEqual(empty_rep.total_devices, len(empty_rep.devices))
        self.assertEqual(sum(empty_rep.category_counts.values()), len(empty_rep.devices))

    def test_listener_socket_cleanup_on_success_and_failure(self) -> None:
        """Requirement: Sockets are deterministically closed on normal completion and errors."""
        sock_mndp = MockDatagramSocket()
        sock_onvif = MockDatagramSocket()

        from unittest.mock import patch
        with patch("select.select", side_effect=TestLiveVendorDiscovery._mock_select):
            VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=0.05,
                mndp_socket_factory=lambda *a, **k: sock_mndp,
                onvif_socket_factory=lambda *a, **k: sock_onvif,
            )
        self.assertTrue(sock_mndp.closed)
        self.assertTrue(sock_onvif.closed)

        # Now test failure during socket binding
        class FailingSocket(MockDatagramSocket):
            def bind(self, addr):
                raise OSError("Simulated bind failure")

        fail_mndp = FailingSocket()
        fail_onvif = FailingSocket()

        VendorManagerEngine.discover_devices(
            mode=DiscoveryMode.LIVE_PASSIVE,
            timeout=0.05,
            mndp_socket_factory=lambda *a, **k: fail_mndp,
            onvif_socket_factory=lambda *a, **k: fail_onvif,
        )
        self.assertTrue(fail_mndp.closed)
        self.assertTrue(fail_onvif.closed)


if __name__ == "__main__":
    unittest.main()

