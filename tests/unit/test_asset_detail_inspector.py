"""Unit tests for reusable AssetDetailInspector component."""

import unittest

try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.core.assets import (
    AssetCategory,
    AssetIdentity,
    AttributeHistory,
    AttributeObservation,
    EntityStatus,
    IPBindingRecord,
    NetworkAsset,
    PhysicalPort,
    TelemetryCategory,
)
from itsa_network_os.network.models import EvidenceProtocol, EvidenceRecord
from itsa_network_os.ui.desktop.views.asset_detail_inspector import AssetDetailInspector


class TestAssetDetailInspector(unittest.TestCase):
    """Test AssetDetailInspector view binding, provenance rendering, and secret scrubbing."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for inspector tests")
        self.inspector = AssetDetailInspector()

    def test_inspect_none_asset(self) -> None:
        self.inspector.inspect_asset(None)
        self.assertEqual(self.inspector.lbl_title.text(), "(No Asset Selected)")
        self.assertEqual(self.inspector.ports_table.rowCount(), 0)
        self.assertEqual(self.inspector.ip_table.rowCount(), 0)
        self.assertEqual(self.inspector.evidence_table.rowCount(), 0)
        self.assertFalse(self.inspector.conflict_banner.isVisible())

    def test_inspect_populated_asset(self) -> None:
        identity = AssetIdentity(
            system_name="EdgeRouter-X",
            primary_mac="00:11:22:33:44:55",
            confidence=0.95,
            vendor_guess="Ubiquiti",
            model_guess="ER-X",
        )
        asset = NetworkAsset(
            identity=identity,
            category=AssetCategory.ROUTER,
            vendor="Ubiquiti",
            model="EdgeRouter X",
            firmware_version="v2.0.9",
            status=EntityStatus.ONLINE,
            management_ips=["192.168.1.1"],
        )
        port = PhysicalPort(port_id="eth0", name="eth0", speed_mbps=1000, is_up=True)
        asset.add_port(port)

        asset.bind_ip("192.168.1.1", interface_name="eth0")

        self.inspector.inspect_asset(asset)

        self.assertEqual(self.inspector.lbl_title.text(), "EdgeRouter-X")
        self.assertEqual(self.inspector.identity_fields["lbl_vendor"].text(), "Ubiquiti")
        self.assertEqual(self.inspector.identity_fields["lbl_mac"].text(), "00:11:22:33:44:55")
        self.assertIn("192.168.1.1", self.inspector.identity_fields["lbl_ips"].text())
        self.assertEqual(self.inspector.ports_table.rowCount(), 1)
        self.assertEqual(self.inspector.ip_table.rowCount(), 1)
        self.assertEqual(self.inspector.lbl_status_badge.text(), "ONLINE")
        self.assertIn("95%", self.inspector.lbl_confidence_badge.text())

    def test_conflict_detection_and_redaction(self) -> None:
        identity = AssetIdentity(system_name="CoreSwitch")
        asset = NetworkAsset(identity=identity, category=AssetCategory.SWITCH)

        ev1 = EvidenceRecord(
            source_protocol=EvidenceProtocol.MNDP,
            timestamp="2026-10-29T10:00:00Z",
            confidence=0.9,
            is_verified_fact=True,
            attribute="snmp_community",
        )
        ev2 = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp="2026-10-29T10:05:00Z",
            confidence=0.8,
            is_verified_fact=False,
            attribute="snmp_community",
        )

        # Record conflicting secret values
        asset.record_observation("snmp_community", "secret-comm-1", ev1)
        asset.record_observation("snmp_community", "secret-comm-2", ev2)

        self.assertTrue(asset.has_attribute_conflict("snmp_community"))

        self.inspector.inspect_asset(asset)

        # Conflict banner should be displayed (not hidden)
        self.assertFalse(self.inspector.conflict_banner.isHidden())
        self.assertIn("Conflicting observations", self.inspector.conflict_banner.text())

        # Evidence table should redact secrets
        self.assertGreater(self.inspector.evidence_table.rowCount(), 0)
        table_text = " ".join(
            self.inspector.evidence_table.item(row, 1).text()
            for row in range(self.inspector.evidence_table.rowCount())
        )
        self.assertNotIn("secret-comm-1", table_text)
        self.assertNotIn("secret-comm-2", table_text)
        self.assertIn("***REDACTED***", table_text)


if __name__ == "__main__":
    unittest.main()
