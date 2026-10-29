"""Unit tests for desktop GUI components."""

import os
import sys
import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig


class TestDesktopGUI(unittest.TestCase):
    """Test desktop UI instantiation and widget controllers."""

    @classmethod
    def setUpClass(cls) -> None:
        os.environ["QT_QPA_PLATFORM"] = "offscreen"

    def test_pyside6_availability(self) -> None:
        try:
            import PySide6
            self.assertTrue(hasattr(PySide6, "__version__"))
        except ImportError:
            self.skipTest("PySide6 not installed in current test runner")

    def test_main_window_instantiation_offscreen(self) -> None:
        try:
            from PySide6.QtWidgets import QApplication
            from itsa_network_os.ui.desktop.app_window import MainWindow

            qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
            app = Application(config=AppConfig(database_file=":memory:"))
            window = MainWindow(app)

            self.assertEqual(window.pages_stack.count(), 14)
            self.assertIn("ITSA Network OS", window.windowTitle())

            # Test subnet calculate trigger in GUI
            window.subnet_input.setText("10.0.0.0/24")
            window._on_calculate_subnet()
            self.assertEqual(window.subnet_status_label.text(), "")

            # Test packet lab selection
            window._on_packet_selected(0)
            self.assertGreater(window.lab_table.rowCount(), 0)

            # Test topology widget on page 8
            self.assertTrue(hasattr(window, "topo_widget"))
            self.assertGreater(len(window.topo_widget.scene.items()), 0)

            # Test Wi-Fi spectrum widget on page 9 (index 9)
            self.assertTrue(hasattr(window, "wifi_widget"))
            self.assertGreater(window.wifi_widget.ap_table.rowCount(), 0)
            self.assertIsNotNone(window.wifi_widget.spectrum_graph)

            # Test Bandwidth widget on page 10 (index 10)
            self.assertTrue(hasattr(window, "bandwidth_widget"))
            self.assertGreater(window.bandwidth_widget.rates_table.rowCount(), 0)
            self.assertIsNotNone(window.bandwidth_widget.graph_widget)
            window.bandwidth_widget.timer.stop()

            # Test TLS Inspector widget on page 11 (index 11)
            self.assertTrue(hasattr(window, "tls_widget"))
            self.assertIsNotNone(window.tls_widget.current_report)
            self.assertGreater(window.tls_widget.findings_table.rowCount(), 0)
            window.tls_widget.inspect_target("legacy.internal", 443)
            self.assertEqual(window.tls_widget.current_report.negotiated_protocol, "TLSv1.0")

            # Test OSPF SPF Simulator widget on page 12 (index 12)
            self.assertTrue(hasattr(window, "spf_widget"))
            self.assertIsNotNone(window.spf_widget.current_result)
            self.assertGreater(window.spf_widget.table_routes.rowCount(), 0)
            window.spf_widget.run_simulation("R2", "R2-R4")
            self.assertEqual(window.spf_widget.current_result.source_router, "R2")
            self.assertEqual(window.spf_widget.current_result.failed_link_id, "R2-R4")

            # Test Multi-Vendor & Cameras widget on page 13 (index 13)
            self.assertTrue(hasattr(window, "vendor_widget"))
            self.assertGreater(len(window.vendor_widget.all_devices), 0)
            self.assertGreater(window.vendor_widget.devices_table.rowCount(), 0)
            window.vendor_widget._on_filter_clicked(None)
            self.assertEqual(len(window.vendor_widget.current_filtered_devices), 8)

        except ImportError:
            self.skipTest("PySide6 not available for GUI test")

    def test_vendor_widget_provenance_and_mode_selection(self) -> None:
        """Verify GUI displays clear provenance badges, handles quiet network, and refuses mock fallback on error."""
        try:
            from unittest.mock import patch
            from PySide6.QtWidgets import QApplication
            from itsa_network_os.network.vendor_manager import (
                DiscoveryMode,
                DiscoveryStatus,
                VendorDiscoveryReport,
            )
            from itsa_network_os.ui.desktop.vendor_canvas import VendorDeviceManagerWidget

            qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
            app = Application(config=AppConfig(database_file=":memory:"))
            widget = VendorDeviceManagerWidget(app=app)

            # 1. Initial State: Explicit Mock Mode
            self.assertIsNotNone(widget.current_report)
            self.assertTrue(widget.current_report.is_mock)
            self.assertFalse(widget.current_report.is_live)
            self.assertIn("OFFLINE MOCK / SIMULATED FIXTURES", widget.lbl_provenance_badge.text())
            self.assertIn("simulated lab fixtures", widget.status_banner.text())
            self.assertEqual(widget.devices_table.rowCount(), 8)

            # 2. Explicit User Action: Live Discovery on Quiet Network
            quiet_report = VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                mode=DiscoveryMode.LIVE_PASSIVE,
                status=DiscoveryStatus.COMPLETED,
            )
            with patch.object(app, "discover_vendor_devices", return_value=quiet_report) as mock_disc:
                widget.btn_live_scan.click()
                for _ in range(50):
                    if widget.btn_live_scan.isEnabled():
                        break
                    qt_app.processEvents()
                    import time
                    time.sleep(0.01)
                mock_disc.assert_called_once_with(mode=DiscoveryMode.LIVE_PASSIVE, timeout=5.0)

            self.assertIn("LIVE PASSIVE (QUIET NETWORK - 0 DEVICES)", widget.lbl_provenance_badge.text())
            self.assertIn("Zero devices observed", widget.status_banner.text())
            self.assertIn("This does NOT claim that the network contains no devices", widget.status_banner.text())
            self.assertEqual(widget.devices_table.rowCount(), 0)
            self.assertFalse(widget.current_report.is_mock)
            self.assertTrue(widget.current_report.is_live)

            # 3. Live Discovery Failure: Refuse silent mock fallback
            failed_report = VendorDiscoveryReport(
                total_devices=0,
                category_counts={},
                devices=[],
                vulnerable_device_count=0,
                mode=DiscoveryMode.LIVE_PASSIVE,
                status=DiscoveryStatus.FAILED,
                error_message="Socket permission denied: need CAP_NET_RAW",
            )
            with patch.object(app, "discover_vendor_devices", return_value=failed_report):
                widget.btn_live_scan.click()
                for _ in range(50):
                    if widget.btn_live_scan.isEnabled():
                        break
                    qt_app.processEvents()
                    import time
                    time.sleep(0.01)

            self.assertIn("LIVE DISCOVERY FAILED", widget.lbl_provenance_badge.text())
            self.assertIn("Socket permission denied", widget.status_banner.text())
            self.assertEqual(widget.devices_table.rowCount(), 0)
            self.assertFalse(widget.current_report.is_mock)

            # 4. Return to Mock Fixtures explicitly
            widget.btn_mock.click()
            self.assertIn("OFFLINE MOCK / SIMULATED FIXTURES", widget.lbl_provenance_badge.text())
            self.assertIn("simulated lab fixtures", widget.status_banner.text())
            self.assertEqual(widget.devices_table.rowCount(), 8)
            self.assertTrue(widget.current_report.is_mock)

        except ImportError:
            self.skipTest("PySide6 not available for GUI test")

    def test_vendor_widget_no_auto_live_discovery_on_open(self) -> None:
        """Verify opening/rendering the GUI does NOT trigger live network discovery."""
        try:
            from unittest.mock import patch
            from PySide6.QtWidgets import QApplication
            from itsa_network_os.network.vendor_manager import DiscoveryMode
            from itsa_network_os.ui.desktop.vendor_canvas import VendorDeviceManagerWidget

            qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
            app = Application(config=AppConfig(database_file=":memory:"))

            with patch.object(app, "discover_vendor_devices") as mock_disc:
                widget = VendorDeviceManagerWidget(app=app)
                # Verify live discovery was NOT called on widget initialization
                for call_args in mock_disc.call_args_list:
                    self.assertNotEqual(
                        call_args.kwargs.get("mode"),
                        DiscoveryMode.LIVE_PASSIVE,
                        "Live discovery was automatically triggered on widget instantiation!",
                    )

        except ImportError:
            self.skipTest("PySide6 not available for GUI test")


if __name__ == "__main__":
    unittest.main()
