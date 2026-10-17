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


if __name__ == "__main__":
    unittest.main()
