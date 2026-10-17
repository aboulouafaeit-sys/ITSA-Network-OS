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

            self.assertEqual(window.pages_stack.count(), 8)
            self.assertIn("ITSA Network OS", window.windowTitle())

            # Test subnet calculate trigger in GUI
            window.subnet_input.setText("10.0.0.0/24")
            window._on_calculate_subnet()
            self.assertEqual(window.subnet_status_label.text(), "")

            # Test packet lab selection
            window._on_packet_selected(0)
            self.assertGreater(window.lab_table.rowCount(), 0)

        except ImportError:
            self.skipTest("PySide6 not available for GUI test")


if __name__ == "__main__":
    unittest.main()
