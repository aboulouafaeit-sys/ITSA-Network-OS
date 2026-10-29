import time
import unittest

try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.ui.desktop.app_window import MainWindow


class TestShellIntegration(unittest.TestCase):
    """Test MainWindow shell header, global search routing, tabs, and accessible views."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for shell integration tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))
        self.window = MainWindow(self.app)

    def tearDown(self) -> None:
        if hasattr(self, "window") and self.window:
            self.window.close()

    def test_shell_header_presence(self) -> None:
        self.assertTrue(hasattr(self.window, "header"))
        self.assertTrue(hasattr(self.window, "global_search_input"))
        self.assertTrue(hasattr(self.window, "scope_badge"))
        self.assertTrue(hasattr(self.window, "health_badge"))
        self.assertIn("Scope:", self.window.scope_badge.text())
        # Truthful asynchronous health check (TASK-P4-03)
        for _ in range(50):
            if any(st in self.window.health_badge.text() for st in ["HEALTHY", "WARNING"]):
                break
            if self.qt_app:
                self.qt_app.processEvents()
            time.sleep(0.01)
        self.assertTrue(any(st in self.window.health_badge.text() for st in ["CHECKING", "HEALTHY", "WARNING"]))

    def test_global_search_routing(self) -> None:
        # Type in the global search bar
        self.window.global_search_input.setText("camera")

        # Verify query was routed to inventory view
        self.assertEqual(self.window.inventory_view.search_input.text(), "camera")
        # Verify view switched to Page 2 (index 2) and inventory tab (index 1)
        self.assertEqual(self.window.sidebar.currentRow(), 2)
        self.assertEqual(self.window.interfaces_tabs.currentIndex(), 1)

    def test_interfaces_and_inventory_tabs(self) -> None:
        self.assertEqual(self.window.interfaces_tabs.count(), 2)
        self.assertIn("Local Network Interfaces", self.window.interfaces_tabs.tabText(0))
        self.assertIn("Unified Asset Inventory", self.window.interfaces_tabs.tabText(1))

    def test_status_bar(self) -> None:
        sb = self.window.statusBar()
        self.assertIsNotNone(sb)
        self.assertIn("ITSA Network OS", sb.currentMessage())

    def test_accessible_names_across_views(self) -> None:
        self.assertTrue(bool(self.window.sidebar.accessibleName()))
        self.assertTrue(bool(self.window.subnet_view.accessibleName()))
        self.assertTrue(bool(self.window.interfaces_view.accessibleName()))
        self.assertTrue(bool(self.window.inventory_view.accessibleName()))
        self.assertTrue(bool(self.window.dns_view.accessibleName()))
        self.assertTrue(bool(self.window.latency_view.accessibleName()))
        self.assertTrue(bool(self.window.audit_view.accessibleName()))
        self.assertTrue(bool(self.window.lab_view.accessibleName()))
        self.assertTrue(bool(self.window.routes_view.accessibleName()))


if __name__ == "__main__":
    unittest.main()
