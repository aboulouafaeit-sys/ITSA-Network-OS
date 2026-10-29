"""Unit tests for Phase 4 asynchronous operations, startup decoupling, truthful health, and shutdown lifecycle."""

from __future__ import annotations

import threading
import time
import unittest
from unittest.mock import MagicMock, patch

try:
    from PySide6.QtCore import Qt, QThread
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.core.health import HealthStatus, SystemHealthReport
from itsa_network_os.ui.desktop.app_window import MainWindow
from itsa_network_os.ui.desktop.vendor_canvas import VendorDeviceManagerWidget
from itsa_network_os.ui.desktop.views.asset_inventory_view import AssetInventoryView
from itsa_network_os.ui.desktop.views.dns_view import DNSDiagnosticsView
from itsa_network_os.ui.desktop.views.latency_view import LatencyBenchmarkView
from itsa_network_os.ui.desktop.views.security_audit_view import SecurityAuditView
from itsa_network_os.ui.desktop.wifi_worker import ActiveThreadRegistry
from itsa_network_os.ui.desktop.workers import AsyncOperationWorker, AsyncWorkerRunner


class TestPhase4AsyncOperations(unittest.TestCase):
    """Test asynchronous operation wiring and duplicate click rejection (TASK-P4-01)."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for async view tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))

    def _spin_events(self, iterations: int = 20, delay: float = 0.01) -> None:
        for _ in range(iterations):
            if self.qt_app:
                self.qt_app.processEvents()
            time.sleep(delay)

    def test_dns_view_async_execution_and_duplicate_guard(self) -> None:
        view = DNSDiagnosticsView(self.app)
        self.assertEqual(view.dns_table.rowCount(), 0)

        # Trigger resolution
        view._on_resolve_dns()
        # Verify button is disabled during execution and text changes
        self.assertFalse(view.query_btn.isEnabled())
        self.assertIn("Resolving", view.query_btn.text())

        # Duplicate launch attempt must be rejected
        call_count_before = ActiveThreadRegistry.active_count()
        view._on_resolve_dns()
        self.assertEqual(ActiveThreadRegistry.active_count(), call_count_before)

        # Wait for worker completion
        for _ in range(50):
            if view.query_btn.isEnabled():
                break
            self._spin_events(2, 0.01)

        # Verify button restored and results populated
        self.assertTrue(view.query_btn.isEnabled())
        self.assertIn("Resolve DNS", view.query_btn.text())
        self.assertGreater(view.dns_table.rowCount(), 0)

    def test_dns_view_stale_result_filtering(self) -> None:
        view = DNSDiagnosticsView(self.app)
        view._request_counter = 5
        # Simulate finished signal for older request_id (3)
        view._on_dns_finished(3, MagicMock())
        # Should not alter UI state or reset counter
        self.assertEqual(view._request_counter, 5)

    def test_latency_view_async_execution_and_duplicate_guard(self) -> None:
        view = LatencyBenchmarkView(self.app)
        # Trigger benchmark
        view._on_run_latency()
        self.assertFalse(view.test_btn.isEnabled())
        self.assertIn("Benchmarking", view.test_btn.text())

        # Duplicate attempt rejected
        view._on_run_latency()

        # Wait for completion
        for _ in range(50):
            if view.test_btn.isEnabled():
                break
            self._spin_events(2, 0.01)

        self.assertTrue(view.test_btn.isEnabled())
        self.assertIn("Run Benchmark", view.test_btn.text())

    def test_security_audit_view_async_execution(self) -> None:
        view = SecurityAuditView(self.app)
        view._run_audit_scan()
        self.assertFalse(view.refresh_audit_btn.isEnabled())
        self.assertIn("Auditing", view.refresh_audit_btn.text())

        # Wait for completion
        for _ in range(50):
            if view.refresh_audit_btn.isEnabled():
                break
            self._spin_events(2, 0.01)

        self.assertTrue(view.refresh_audit_btn.isEnabled())
        self.assertIn("Audit", view.refresh_audit_btn.text())

    def test_asset_inventory_view_async_refresh(self) -> None:
        view = AssetInventoryView(self.app)
        # Trigger refresh
        view.refresh_inventory(refresh=True)
        self.assertFalse(view.btn_refresh.isEnabled())
        self.assertIn("Loading", view.btn_refresh.text())

        # Duplicate attempt rejected
        view.refresh_inventory(refresh=True)

        for _ in range(50):
            if view.btn_refresh.isEnabled():
                break
            self._spin_events(2, 0.01)

        self.assertTrue(view.btn_refresh.isEnabled())
        self.assertIn("Refresh Inventory", view.btn_refresh.text())
        self.assertGreater(view.inventory_table.rowCount(), 0)

    def test_vendor_canvas_async_discovery(self) -> None:
        widget = VendorDeviceManagerWidget()
        widget.start_live_discovery(timeout=0.1)
        self.assertFalse(widget.btn_live_scan.isEnabled())
        self.assertIn("Listening", widget.btn_live_scan.text())

        # Duplicate attempt rejected
        widget.start_live_discovery(timeout=0.1)

        for _ in range(50):
            if widget.btn_live_scan.isEnabled():
                break
            self._spin_events(2, 0.01)

        self.assertTrue(widget.btn_live_scan.isEnabled())
        self.assertIn("Live Passive Discovery", widget.btn_live_scan.text())


class TestPhase4StartupDecoupling(unittest.TestCase):
    """Test startup decoupling and eager execution removal (TASK-P4-02)."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for startup decoupling tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))

    def test_dns_view_constructor_no_eager_resolution(self) -> None:
        with patch.object(self.app, "diagnose_dns", wraps=self.app.diagnose_dns) as mock_resolve:
            view = DNSDiagnosticsView(self.app)
            self.assertEqual(mock_resolve.call_count, 0)
            self.assertEqual(view.dns_table.rowCount(), 0)

    def test_latency_view_constructor_no_eager_benchmark(self) -> None:
        with patch.object(self.app, "benchmark_latency", wraps=self.app.benchmark_latency) as mock_latency:
            view = LatencyBenchmarkView(self.app)
            self.assertEqual(mock_latency.call_count, 0)
            self.assertEqual(view.lat_table.rowCount(), 0)
            self.assertIn("Ready to benchmark", view.lat_stats_label.text())

    def test_security_audit_view_constructor_no_eager_audit(self) -> None:
        with patch.object(self.app, "run_security_audit", wraps=self.app.run_security_audit) as mock_audit:
            view = SecurityAuditView(self.app)
            self.assertEqual(mock_audit.call_count, 0)
            self.assertEqual(view.audit_table.rowCount(), 0)

    def test_main_window_preserves_all_14_navigation_destinations(self) -> None:
        window = MainWindow(self.app)
        try:
            self.assertEqual(window.sidebar.count(), 14)
            self.assertEqual(window.pages_stack.count(), 14)

            expected_titles = [
                "System Overview",
                "Subnet Calculator",
                "Network Interfaces",
                "DNS Diagnostics",
                "Latency Benchmark",
                "Security Audit",
                "Packet Protocol Lab",
                "Routing Table",
                "Topology Visualizer",
                "Wi-Fi & Spectrum",
                "Bandwidth & Flow",
                "TLS & SSL Security",
                "OSPF & Dijkstra SPF",
                "Multi-Vendor & Cameras",
            ]
            for idx, expected in enumerate(expected_titles):
                item_text = window.sidebar.item(idx).text()
                self.assertIn(expected, item_text)
        finally:
            window.close()


class TestPhase4TruthfulRuntimeHealth(unittest.TestCase):
    """Test truthful runtime health indicator mapping and transitions (TASK-P4-03)."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for health tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))

    def test_health_indicator_direct_mapping(self) -> None:
        window = MainWindow(self.app)
        try:
            # 1. Healthy state
            report_healthy = SystemHealthReport(
                status=HealthStatus.HEALTHY,
                python_version="3.13.5",
                is_virtual_env=True,
                platform_name="Linux",
                architecture="x86_64",
                user_non_root=True,
                disk_free_gb=50.0,
                issues=[],
            )
            window._on_health_check_finished(window._health_request_id, report_healthy)
            self.assertIn("HEALTHY", window.health_badge.text())
            self.assertIn("normal", window.health_badge.toolTip().lower())

            # 2. Warning state
            report_warning = SystemHealthReport(
                status=HealthStatus.WARNING,
                python_version="3.13.5",
                is_virtual_env=False,
                platform_name="Linux",
                architecture="x86_64",
                user_non_root=True,
                disk_free_gb=50.0,
                issues=["Application running in system interpreter"],
            )
            window._on_health_check_finished(window._health_request_id, report_warning)
            self.assertIn("WARNING", window.health_badge.text())
            self.assertIn("system interpreter", window.health_badge.toolTip())

            # 3. Degraded state
            report_degraded = SystemHealthReport(
                status=HealthStatus.DEGRADED,
                python_version="3.13.5",
                is_virtual_env=True,
                platform_name="Linux",
                architecture="x86_64",
                user_non_root=True,
                disk_free_gb=0.4,
                issues=["Low free storage space (0.4 GB)"],
            )
            window._on_health_check_finished(window._health_request_id, report_degraded)
            self.assertIn("DEGRADED", window.health_badge.text())
            self.assertIn("Low free storage", window.health_badge.toolTip())

            # 4. Failed/Unavailable state
            window._on_health_check_failed(window._health_request_id, "Connection refused to daemon")
            self.assertIn("UNAVAILABLE", window.health_badge.text())
            self.assertNotIn("HEALTHY", window.health_badge.text())
        finally:
            window.close()

    def test_health_indicator_no_secret_leakage(self) -> None:
        window = MainWindow(self.app)
        try:
            leak_msg = "Error: password=secret123 at /home/user/.secret_key"
            window._on_health_check_failed(window._health_request_id, leak_msg)
            self.assertIn("UNAVAILABLE", window.health_badge.text())
        finally:
            window.close()


class TestPhase4ShutdownLifecycle(unittest.TestCase):
    """Test safe worker cancellation, QThread ownership, and window shutdown (TASK-P4-04)."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for shutdown lifecycle tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))

    def test_clean_shutdown_with_no_workers(self) -> None:
        window = MainWindow(self.app)
        event = QCloseEvent()
        window.closeEvent(event)
        self.assertTrue(event.isAccepted())
        self.assertTrue(window._is_shutting_down)

    def test_close_event_idempotency(self) -> None:
        window = MainWindow(self.app)
        event1 = QCloseEvent()
        window.closeEvent(event1)
        self.assertTrue(event1.isAccepted())

        # Second close call must be idempotent
        event2 = QCloseEvent()
        window.closeEvent(event2)
        self.assertTrue(event2.isAccepted())

    def test_shutdown_with_running_cancellable_worker(self) -> None:
        cancelled = []

        def slow_worker() -> None:
            for _ in range(50):
                time.sleep(0.01)

        worker = AsyncOperationWorker(101, slow_worker)
        worker.cancelled.connect(lambda req_id: cancelled.append(req_id))
        thread, _ = AsyncWorkerRunner.launch(worker)

        self.assertTrue(ActiveThreadRegistry.is_registered(thread))

        window = MainWindow(self.app)
        event = QCloseEvent()
        window.closeEvent(event)
        self.assertTrue(event.isAccepted())

        # ActiveThreadRegistry must have called cancel_and_wait_all
        thread.wait(1000)
        if self.qt_app:
            self.qt_app.processEvents()
        self.assertFalse(ActiveThreadRegistry.is_registered(thread))

    def test_shutdown_with_worker_exceeding_initial_wait_retains_ownership(self) -> None:
        """When a worker exceeds the initial shutdown wait, ActiveThreadRegistry retains ownership."""
        task_started = threading.Event()
        done_flag = [False]

        def very_slow_task() -> None:
            task_started.set()
            time.sleep(0.4)
            done_flag[0] = True

        worker = AsyncOperationWorker(102, very_slow_task)
        thread, _ = AsyncWorkerRunner.launch(worker)

        # Wait until task is actively executing
        self.assertTrue(task_started.wait(timeout=2.0))
        self.assertTrue(ActiveThreadRegistry.is_registered(thread))

        # Cancel and wait with 20ms timeout (task is actively sleeping for 400ms)
        finished = ActiveThreadRegistry.cancel_and_wait_all(timeout_ms=20)
        self.assertFalse(finished)  # Did not finish within 20ms

        # The thread MUST still be registered/owned to prevent destruction crash
        self.assertTrue(ActiveThreadRegistry.is_registered(thread))

        # Wait for actual completion
        thread.wait(2000)
        if self.qt_app:
            self.qt_app.processEvents()
        self.assertTrue(done_flag[0])
        self.assertFalse(ActiveThreadRegistry.is_registered(thread))


if __name__ == "__main__":
    unittest.main()
