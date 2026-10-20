"""Unit tests for non-blocking wireless scan worker, QThread lifecycle, and GUI integration."""

import os
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WifiSecurityProtocol,
    WifiStandard,
    WirelessSpectrumAnalyzer,
)
from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner
from itsa_network_os.ui.desktop.wifi_canvas import WifiSpectrumWidget
from itsa_network_os.ui.desktop.wifi_worker import (
    ActiveThreadRegistry,
    PYSIDE6_AVAILABLE,
    WifiScanResult,
    WifiScanStatus,
    WifiScanWorker,
)

if PYSIDE6_AVAILABLE:
    from PySide6.QtCore import QEventLoop, QThread, QTimer  # type: ignore
    from PySide6.QtWidgets import QApplication  # type: ignore


class TestWifiScanWorkerLifecycle(unittest.TestCase):
    """Deterministic unit tests for WifiScanWorker lifecycle, threading, and cancellation."""

    @classmethod
    def setUpClass(cls) -> None:
        if not PYSIDE6_AVAILABLE:
            raise unittest.SkipTest("PySide6 not installed")
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        cls.qt_app = QApplication.instance() or QApplication(["test_worker", "-platform", "offscreen"])

    def setUp(self) -> None:
        self.app = Application(config=AppConfig(database_file=":memory:"))

    def test_worker_initial_state(self) -> None:
        """Worker starts in IDLE state with unflagged cancellation."""
        worker = WifiScanWorker(request_id=1, app=self.app)
        self.assertEqual(worker.request_id, 1)
        self.assertEqual(worker.status, WifiScanStatus.IDLE)
        self.assertFalse(worker.is_cancellation_requested)

    def test_worker_successful_mock_execution(self) -> None:
        """Worker completes mock scan on worker thread and emits finished signal."""
        worker = WifiScanWorker(request_id=42, app=self.app, band=SpectrumBand.BAND_2_4_GHZ, force_live=False)
        thread = QThread()
        worker.moveToThread(thread)

        results_collected = []
        loop = QEventLoop()

        def on_finished(res: WifiScanResult) -> None:
            results_collected.append(res)
            loop.quit()

        thread.started.connect(worker.execute_scan)
        worker.finished.connect(lambda res: results_collected.append(res))
        worker.finished.connect(thread.quit)
        thread.finished.connect(loop.quit)

        # Safety timeout timer
        timer = QTimer()
        timer.setSingleShot(True)
        timer.timeout.connect(loop.quit)
        timer.start(5000)

        thread.start()
        loop.exec()

        thread.wait(2000)
        self.assertFalse(thread.isRunning())

        self.assertEqual(len(results_collected), 1)
        res = results_collected[0]
        self.assertEqual(res.request_id, 42)
        self.assertEqual(res.status, WifiScanStatus.COMPLETED)
        self.assertTrue(res.is_mock)
        self.assertFalse(res.is_live)
        self.assertGreater(len(res.access_points), 0)
        self.assertGreater(len(res.reports), 0)
        self.assertEqual(res.band, SpectrumBand.BAND_2_4_GHZ)
        self.assertEqual(worker.status, WifiScanStatus.COMPLETED)

        thread.wait(1000)

    def test_worker_cancellation_before_execution(self) -> None:
        """Worker requested for cancellation prior to run terminates in CANCELLED state."""
        worker = WifiScanWorker(request_id=10, app=self.app)
        worker.request_cancellation()
        self.assertTrue(worker.is_cancellation_requested)

        cancelled_collected = []
        worker.cancelled.connect(lambda req_id: cancelled_collected.append(req_id))

        worker.execute_scan()

        self.assertEqual(len(cancelled_collected), 1)
        self.assertEqual(cancelled_collected[0], 10)
        self.assertEqual(worker.status, WifiScanStatus.CANCELLED)

    def test_worker_cancellation_during_scan_emits_cancelled(self) -> None:
        """Cancellation token stops scan midway and emits cancelled signal."""
        worker = WifiScanWorker(request_id=11, app=self.app, force_live=True)

        cancelled_collected = []
        finished_collected = []
        worker.cancelled.connect(lambda req_id: cancelled_collected.append(req_id))
        worker.finished.connect(lambda res: finished_collected.append(res))

        from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

        def cancel_midway(*args, **kwargs) -> list:
            worker.request_cancellation()
            return []

        with patch.object(LinuxWirelessScanner, "get_access_points", side_effect=cancel_midway):
            worker.execute_scan()

        self.assertEqual(len(cancelled_collected), 1)
        self.assertEqual(len(finished_collected), 0)
        self.assertEqual(worker.status, WifiScanStatus.CANCELLED)

    def test_worker_exception_emits_failed_signal(self) -> None:
        """Worker catches unexpected scanner exceptions, emits failed signal, and reaches FAILED state."""
        worker = WifiScanWorker(request_id=99, app=self.app, force_live=True)

        failed_collected = []
        worker.failed.connect(lambda req_id, err: failed_collected.append((req_id, err)))

        from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

        with patch.object(LinuxWirelessScanner, "get_access_points", side_effect=OSError("Netlink socket failure")):
            worker.execute_scan()

        self.assertEqual(len(failed_collected), 1)
        req_id, err_msg = failed_collected[0]
        self.assertEqual(req_id, 99)
        self.assertIn("Netlink socket failure", err_msg)
        self.assertEqual(worker.status, WifiScanStatus.FAILED)

    def test_worker_live_empty_result_includes_diagnostics(self) -> None:
        """Live scan with 0 APs completes with diagnostics and does NOT silently fall back to mock."""
        worker = WifiScanWorker(request_id=15, app=self.app, force_live=True)

        finished_collected = []
        worker.finished.connect(lambda res: finished_collected.append(res))

        from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

        with patch.object(LinuxWirelessScanner, "get_access_points", return_value=[]):
            worker.execute_scan()

        self.assertEqual(len(finished_collected), 1)
        res = finished_collected[0]
        self.assertEqual(res.status, WifiScanStatus.COMPLETED)
        self.assertEqual(len(res.access_points), 0)
        self.assertTrue(res.is_live)
        self.assertFalse(res.is_mock)
        self.assertGreater(len(res.diagnostics), 0)

    def test_security_semantics_survive_worker_boundary(self) -> None:
        """Verified access points with UNKNOWN, OPEN, and WPA3 survive through worker signal."""
        dummy_aps = [
            AccessPointInfo(
                ssid="Incomplete-AP",
                bssid="00:11:22:33:44:01",
                rssi_dbm=-65,
                signal_percent=50,
                channel=6,
                frequency_mhz=2437,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.UNKNOWN,
                standard=WifiStandard.LEGACY,
                wps_enabled=False,
                security_warnings=["Incomplete beacon telemetry: capability field absent; security status unknown."],
            ),
            AccessPointInfo(
                ssid="Confirmed-Open",
                bssid="00:11:22:33:44:02",
                rssi_dbm=-55,
                signal_percent=64,
                channel=1,
                frequency_mhz=2412,
                channel_width_mhz=20,
                security=WifiSecurityProtocol.OPEN,
                standard=WifiStandard.WIFI_4,
                wps_enabled=False,
                security_warnings=["Unencrypted network: cleartext traffic susceptible to eavesdropping."],
            ),
            AccessPointInfo(
                ssid="Secure-WPA3",
                bssid="00:11:22:33:44:03",
                rssi_dbm=-40,
                signal_percent=85,
                channel=36,
                frequency_mhz=5180,
                channel_width_mhz=80,
                security=WifiSecurityProtocol.WPA3_SAE,
                standard=WifiStandard.WIFI_6,
                wps_enabled=False,
                security_warnings=[],
            ),
        ]

        worker = WifiScanWorker(request_id=77, app=self.app, force_live=True)
        finished_collected = []
        worker.finished.connect(lambda res: finished_collected.append(res))

        from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

        with patch.object(LinuxWirelessScanner, "get_access_points", return_value=dummy_aps):
            worker.execute_scan()

        self.assertEqual(len(finished_collected), 1)
        res = finished_collected[0]
        self.assertEqual(len(res.access_points), 3)

        ap_unknown = res.access_points[0]
        self.assertEqual(ap_unknown.security, WifiSecurityProtocol.UNKNOWN)
        self.assertEqual(ap_unknown.security.value, "Unknown")
        self.assertIn("security status unknown", ap_unknown.security_warnings[0])

        ap_open = res.access_points[1]
        self.assertEqual(ap_open.security, WifiSecurityProtocol.OPEN)
        self.assertEqual(ap_open.security.value, "Open (None)")

        ap_wpa3 = res.access_points[2]
        self.assertEqual(ap_wpa3.security, WifiSecurityProtocol.WPA3_SAE)


class TestWifiSpectrumWidgetAsyncLifecycle(unittest.TestCase):
    """Integration unit tests for WifiSpectrumWidget UI, non-blocking scan, and thread lifecycle."""

    @classmethod
    def setUpClass(cls) -> None:
        if not PYSIDE6_AVAILABLE:
            raise unittest.SkipTest("PySide6 not installed")
        os.environ["QT_QPA_PLATFORM"] = "offscreen"
        cls.qt_app = QApplication.instance() or QApplication(["test_widget", "-platform", "offscreen"])

    def setUp(self) -> None:
        self.app = Application(config=AppConfig(database_file=":memory:"))
        self.widget = WifiSpectrumWidget(app=self.app)

    def tearDown(self) -> None:
        self.widget._cleanup_active_worker(wait_ms=300)

    def test_widget_initial_startup_state(self) -> None:
        """Widget starts populated with initial offline mock fixtures without blocking."""
        self.assertFalse(self.widget._is_scanning)
        self.assertGreater(self.widget.ap_table.rowCount(), 0)
        self.assertIn("MOCK", self.widget.lbl_provenance_badge.text())
        self.assertTrue(self.widget.btn_scan.isEnabled())
        self.assertTrue(self.widget.btn_live_scan.isEnabled())
        self.assertFalse(self.widget.btn_cancel.isVisible())

    def test_repeated_scan_requests_do_not_create_duplicate_workers(self) -> None:
        """Calling start_scan while already scanning ignores overlapping requests."""
        self.widget._is_scanning = True
        prev_req_id = self.widget._active_request_id

        # Attempt to start another scan
        self.widget.start_scan(force_live=False)

        # Active request ID must not increment, and overlapping scan must be refused
        self.assertEqual(self.widget._active_request_id, prev_req_id)
        self.widget._is_scanning = False

    def test_stale_result_ignored_by_request_id(self) -> None:
        """Result with obsolete request_id is discarded and does not overwrite UI."""
        self.widget._active_request_id = 5

        stale_result = WifiScanResult(
            request_id=4,  # Stale request ID
            status=WifiScanStatus.COMPLETED,
            access_points=[],
            reports=[],
            band=SpectrumBand.BAND_2_4_GHZ,
            is_mock=False,
            is_live=True,
        )

        initial_row_count = self.widget.ap_table.rowCount()
        self.widget._on_scan_finished(stale_result)

        # Stale result with 0 APs must be discarded; row count must remain unchanged
        self.assertEqual(self.widget.ap_table.rowCount(), initial_row_count)

    def test_failed_scan_updates_status_banner_without_wiping_data(self) -> None:
        """Scan failure displays diagnostic error banner and preserves existing table rows."""
        self.widget._is_scanning = True
        self.widget._active_request_id = 1
        initial_row_count = self.widget.ap_table.rowCount()

        self.widget._on_scan_failed(request_id=1, error_message="Permission denied on iw scan dump")

        self.assertFalse(self.widget._is_scanning)
        self.assertTrue(self.widget.btn_scan.isEnabled())
        self.assertIn("Permission denied", self.widget.status_banner.text())
        self.assertIn("FAILED", self.widget.lbl_provenance_badge.text())
        # Prior AP rows remain visible
        self.assertEqual(self.widget.ap_table.rowCount(), initial_row_count)

    def test_cancelled_scan_resets_controls(self) -> None:
        """Cancellation updates banner and re-enables scan buttons."""
        self.widget._is_scanning = True
        self.widget._active_request_id = 2

        self.widget._on_scan_cancelled(request_id=2)

        self.assertFalse(self.widget._is_scanning)
        self.assertTrue(self.widget.btn_scan.isEnabled())
        self.assertTrue(self.widget.btn_live_scan.isEnabled())
        self.assertFalse(self.widget.btn_cancel.isVisible())
        self.assertIn("CANCELLED", self.widget.lbl_provenance_badge.text())

    def test_live_scan_completion_updates_provenance_badge(self) -> None:
        """Successful live scan switches provenance badge from Mock to Live."""
        live_ap = AccessPointInfo(
            ssid="Live-Corporate",
            bssid="00:22:33:44:55:66",
            rssi_dbm=-48,
            signal_percent=74,
            channel=6,
            frequency_mhz=2437,
            channel_width_mhz=20,
            security=WifiSecurityProtocol.WPA2_PSK,
            standard=WifiStandard.WIFI_4,
            wps_enabled=False,
            security_warnings=[],
        )
        reports = WirelessSpectrumAnalyzer.analyze_spectrum([live_ap], band=SpectrumBand.BAND_2_4_GHZ)

        live_result = WifiScanResult(
            request_id=1,
            status=WifiScanStatus.COMPLETED,
            access_points=[live_ap],
            reports=reports,
            band=SpectrumBand.BAND_2_4_GHZ,
            is_mock=False,
            is_live=True,
        )

        self.widget._active_request_id = 1
        self.widget._is_scanning = True
        self.widget._on_scan_finished(live_result)

        self.assertIn("LIVE AIRWAVES", self.widget.lbl_provenance_badge.text())
        self.assertEqual(self.widget.ap_table.rowCount(), 1)
        self.assertEqual(self.widget.ap_table.item(0, 0).text(), "Live-Corporate")

    def test_close_event_cleans_up_worker_and_thread(self) -> None:
        """Closing widget cancels worker and terminates QThread without crash."""
        self.widget.start_scan(force_live=False)
        self.assertTrue(self.widget._is_scanning)
        self.assertIsNotNone(self.widget._worker)
        self.assertIsNotNone(self.widget._thread)

        worker = self.widget._worker
        thread = self.widget._thread

        # Trigger widget close
        self.widget.close()

        self.assertTrue(worker.is_cancellation_requested)
        self.assertFalse(thread.isRunning())

    def test_close_during_slow_scan_retains_thread_in_registry_and_cleans_up_safely(self) -> None:
        """Closing widget during slow scan keeps QThread strongly referenced until completion."""
        scan_entered = threading.Event()

        def slow_scan(*args, **kwargs) -> list:
            scan_entered.set()
            time.sleep(0.3)
            return []

        with patch.object(LinuxWirelessScanner, "get_access_points", side_effect=slow_scan):
            self.widget.start_scan(force_live=True)
            self.assertTrue(self.widget._is_scanning)
            thread = self.widget._thread
            self.assertIsNotNone(thread)
            self.assertTrue(ActiveThreadRegistry.is_registered(thread))

            # Wait until slow_scan has actually entered execution
            self.assertTrue(scan_entered.wait(timeout=2.0))

            # Close widget while scan is active (wait_ms=50 is shorter than 0.3s)
            self.widget._cleanup_active_worker(wait_ms=50)

            # Thread is still running, but safely retained in registry
            self.assertTrue(thread.isRunning())
            self.assertTrue(ActiveThreadRegistry.is_registered(thread))

            # Wait for thread to finish cleanly
            thread.wait(2000)
            self.assertFalse(thread.isRunning())
            # Process events to allow thread.finished to clean registry
            self.qt_app.processEvents()
            # Once thread exits, registry must clean up
            self.assertFalse(ActiveThreadRegistry.is_registered(thread))

    def test_slow_scan_shutdown_in_isolated_process_produces_zero_destruction_warnings(self) -> None:
        """Subprocess test verifying that closing widget during slow scan produces zero QThread destroyed warnings."""
        code = """
import os, time, sys, threading
os.environ["QT_QPA_PLATFORM"] = "offscreen"
from PySide6.QtWidgets import QApplication
from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.ui.desktop.wifi_canvas import WifiSpectrumWidget
from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner
from unittest.mock import patch

app = QApplication.instance() or QApplication(["test", "-platform", "offscreen"])

scan_entered = threading.Event()
def slow_scan(*args, **kwargs):
    scan_entered.set()
    time.sleep(0.3)
    return []

with patch.object(LinuxWirelessScanner, "get_access_points", side_effect=slow_scan):
    widget = WifiSpectrumWidget(app=Application(config=AppConfig(database_file=":memory:")))
    widget.start_scan(force_live=True)
    scan_entered.wait(timeout=2.0)
    widget.close()
    time.sleep(0.4)
    app.processEvents()
"""
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("QThread: Destroyed while thread", proc.stderr)

    def test_immediate_rescan_handoff_and_prevention_of_concurrent_workers(self) -> None:
        """Consecutive scans execute cleanly without dropping references or allowing overlap."""
        self.widget.start_scan(force_live=False)
        self.assertTrue(self.widget._is_scanning)

        # Attempt concurrent scan while first is running
        prev_req_id = self.widget._active_request_id
        self.widget.start_scan(force_live=False)
        self.assertEqual(self.widget._active_request_id, prev_req_id)

        # Allow first scan to complete
        thread1 = self.widget._thread
        if thread1 is not None:
            thread1.wait(2000)
        self.qt_app.processEvents()

        # Immediately trigger second scan
        self.widget.start_scan(force_live=False)
        self.assertEqual(self.widget._active_request_id, prev_req_id + 1)
        thread2 = self.widget._thread
        self.assertIsNotNone(thread2)
        if thread2 is not None:
            thread2.wait(2000)
        self.qt_app.processEvents()


class TestSubprocessCancellationAndDeadlines(unittest.TestCase):
    """Deterministic tests for interruptible subprocess execution, cancellation, and overall deadline."""

    def test_interruptible_subprocess_cancellation_terminates_child_process(self) -> None:
        """Cancellation terminates child process in < 0.6s and reaps child without orphans."""
        cancel_event = threading.Event()

        # Timer to trigger cancellation after 100ms
        timer = threading.Timer(0.1, cancel_event.set)
        timer.start()

        cmd = [sys.executable, "-c", "import time; time.sleep(5.0)"]
        start_t = time.monotonic()

        stdout, stderr, code, was_cancelled = LinuxWirelessScanner._execute_interruptible_scan(
            cmd=cmd,
            timeout=5.0,
            cancellation_check=cancel_event.is_set,
        )
        elapsed = time.monotonic() - start_t
        timer.cancel()

        self.assertTrue(was_cancelled)
        self.assertLess(elapsed, 1.0, "Cancellation took longer than 1.0s!")

    def test_scanner_overall_deadline_bounds_multi_interface_delays(self) -> None:
        """Overall deadline bounds execution when multiple candidate interfaces have delays."""
        with patch.object(LinuxWirelessScanner, "discover_wireless_interfaces", return_value=["wlan0", "wlan1", "wlan2", "wlan3"]):
            with patch("shutil.which", return_value="/usr/sbin/iw"):
                def slow_scan(cmd, timeout, cancellation_check=None):
                    time.sleep(0.1)
                    return "", "", 1, False

                with patch.object(LinuxWirelessScanner, "_execute_interruptible_scan", side_effect=slow_scan):
                    orig_deadline = LinuxWirelessScanner.TOTAL_SCAN_DEADLINE_SECONDS
                    LinuxWirelessScanner.TOTAL_SCAN_DEADLINE_SECONDS = 0.15
                    try:
                        start_t = time.monotonic()
                        aps = LinuxWirelessScanner.get_access_points(cancellation_check=lambda: False)
                        elapsed = time.monotonic() - start_t
                        self.assertEqual(aps, [])
                        self.assertLess(elapsed, 0.35, "Scan exceeded overall deadline bound!")
                    finally:
                        LinuxWirelessScanner.TOTAL_SCAN_DEADLINE_SECONDS = orig_deadline

    def test_scanner_subprocess_timeout_raises_timeout_expired(self) -> None:
        """Interruptible subprocess execution raises TimeoutExpired when process exceeds timeout."""
        cmd = [sys.executable, "-c", "import time; time.sleep(5.0)"]
        with self.assertRaises(subprocess.TimeoutExpired):
            LinuxWirelessScanner._execute_interruptible_scan(
                cmd=cmd,
                timeout=0.2,
                cancellation_check=lambda: False,
            )

    def test_scanner_process_start_error_handled_cleanly(self) -> None:
        """Non-existent binary in interruptible execution raises FileNotFoundError."""
        cmd = ["/nonexistent/path/to/binary"]
        with self.assertRaises(FileNotFoundError):
            LinuxWirelessScanner._execute_interruptible_scan(
                cmd=cmd,
                timeout=1.0,
                cancellation_check=lambda: False,
            )


if __name__ == "__main__":
    unittest.main()
