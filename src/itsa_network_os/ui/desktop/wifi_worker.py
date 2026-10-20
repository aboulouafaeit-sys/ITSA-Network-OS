"""Non-blocking Qt worker and execution lifecycle for wireless airwave scanning."""

from __future__ import annotations

import enum
import shutil
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

try:
    from PySide6.QtCore import QObject, QThread, Signal, Slot  # type: ignore
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

    class QObject:  # type: ignore
        def __init__(self, parent: Optional[Any] = None) -> None:
            pass

    class QThread:  # type: ignore
        def __init__(self, parent: Optional[Any] = None) -> None:
            pass

    def Signal(*args: Any, **kwargs: Any) -> Any:  # type: ignore
        class _Signal:
            def connect(self, slot: Any) -> None:
                pass
            def disconnect(self, slot: Any) -> None:
                pass
            def emit(self, *a: Any, **kw: Any) -> None:
                pass
        return _Signal()

    def Slot(*args: Any, **kwargs: Any) -> Any:  # type: ignore
        return lambda f: f

from itsa_network_os.core.logger import get_logger
from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WirelessSpectrumAnalyzer,
)

logger = get_logger("itsa_network_os.ui.desktop.wifi_worker")


class WifiScanStatus(str, enum.Enum):
    """Execution status for asynchronous wireless scanning operation."""

    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class WifiScanResult:
    """Thread-safe, immutable data container returned by WifiScanWorker."""

    request_id: int
    status: WifiScanStatus
    access_points: List[AccessPointInfo] = field(default_factory=list)
    reports: List[ChannelCongestionReport] = field(default_factory=list)
    band: SpectrumBand = SpectrumBand.BAND_2_4_GHZ
    error_message: Optional[str] = None
    diagnostics: List[str] = field(default_factory=list)
    is_mock: bool = False
    is_live: bool = False


class ActiveThreadRegistry:
    """Thread-safe registry maintaining strong Python references to running QThread and worker instances.

    Guarantees that QThread and worker objects remain strongly referenced in Python
    until the underlying OS thread has fully exited, preventing 'QThread: Destroyed while thread
    is still running' fatal aborts when owning widgets are closed or deallocated.
    """

    _lock = threading.Lock()
    _active_threads: Dict[int, tuple[Any, Any]] = {}

    @classmethod
    def register(cls, thread: Any, worker: Any) -> int:
        """Register a running QThread and worker, retaining strong references until thread.finished."""
        thread_id = id(thread)
        with cls._lock:
            cls._active_threads[thread_id] = (thread, worker)

        def _on_thread_finished() -> None:
            with cls._lock:
                cls._active_threads.pop(thread_id, None)

        if hasattr(thread, "finished"):
            thread.finished.connect(_on_thread_finished)
        return thread_id

    @classmethod
    def is_registered(cls, thread: Any) -> bool:
        """Check if thread is currently registered and actively tracked."""
        if thread is None:
            return False
        with cls._lock:
            return id(thread) in cls._active_threads

    @classmethod
    def count(cls) -> int:
        """Number of currently tracked active threads."""
        with cls._lock:
            return len(cls._active_threads)

    @classmethod
    def get_tracked_threads(cls) -> List[Any]:
        """List of all currently registered thread instances."""
        with cls._lock:
            return [t for t, _ in cls._active_threads.values()]

    @classmethod
    def clear_finished(cls) -> None:
        """Remove any threads that have finished executing."""
        with cls._lock:
            finished_ids = [
                tid for tid, (t, _) in cls._active_threads.items()
                if hasattr(t, "isRunning") and not t.isRunning()
            ]
            for tid in finished_ids:
                cls._active_threads.pop(tid, None)


class WifiScanWorker(QObject):
    """Qt worker object executing wireless scan off the GUI thread with cancellation support."""

    # Qt cross-thread signals
    started = Signal(int)                          # request_id
    finished = Signal(object)                       # WifiScanResult
    failed = Signal(int, str)                      # request_id, error_message
    cancelled = Signal(int)                        # request_id
    status_changed = Signal(int, str)              # request_id, status_message

    def __init__(
        self,
        request_id: int,
        app: Optional[Any] = None,
        band: SpectrumBand = SpectrumBand.BAND_2_4_GHZ,
        force_live: bool = False,
        interface: Optional[str] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self.request_id = request_id
        self.app = app
        self.band = band
        self.force_live = force_live
        self.interface = interface

        self._status = WifiScanStatus.IDLE
        self._cancellation_event = threading.Event()
        self._lock = threading.Lock()

    @property
    def status(self) -> WifiScanStatus:
        """Current execution status of the worker."""
        with self._lock:
            return self._status

    @property
    def is_cancellation_requested(self) -> bool:
        """Check if cancellation was requested for this worker."""
        return self._cancellation_event.is_set()

    @Slot()
    def request_cancellation(self) -> None:
        """Cooperative thread-safe request to cancel active scan."""
        logger.info("Cancellation requested for wireless scan request %d", self.request_id)
        self._cancellation_event.set()

    @Slot()
    def execute_scan(self) -> None:
        """Execute scan workflow on the dedicated worker thread."""
        with self._lock:
            self._status = WifiScanStatus.RUNNING

        self.started.emit(self.request_id)
        self.status_changed.emit(self.request_id, "Scanning wireless airwaves...")

        # 1. Preflight cancellation check
        if self._cancellation_event.is_set():
            self._handle_cancellation()
            return

        try:
            # 2. Determine scan mode (offline mock vs live wireless hardware)
            use_mock = True
            if self.app is not None:
                use_mock = self.app.config.use_mock_network and not self.force_live
            else:
                use_mock = not self.force_live

            logger.debug(
                "Scan worker %d executing (use_mock=%s, force_live=%s, band=%s)",
                self.request_id,
                use_mock,
                self.force_live,
                self.band.value,
            )

            # 3. Perform scan with cooperative cancellation token
            cancel_check: Callable[[], bool] = self._cancellation_event.is_set

            if use_mock:
                if self.app is not None:
                    aps = self.app.get_wifi_access_points(force_live=False, cancellation_check=cancel_check)
                else:
                    aps = WirelessSpectrumAnalyzer.get_access_points(use_mock=True, cancellation_check=cancel_check)
            else:
                # Live wireless scan using LinuxWirelessScanner
                from itsa_network_os.network.wireless_scanner import LinuxWirelessScanner

                aps = LinuxWirelessScanner.get_access_points(
                    interface=self.interface,
                    cancellation_check=cancel_check,
                )

            # 4. Check for cancellation post-scan
            if self._cancellation_event.is_set():
                self._handle_cancellation()
                return

            # 5. Compute RF spectrum congestion metrics
            reports = WirelessSpectrumAnalyzer.analyze_spectrum(aps, band=self.band)

            # 6. Check for cancellation post-analysis
            if self._cancellation_event.is_set():
                self._handle_cancellation()
                return

            # 7. Formulate diagnostics for zero-AP results in live mode
            diagnostics: List[str] = []
            if not use_mock and len(aps) == 0:
                if not shutil.which("iw"):
                    diagnostics.append("Wireless utility 'iw' is not installed or not in system PATH.")
                else:
                    diagnostics.append(
                        "Scan dump returned 0 access points. (Check wireless adapter state or RF coverage)."
                    )

            with self._lock:
                self._status = WifiScanStatus.COMPLETED

            result = WifiScanResult(
                request_id=self.request_id,
                status=WifiScanStatus.COMPLETED,
                access_points=aps,
                reports=reports,
                band=self.band,
                diagnostics=diagnostics,
                is_mock=use_mock,
                is_live=not use_mock,
            )

            logger.info(
                "Scan worker %d finished successfully: %d APs, %d reports (mock=%s)",
                self.request_id,
                len(aps),
                len(reports),
                use_mock,
            )
            self.finished.emit(result)

        except Exception as exc:
            logger.error(
                "Wireless scan worker %d failed with exception: %s",
                self.request_id,
                exc,
                exc_info=True,
            )
            with self._lock:
                self._status = WifiScanStatus.FAILED
            self.failed.emit(self.request_id, str(exc))

    def _handle_cancellation(self) -> None:
        """Update terminal status and emit cancellation signal."""
        with self._lock:
            self._status = WifiScanStatus.CANCELLED
        logger.info("Wireless scan worker %d terminated due to cancellation", self.request_id)
        self.cancelled.emit(self.request_id)
