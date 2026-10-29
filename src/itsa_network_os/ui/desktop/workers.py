"""Asynchronous Qt worker infrastructure and thread lifecycle management for desktop UI."""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

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
from itsa_network_os.ui.desktop.wifi_worker import ActiveThreadRegistry

logger = get_logger("itsa_network_os.ui.desktop.workers")


class WorkerStatus(str, enum.Enum):
    """Execution status for asynchronous UI workers."""

    IDLE = "IDLE"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AsyncOperationWorker(QObject):
    """General-purpose Qt worker executing a Python callable off the GUI thread."""

    started = Signal(int)                 # request_id
    finished = Signal(int, object)        # request_id, result
    failed = Signal(int, str)             # request_id, error_message
    cancelled = Signal(int)               # request_id
    progress = Signal(int, str)           # request_id, progress_message

    def __init__(
        self,
        request_id: int,
        target_callable: Callable[..., Any],
        *args: Any,
        parent: Optional[QObject] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(parent)
        self.request_id = request_id
        self.target_callable = target_callable
        self.args = args
        self.kwargs = kwargs

        self._status = WorkerStatus.IDLE
        self._cancellation_event = threading.Event()
        self._lock = threading.Lock()

    @property
    def status(self) -> WorkerStatus:
        """Current execution status."""
        with self._lock:
            return self._status

    @property
    def is_cancellation_requested(self) -> bool:
        """True if worker was requested to cancel."""
        return self._cancellation_event.is_set()

    @Slot()
    def request_cancellation(self) -> None:
        """Request cooperative cancellation."""
        logger.info("Cancellation requested for worker request %d", self.request_id)
        self._cancellation_event.set()

    @Slot()
    def execute(self) -> None:
        """Execute callable on worker thread."""
        with self._lock:
            self._status = WorkerStatus.RUNNING

        self.started.emit(self.request_id)

        if self._cancellation_event.is_set():
            with self._lock:
                self._status = WorkerStatus.CANCELLED
            self.cancelled.emit(self.request_id)
            return

        try:
            # Check if target callable accepts a stop_event or cancellation_check parameter
            import inspect
            sig = inspect.signature(self.target_callable)
            call_kwargs = dict(self.kwargs)
            if "stop_event" in sig.parameters and "stop_event" not in call_kwargs:
                call_kwargs["stop_event"] = self._cancellation_event
            elif "cancellation_check" in sig.parameters and "cancellation_check" not in call_kwargs:
                call_kwargs["cancellation_check"] = self._cancellation_event.is_set

            result = self.target_callable(*self.args, **call_kwargs)

            if self._cancellation_event.is_set():
                with self._lock:
                    self._status = WorkerStatus.CANCELLED
                self.cancelled.emit(self.request_id)
                return

            with self._lock:
                self._status = WorkerStatus.COMPLETED

            self.finished.emit(self.request_id, result)

        except Exception as exc:
            logger.error("AsyncOperationWorker [%d] failed: %s", self.request_id, exc, exc_info=True)
            with self._lock:
                self._status = WorkerStatus.FAILED
            self.failed.emit(self.request_id, str(exc))


class AsyncWorkerRunner:
    """Helper for wiring QThread lifecycle, signal routing, and thread-safety tracking."""

    @classmethod
    def launch(
        cls,
        worker: Any,
        on_finished: Optional[Callable[[int, Any], None]] = None,
        on_failed: Optional[Callable[[int, str], None]] = None,
        on_started: Optional[Callable[[int], None]] = None,
        on_cancelled: Optional[Callable[[int], None]] = None,
        on_progress: Optional[Callable[[int, str], None]] = None,
    ) -> Tuple[Any, Any]:
        """Launch worker on a dedicated QThread with managed lifetime."""
        if not PYSIDE6_AVAILABLE:
            raise RuntimeError("PySide6 is required to launch asynchronous workers.")

        thread = QThread()
        worker.moveToThread(thread)

        # Wire thread execution and cleanup
        thread.started.connect(worker.execute)
        worker.finished.connect(lambda req_id, res: thread.quit())
        worker.failed.connect(lambda req_id, err: thread.quit())
        worker.cancelled.connect(lambda req_id: thread.quit())

        # Wire user callbacks
        if on_started and hasattr(worker, "started"):
            worker.started.connect(on_started)
        if on_finished and hasattr(worker, "finished"):
            worker.finished.connect(on_finished)
        if on_failed and hasattr(worker, "failed"):
            worker.failed.connect(on_failed)
        if on_cancelled and hasattr(worker, "cancelled"):
            worker.cancelled.connect(on_cancelled)
        if on_progress and hasattr(worker, "progress"):
            worker.progress.connect(on_progress)

        # Register thread to prevent garbage collection aborts
        ActiveThreadRegistry.register(thread, worker)
        thread.start()

        return thread, worker
