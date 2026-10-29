"""Unit tests for asynchronous Qt worker infrastructure and thread lifecycle."""

import time
import unittest

try:
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.ui.desktop.workers import (
    ActiveThreadRegistry,
    AsyncOperationWorker,
    AsyncWorkerRunner,
    WorkerStatus,
)


class TestAsyncWorkers(unittest.TestCase):
    """Test asynchronous operation workers, threading, and lifecycle management."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for worker tests")

    def test_worker_success(self) -> None:
        results = []

        def sample_calc(a: int, b: int) -> int:
            return a + b

        worker = AsyncOperationWorker(1, sample_calc, 10, 25)

        thread, _ = AsyncWorkerRunner.launch(
            worker,
            on_finished=lambda req_id, res: results.append((req_id, res)),
        )

        # Wait for thread to finish cleanly
        thread.wait(2000)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], (1, 35))
        self.assertEqual(worker.status, WorkerStatus.COMPLETED)

    def test_worker_failure_propagation(self) -> None:
        errors = []

        def failing_task() -> None:
            raise ValueError("Intentional network timeout simulation")

        worker = AsyncOperationWorker(2, failing_task)

        thread, _ = AsyncWorkerRunner.launch(
            worker,
            on_failed=lambda req_id, err: errors.append((req_id, err)),
        )

        thread.wait(2000)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0][0], 2)
        self.assertIn("Intentional network timeout simulation", errors[0][1])
        self.assertEqual(worker.status, WorkerStatus.FAILED)

    def test_worker_cancellation(self) -> None:
        cancelled_events = []

        def cancellable_task(stop_event=None) -> str:
            for _ in range(20):
                if stop_event and stop_event.is_set():
                    return "Cancelled early"
                time.sleep(0.02)
            return "Completed"

        worker = AsyncOperationWorker(3, cancellable_task)

        thread, _ = AsyncWorkerRunner.launch(
            worker,
            on_cancelled=lambda req_id: cancelled_events.append(req_id),
        )

        # Immediately request cancellation
        worker.request_cancellation()
        thread.wait(2000)

        self.assertTrue(worker.is_cancellation_requested)
        self.assertEqual(worker.status, WorkerStatus.CANCELLED)
        self.assertIn(3, cancelled_events)

    def test_active_thread_registry_tracking(self) -> None:
        def fast_task() -> str:
            return "done"

        worker = AsyncOperationWorker(4, fast_task)
        initial_count = ActiveThreadRegistry.count()

        thread, _ = AsyncWorkerRunner.launch(worker)
        # Verify thread is tracked in registry
        self.assertTrue(ActiveThreadRegistry.is_registered(thread))

        thread.wait(2000)
        # Process pending Qt events to trigger finished signal cleanup
        self.qt_app.processEvents()

        # After thread finished, it unregisters
        self.assertFalse(ActiveThreadRegistry.is_registered(thread))


if __name__ == "__main__":
    unittest.main()
