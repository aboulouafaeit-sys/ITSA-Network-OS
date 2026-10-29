"""Latency benchmark desktop view."""

from __future__ import annotations

from typing import Any, Optional

try:
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPushButton,
        QSpinBox,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.app import Application
from itsa_network_os.ui.desktop.workers import AsyncOperationWorker, AsyncWorkerRunner


class LatencyBenchmarkView(QWidget):  # type: ignore
    """TCP latency benchmark and round-trip timing view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self._request_counter: int = 0
        self._is_loading: bool = False
        self._active_worker: Optional[AsyncOperationWorker] = None

        self.setAccessibleName("Latency Benchmark View")
        self.setAccessibleDescription("Safe non-root TCP handshake connection timing and packet loss detection.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Latency & Connectivity Benchmarking")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Safe non-root TCP handshake connection timing and packet loss detection.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        input_row = QHBoxLayout()
        self.lat_host_input = QLineEdit("1.1.1.1")
        self.lat_host_input.setAccessibleName("Benchmark Target Host Input")
        self.lat_host_input.setPlaceholderText("Target Host (e.g. 1.1.1.1)")
        self.lat_port_spin = QSpinBox()
        self.lat_port_spin.setAccessibleName("Benchmark Target Port")
        self.lat_port_spin.setRange(1, 65535)
        self.lat_port_spin.setValue(443)
        self.lat_count_spin = QSpinBox()
        self.lat_count_spin.setAccessibleName("Benchmark Probe Count")
        self.lat_count_spin.setRange(1, 20)
        self.lat_count_spin.setValue(4)

        self.test_btn = QPushButton("Run Benchmark")
        self.test_btn.setProperty("class", "PrimaryButton")
        self.test_btn.setAccessibleName("Run Benchmark Button")
        self.test_btn.clicked.connect(self._on_run_latency)

        input_row.addWidget(QLabel("Host:"))
        input_row.addWidget(self.lat_host_input, stretch=2)
        input_row.addWidget(QLabel("Port:"))
        input_row.addWidget(self.lat_port_spin)
        input_row.addWidget(QLabel("Probes:"))
        input_row.addWidget(self.lat_count_spin)
        input_row.addWidget(self.test_btn)
        layout.addLayout(input_row)

        self.lat_stats_label = QLabel("Ready to benchmark. Enter host/port and click 'Run Benchmark'.")
        self.lat_stats_label.setStyleSheet("color: #58a6ff; font-weight: bold;")
        layout.addWidget(self.lat_stats_label)

        self.lat_table = QTableWidget()
        self.lat_table.setAccessibleName("Latency Probes Table")
        self.lat_table.setColumnCount(3)
        self.lat_table.setHorizontalHeaderLabels(["Probe Sequence", "Round-Trip Latency (ms)", "Status / Error"])
        self.lat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.lat_table)

    def _on_run_latency(self) -> None:
        """Trigger asynchronous latency benchmark with duplicate-launch protection."""
        if self._is_loading:
            return

        host = self.lat_host_input.text().strip()
        port = self.lat_port_spin.value()
        count = self.lat_count_spin.value()
        if not host:
            return

        self._is_loading = True
        self.test_btn.setEnabled(False)
        self.test_btn.setText("Benchmarking...")
        self.lat_stats_label.setText(f"Benchmarking latency to {host}:{port} ({count} probes in progress)...")

        self._request_counter += 1
        req_id = self._request_counter

        worker = AsyncOperationWorker(req_id, self.app.benchmark_latency, host, port=port, count=count)
        self._active_worker = worker

        AsyncWorkerRunner.launch(
            worker,
            on_finished=self._on_latency_finished,
            on_failed=self._on_latency_failed,
        )

    def _on_latency_finished(self, req_id: int, res: Any) -> None:
        """Handle completed benchmark results on GUI thread."""
        if req_id != self._request_counter:
            return

        try:
            if not hasattr(self, "test_btn") or self.test_btn is None:
                return

            self._is_loading = False
            self.test_btn.setEnabled(True)
            self.test_btn.setText("Run Benchmark")
            self.lat_stats_label.setText(
                f"Target: {res.target_host}:{res.target_port} | Loss: {res.packet_loss_percent}% | "
                f"Min: {res.min_latency_ms} ms | Avg: {res.avg_latency_ms} ms | Max: {res.max_latency_ms} ms | Jitter: {res.jitter_ms} ms"
            )
            self.lat_table.setRowCount(len(res.probes))
            for row, p in enumerate(res.probes):
                self.lat_table.setItem(row, 0, QTableWidgetItem(f"Seq #{p.sequence}"))
                self.lat_table.setItem(row, 1, QTableWidgetItem(f"{p.latency_ms:.2f}" if p.success else "N/A"))
                self.lat_table.setItem(row, 2, QTableWidgetItem("SUCCESS" if p.success else f"FAILED: {p.error}"))
        except RuntimeError:
            return

    def _on_latency_failed(self, req_id: int, error_msg: str) -> None:
        """Handle benchmark failure on GUI thread."""
        if req_id != self._request_counter:
            return

        try:
            if not hasattr(self, "test_btn") or self.test_btn is None:
                return

            self._is_loading = False
            self.test_btn.setEnabled(True)
            self.test_btn.setText("Run Benchmark")
            self.lat_stats_label.setText(f"Benchmark Failed: {error_msg}")
            self.lat_table.setRowCount(0)
        except RuntimeError:
            return
