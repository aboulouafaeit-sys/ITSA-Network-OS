"""DNS diagnostics desktop view."""

from __future__ import annotations

from typing import Any, Optional

try:
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPushButton,
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


class DNSDiagnosticsView(QWidget):  # type: ignore
    """DNS resolution and latency diagnostics view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self._request_counter: int = 0
        self._is_loading: bool = False
        self._active_worker: Optional[AsyncOperationWorker] = None

        self.setAccessibleName("DNS Diagnostics View")
        self.setAccessibleDescription("Query domain records and measure nameserver response latency.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("DNS Resolution Diagnostics")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Query domain records and measure nameserver response latency.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        input_row = QHBoxLayout()
        self.dns_input = QLineEdit("google.com")
        self.dns_input.setAccessibleName("DNS Hostname Target Input")
        self.dns_input.setPlaceholderText("Enter hostname to resolve (e.g., example.com)")
        self.query_btn = QPushButton("Resolve DNS")
        self.query_btn.setProperty("class", "PrimaryButton")
        self.query_btn.setAccessibleName("Resolve DNS Button")
        self.query_btn.clicked.connect(self._on_resolve_dns)
        input_row.addWidget(self.dns_input)
        input_row.addWidget(self.query_btn)
        layout.addLayout(input_row)

        self.dns_meta_label = QLabel("Active Resolvers: System Default | Ready to resolve domain records.")
        self.dns_meta_label.setStyleSheet("color: #8b949e;")
        layout.addWidget(self.dns_meta_label)

        self.dns_table = QTableWidget()
        self.dns_table.setAccessibleName("DNS Records Table")
        self.dns_table.setColumnCount(3)
        self.dns_table.setHorizontalHeaderLabels(["Record Type", "Resolved Address / Value", "TTL"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dns_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.dns_table)

    def _on_resolve_dns(self) -> None:
        """Trigger asynchronous DNS diagnostics with duplicate-launch protection."""
        if self._is_loading:
            return

        host = self.dns_input.text().strip()
        if not host:
            return

        self._is_loading = True
        self.query_btn.setEnabled(False)
        self.query_btn.setText("Resolving...")
        self.dns_meta_label.setText(f"Resolving DNS records for '{host}'...")

        self._request_counter += 1
        req_id = self._request_counter

        worker = AsyncOperationWorker(req_id, self.app.diagnose_dns, host)
        self._active_worker = worker

        AsyncWorkerRunner.launch(
            worker,
            on_finished=self._on_dns_finished,
            on_failed=self._on_dns_failed,
        )

    def _on_dns_finished(self, req_id: int, result: Any) -> None:
        """Handle completed DNS diagnostics on GUI thread."""
        if req_id != self._request_counter:
            return  # Discard stale result

        try:
            if not hasattr(self, "query_btn") or self.query_btn is None:
                return

            self._is_loading = False
            self.query_btn.setEnabled(True)
            self.query_btn.setText("Resolve DNS")
            self.dns_meta_label.setText(
                f"Active Resolvers: {', '.join(result.system_resolvers)} | Latency: {result.response_time_ms} ms | Status: {result.status}"
            )
            self.dns_table.setRowCount(len(result.records))
            for row, rec in enumerate(result.records):
                self.dns_table.setItem(row, 0, QTableWidgetItem(rec.record_type))
                self.dns_table.setItem(row, 1, QTableWidgetItem(rec.value))
                self.dns_table.setItem(row, 2, QTableWidgetItem(str(rec.ttl) if rec.ttl else "Default"))
        except RuntimeError:
            return

    def _on_dns_failed(self, req_id: int, error_msg: str) -> None:
        """Handle DNS diagnostics failure on GUI thread."""
        if req_id != self._request_counter:
            return

        try:
            if not hasattr(self, "query_btn") or self.query_btn is None:
                return

            self._is_loading = False
            self.query_btn.setEnabled(True)
            self.query_btn.setText("Resolve DNS")
            self.dns_meta_label.setText(f"DNS Resolution Failed: {error_msg}")
            self.dns_table.setRowCount(0)
        except RuntimeError:
            return
