"""Live Bandwidth & Traffic Flow Monitor canvas widget for desktop dashboard."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

try:
    from PySide6.QtCore import QPointF, QRectF, QTimer, Qt
    from PySide6.QtGui import (
        QBrush,
        QColor,
        QFont,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPaintEvent,
        QPen,
    )
    from PySide6.QtWidgets import (
        QComboBox,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
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

from itsa_network_os.network.bandwidth import (
    BandwidthRate,
    format_bytes_rate,
    format_total_bytes,
)


class ThroughputGraphWidget(QWidget):  # type: ignore
    """Dual-stream visual area chart rendering real-time RX and TX throughput velocity."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(240)
        self.history_len = 35
        # List of (rx_bytes_sec, tx_bytes_sec)
        self.history: List[Tuple[float, float]] = []
        self.max_rx: float = 0.0
        self.max_tx: float = 0.0
        self.setStyleSheet("background-color: #0d1117; border-radius: 8px;")

        # Initialize with smooth starting history
        base_rx = 2_150_000.0
        base_tx = 640_000.0
        import math
        for i in range(self.history_len):
            factor = 1.0 + 0.35 * math.sin(i * 0.35)
            tx_factor = 1.0 + 0.28 * math.cos(i * 0.45)
            self.history.append((base_rx * factor, base_tx * tx_factor))

    def add_point(self, rx_sec: float, tx_sec: float) -> None:
        """Append newest bandwidth measurement and update rolling window."""
        self.history.append((rx_sec, tx_sec))
        if len(self.history) > self.history_len:
            self.history.pop(0)

        self.max_rx = max(self.max_rx, rx_sec)
        self.max_tx = max(self.max_tx, tx_sec)
        self.update()

    def reset_history(self) -> None:
        """Clear current throughput timeline."""
        self.history.clear()
        self.max_rx = 0.0
        self.max_tx = 0.0
        self.update()

    def paintEvent(self, event: Optional[QPaintEvent] = None) -> None:
        """Render area curves, auto-scaling gridlines, and speed legends."""
        if not PYSIDE6_AVAILABLE:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        width = self.width()
        height = self.height()

        left_margin = 75
        right_margin = 40
        top_margin = 35
        bottom_margin = 35

        plot_width = width - left_margin - right_margin
        plot_height = height - top_margin - bottom_margin
        baseline_y = height - bottom_margin

        # Background canvas fill
        painter.fillRect(0, 0, width, height, QColor("#0d1117"))

        if not self.history:
            return

        # Determine peak scale for dynamic Y autoscaling (headroom + 25%)
        peak_rate = max(max(rx for rx, _ in self.history), max(tx for _, tx in self.history), 100_000.0) * 1.25

        def y_coord(val: float) -> float:
            ratio = min(1.0, max(0.0, val / peak_rate))
            return baseline_y - ratio * plot_height

        def x_coord(index: int) -> float:
            total_slots = max(1, self.history_len - 1)
            return left_margin + (index / total_slots) * plot_width

        # 1. Draw horizontal speed grid lines (4 horizontal divisions)
        grid_pen = QPen(QColor("#21262d"), 1, Qt.PenStyle.DashLine)
        painter.setPen(grid_pen)
        painter.setFont(QFont("Segoe UI", 8))

        for div in range(1, 5):
            val = (peak_rate / 4.0) * div
            y = y_coord(val)
            painter.drawLine(int(left_margin), int(y), int(width - right_margin), int(y))
            painter.setPen(QColor("#8b949e"))
            painter.drawText(8, int(y + 4), format_bytes_rate(val))
            painter.setPen(grid_pen)

        # Baseline axis line
        painter.setPen(QPen(QColor("#30363d"), 1))
        painter.drawLine(int(left_margin), int(baseline_y), int(width - right_margin), int(baseline_y))

        # 2. X-axis timeline markers (-30s, -20s, -10s, Now)
        painter.setFont(QFont("Segoe UI", 8))
        painter.setPen(QColor("#8b949e"))
        x_marks = [
            (0.0, "-35s"),
            (0.28, "-25s"),
            (0.57, "-15s"),
            (0.85, "-5s"),
            (1.0, "Live (Now)"),
        ]
        for ratio, label in x_marks:
            mx = left_margin + ratio * plot_width
            painter.setPen(QPen(QColor("#21262d"), 1))
            painter.drawLine(int(mx), int(top_margin), int(mx), int(baseline_y))
            painter.setPen(QColor("#58a6ff" if "Live" in label else "#6e7681"))
            align = Qt.AlignmentFlag.AlignRight if "Live" in label else Qt.AlignmentFlag.AlignCenter
            painter.drawText(QRectF(mx - 40, baseline_y + 6, 75, 16), align, label)

        # 3. Build paths for RX (Download) and TX (Upload)
        rx_path = QPainterPath()
        rx_path.moveTo(x_coord(0), baseline_y)

        tx_path = QPainterPath()
        tx_path.moveTo(x_coord(0), baseline_y)

        for i, (rx_val, tx_val) in enumerate(self.history):
            px = x_coord(i)
            rx_y = y_coord(rx_val)
            tx_y = y_coord(tx_val)
            if i == 0:
                rx_path.lineTo(px, rx_y)
                tx_path.lineTo(px, tx_y)
            else:
                rx_path.lineTo(px, rx_y)
                tx_path.lineTo(px, tx_y)

        # Close area for fills
        last_x = x_coord(len(self.history) - 1)
        rx_fill_path = QPainterPath(rx_path)
        rx_fill_path.lineTo(last_x, baseline_y)
        rx_fill_path.closeSubpath()

        tx_fill_path = QPainterPath(tx_path)
        tx_fill_path.lineTo(last_x, baseline_y)
        tx_fill_path.closeSubpath()

        # Render RX Area (Emerald)
        rx_grad = QLinearGradient(0, top_margin, 0, baseline_y)
        rx_grad.setColorAt(0.0, QColor(63, 185, 80, 75))
        rx_grad.setColorAt(1.0, QColor(63, 185, 80, 8))
        painter.setBrush(QBrush(rx_grad))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(rx_fill_path)

        painter.setPen(QPen(QColor("#3fb950"), 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(rx_path)

        # Render TX Area (Electric Blue)
        tx_grad = QLinearGradient(0, top_margin, 0, baseline_y)
        tx_grad.setColorAt(0.0, QColor(88, 166, 255, 65))
        tx_grad.setColorAt(1.0, QColor(88, 166, 255, 6))
        painter.setBrush(QBrush(tx_grad))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPath(tx_fill_path)

        painter.setPen(QPen(QColor("#58a6ff"), 2))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(tx_path)

        # 4. Legend and Current Speed Badges at top right
        curr_rx, curr_tx = self.history[-1]
        legend_rx_text = f"⬇ RX Download: {format_bytes_rate(curr_rx)}"
        legend_tx_text = f"⬆ TX Upload: {format_bytes_rate(curr_tx)}"

        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        painter.setPen(QColor("#3fb950"))
        painter.drawText(QRectF(width - right_margin - 340, top_margin - 22, 160, 20), Qt.AlignmentFlag.AlignRight, legend_rx_text)

        painter.setPen(QColor("#58a6ff"))
        painter.drawText(QRectF(width - right_margin - 170, top_margin - 22, 160, 20), Qt.AlignmentFlag.AlignRight, legend_tx_text)


class BandwidthMonitorWidget(QWidget):  # type: ignore
    """Complete interactive Bandwidth & Traffic Flow page with live graph and interface metrics."""

    def __init__(self, app: Any, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.is_monitoring: bool = True
        self.selected_iface: str = "eth0"
        self._init_ui()

        # Polling timer (ticks every 1000 ms)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_timer_tick)
        self.timer.start(1000)

        # Initial sample
        self._on_timer_tick()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Row
        header_row = QHBoxLayout()
        header_text = QVBoxLayout()
        title = QLabel("Live Bandwidth & Traffic Flow Monitor")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Real-time interface throughput, packet counters, and transmission velocity.")
        subtitle.setObjectName("HeaderSubtitle")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header_row.addLayout(header_text)
        header_row.addStretch()

        # Interface selector and control buttons
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(8)

        iface_lbl = QLabel("Adapter:")
        iface_lbl.setStyleSheet("color: #8b949e; font-weight: bold;")
        ctrl_box.addWidget(iface_lbl)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(110)
        self.iface_combo.addItems(["eth0", "wlan0", "lo"])
        self.iface_combo.currentTextChanged.connect(self._on_iface_changed)
        ctrl_box.addWidget(self.iface_combo)

        self.pause_btn = QPushButton("Pause Stream")
        self.pause_btn.setMinimumWidth(110)
        self.pause_btn.setProperty("class", "SecondaryButton")
        self.pause_btn.clicked.connect(self._toggle_monitor)
        ctrl_box.addWidget(self.pause_btn)

        reset_btn = QPushButton("Reset Graph")
        reset_btn.setMinimumWidth(100)
        reset_btn.setProperty("class", "SecondaryButton")
        reset_btn.clicked.connect(self._reset_graph)
        ctrl_box.addWidget(reset_btn)

        header_row.addLayout(ctrl_box)
        layout.addLayout(header_row)

        # KPI Summary Stat Cards
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self.card_rx_rate = self._make_stat_card("Current Download (RX)", "0.00 B/s", "#3fb950")
        self.card_tx_rate = self._make_stat_card("Current Upload (TX)", "0.00 B/s", "#58a6ff")
        self.card_packet_velocity = self._make_stat_card("Packet Flow Rate", "0 pkts/s", "#bc8cff")
        self.card_error_status = self._make_stat_card("Interface Integrity", "0 Errors / 0 Drops", "#3fb950")

        cards_row.addWidget(self.card_rx_rate)
        cards_row.addWidget(self.card_tx_rate)
        cards_row.addWidget(self.card_packet_velocity)
        cards_row.addWidget(self.card_error_status)

        layout.addLayout(cards_row)

        # Throughput live graph
        self.graph_widget = ThroughputGraphWidget(self)
        layout.addWidget(self.graph_widget)

        # All-interfaces table
        self.rates_table = QTableWidget()
        self.rates_table.setColumnCount(8)
        self.rates_table.setHorizontalHeaderLabels([
            "Adapter",
            "RX Speed",
            "TX Speed",
            "RX Packets/s",
            "TX Packets/s",
            "Total Received",
            "Total Transmitted",
            "Errors / Dropped",
        ])
        header = self.rates_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.rates_table.setColumnWidth(0, 80)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.rates_table.setColumnWidth(1, 100)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        self.rates_table.setColumnWidth(2, 100)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self.rates_table.setColumnWidth(5, 105)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.rates_table.setColumnWidth(6, 105)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)

        self.rates_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rates_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.rates_table)

    def _toggle_monitor(self) -> None:
        """Toggle live polling state between active and paused."""
        self.is_monitoring = not self.is_monitoring
        if self.is_monitoring:
            self.pause_btn.setText("Pause Stream")
            self.pause_btn.setProperty("class", "SecondaryButton")
            self.timer.start(1000)
        else:
            self.pause_btn.setText("Resume Stream")
            self.pause_btn.setProperty("class", "PrimaryButton")
            self.timer.stop()
        self.pause_btn.style().polish(self.pause_btn)

    def _reset_graph(self) -> None:
        """Clear throughput history points."""
        self.graph_widget.reset_history()

    def _on_iface_changed(self, iface_name: str) -> None:
        """Switch active graph focus to selected adapter."""
        self.selected_iface = iface_name
        self.graph_widget.reset_history()
        self._on_timer_tick()

    def _on_timer_tick(self) -> None:
        """Sample fresh network counters and refresh graph and table."""
        rates: List[BandwidthRate] = self.app.sample_bandwidth()
        if not rates:
            return

        # Synchronize interface combobox if new interfaces discovered
        existing_items = [self.iface_combo.itemText(i) for i in range(self.iface_combo.count())]
        for r in rates:
            if r.interface_name not in existing_items:
                self.iface_combo.addItem(r.interface_name)

        # Find target rate for selected interface
        target_rate = next((r for r in rates if r.interface_name == self.selected_iface), rates[0])

        # Push to visual graph
        self.graph_widget.add_point(target_rate.rx_bytes_sec, target_rate.tx_bytes_sec)

        # Update KPI Cards
        self._update_stat_card(self.card_rx_rate, "Current Download (RX)", target_rate.rx_rate_formatted, "#3fb950")
        self._update_stat_card(self.card_tx_rate, "Current Upload (TX)", target_rate.tx_rate_formatted, "#58a6ff")

        pkts_text = f"⬇ {int(target_rate.rx_packets_sec):,} | ⬆ {int(target_rate.tx_packets_sec):,} pkts/s"
        self._update_stat_card(self.card_packet_velocity, "Packet Flow Rate", pkts_text, "#bc8cff")

        err_text = f"{target_rate.rx_errors + target_rate.tx_errors} Errors | {target_rate.rx_dropped + target_rate.tx_dropped} Drops"
        err_color = "#3fb950" if (target_rate.rx_errors + target_rate.rx_dropped) == 0 else "#f85149"
        self._update_stat_card(self.card_error_status, "Interface Integrity", err_text, err_color)

        # Update all-interfaces table
        self.rates_table.setRowCount(len(rates))
        for row, r in enumerate(rates):
            self.rates_table.setItem(row, 0, QTableWidgetItem(r.interface_name))

            rx_item = QTableWidgetItem(r.rx_rate_formatted)
            rx_item.setForeground(QBrush(QColor("#3fb950")))
            self.rates_table.setItem(row, 1, rx_item)

            tx_item = QTableWidgetItem(r.tx_rate_formatted)
            tx_item.setForeground(QBrush(QColor("#58a6ff")))
            self.rates_table.setItem(row, 2, tx_item)

            self.rates_table.setItem(row, 3, QTableWidgetItem(f"{r.rx_packets_sec:,.1f}"))
            self.rates_table.setItem(row, 4, QTableWidgetItem(f"{r.tx_packets_sec:,.1f}"))
            self.rates_table.setItem(row, 5, QTableWidgetItem(format_total_bytes(r.total_rx_bytes)))
            self.rates_table.setItem(row, 6, QTableWidgetItem(format_total_bytes(r.total_tx_bytes)))

            err_summary = f"{r.rx_errors + r.tx_errors} err / {r.rx_dropped + r.tx_dropped} drop"
            self.rates_table.setItem(row, 7, QTableWidgetItem(err_summary))

    def _make_stat_card(self, title_text: str, value_text: str, color: str = "#f0f6fc") -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        title = QLabel(title_text)
        title.setObjectName("CardTitle")
        value = QLabel(value_text)
        value.setObjectName("ValueBadge")
        value.setStyleSheet(f"color: {color}; font-size: 15px; font-weight: bold;")
        layout.addWidget(title)
        layout.addWidget(value)
        return card

    def _update_stat_card(self, card: QFrame, title_text: str, value_text: str, color: Optional[str] = None) -> None:
        labels = card.findChildren(QLabel)
        if len(labels) >= 2:
            labels[0].setText(title_text)
            labels[1].setText(value_text)
            if color:
                labels[1].setStyleSheet(f"color: {color}; font-size: 15px; font-weight: bold;")
