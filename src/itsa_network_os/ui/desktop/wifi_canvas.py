"""Wi-Fi Spectrum visualizer and wireless access point security inspection widget."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import QPointF, QRectF, Qt
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

from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WifiSecurityProtocol,
    WirelessSpectrumAnalyzer,
)


class SpectrumGraphWidget(QWidget):  # type: ignore
    """Custom graphical widget rendering RF spectrum bell curves over 2.4/5 GHz bands."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(240)
        self.band = SpectrumBand.BAND_2_4_GHZ
        self.access_points: List[AccessPointInfo] = []
        self.setStyleSheet("background-color: #0d1117; border-radius: 8px;")

    def set_data(self, aps: List[AccessPointInfo], band: SpectrumBand) -> None:
        """Update spectrum dataset and trigger repaint."""
        self.access_points = aps
        self.band = band
        self.update()

    def paintEvent(self, event: Any) -> None:  # type: ignore
        """Render RF spectral power distribution curves and channel grids."""
        if not PYSIDE6_AVAILABLE:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        width = self.width()
        height = self.height()

        # Canvas margins
        left_margin = 60
        right_margin = 30
        top_margin = 35
        bottom_margin = 45

        plot_width = width - left_margin - right_margin
        plot_height = height - top_margin - bottom_margin

        baseline_y = height - bottom_margin
        min_rssi = -100
        max_rssi = -25

        # Background frame
        painter.fillRect(0, 0, width, height, QColor("#0d1117"))

        # Channel mapping
        if self.band == SpectrumBand.BAND_2_4_GHZ:
            channel_keys = list(WirelessSpectrumAnalyzer.CHANNELS_2_4_GHZ.keys())  # 1 to 14
        else:
            channel_keys = list(WirelessSpectrumAnalyzer.CHANNELS_5_GHZ.keys())

        num_channels = len(channel_keys)
        if num_channels == 0:
            return

        def channel_to_x(ch: int) -> float:
            if ch in channel_keys:
                idx = channel_keys.index(ch)
                return left_margin + (idx + 0.5) * (plot_width / num_channels)
            return left_margin

        def rssi_to_y(rssi: int) -> float:
            clamped = max(min_rssi, min(max_rssi, rssi))
            ratio = (clamped - min_rssi) / (max_rssi - min_rssi)
            return baseline_y - ratio * plot_height

        # 1. Draw horizontal RSSI grid lines (-90, -80, -70, -60, -50, -40, -30 dBm)
        grid_pen = QPen(QColor("#21262d"), 1, Qt.PenStyle.DashLine)
        painter.setPen(grid_pen)
        painter.setFont(QFont("Segoe UI", 8))

        for dbm in range(-90, -20, 10):
            y = rssi_to_y(dbm)
            painter.drawLine(int(left_margin), int(y), int(width - right_margin), int(y))
            painter.setPen(QColor("#8b949e"))
            painter.drawText(8, int(y + 4), f"{dbm} dBm")
            painter.setPen(grid_pen)

        # Baseline
        painter.setPen(QPen(QColor("#30363d"), 1))
        painter.drawLine(int(left_margin), int(baseline_y), int(width - right_margin), int(baseline_y))

        # 2. Highlight non-overlapping standard channels in 2.4 GHz (1, 6, 11)
        if self.band == SpectrumBand.BAND_2_4_GHZ:
            painter.setBrush(QBrush(QColor(88, 166, 255, 12)))
            painter.setPen(Qt.PenStyle.NoPen)
            for standard_ch in (1, 6, 11):
                cx = channel_to_x(standard_ch)
                cw = (plot_width / num_channels) * 2.2
                painter.drawRoundedRect(QRectF(cx - cw / 2, top_margin, cw, plot_height), 4, 4)

        # 3. Draw vertical channel markers and labels
        channel_slot_width = plot_width / num_channels
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))

        for idx, ch in enumerate(channel_keys):
            cx = left_margin + (idx + 0.5) * channel_slot_width

            # Subdued vertical tick
            painter.setPen(QPen(QColor("#21262d"), 1))
            painter.drawLine(int(cx), int(top_margin), int(cx), int(baseline_y))

            # Channel number label
            is_prime = self.band == SpectrumBand.BAND_2_4_GHZ and ch in (1, 6, 11)
            painter.setPen(QColor("#58a6ff" if is_prime else "#8b949e"))
            painter.drawText(QRectF(cx - 18, baseline_y + 4, 36, 16), Qt.AlignmentFlag.AlignCenter, f"CH {ch}")

            # Frequency in MHz label below
            freq = (
                WirelessSpectrumAnalyzer.CHANNELS_2_4_GHZ.get(ch)
                if self.band == SpectrumBand.BAND_2_4_GHZ
                else WirelessSpectrumAnalyzer.CHANNELS_5_GHZ.get(ch)
            )
            if freq:
                painter.setFont(QFont("Segoe UI", 7))
                painter.setPen(QColor("#484f58"))
                painter.drawText(QRectF(cx - 22, baseline_y + 20, 44, 14), Qt.AlignmentFlag.AlignCenter, f"{freq}")
                painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))

        # Filter access points belonging to current band
        band_aps = [
            ap
            for ap in self.access_points
            if (self.band == SpectrumBand.BAND_2_4_GHZ and ap.channel <= 14)
            or (self.band == SpectrumBand.BAND_5_GHZ and ap.channel > 14)
        ]

        # 4. Render RF parabolic spectral power curves for each AP
        color_palette = {
            WifiSecurityProtocol.WPA3_SAE: QColor("#3fb950"),      # Emerald
            WifiSecurityProtocol.ENTERPRISE: QColor("#bc8cff"),    # Purple
            WifiSecurityProtocol.WPA2_PSK: QColor("#58a6ff"),      # Blue
            WifiSecurityProtocol.OPEN: QColor("#d29922"),          # Amber warning
            WifiSecurityProtocol.WEP: QColor("#f85149"),           # Red critical
            WifiSecurityProtocol.WPA_PSK: QColor("#f0883e"),       # Orange
            WifiSecurityProtocol.UNKNOWN: QColor("#8b949e"),       # Neutral gray
        }

        for ap in band_aps:
            center_x = channel_to_x(ap.channel)
            peak_y = rssi_to_y(ap.rssi_dbm)

            # Span width determined by channel width
            spread_factor = 2.4 if ap.channel_width_mhz <= 20 else 4.5 if ap.channel_width_mhz <= 40 else 7.5
            curve_width = channel_slot_width * spread_factor
            left_x = center_x - curve_width / 2.0
            right_x = center_x + curve_width / 2.0

            base_color = color_palette.get(ap.security, QColor("#58a6ff"))

            # Build smooth cubic bezier bell curve
            path = QPainterPath()
            path.moveTo(left_x, baseline_y)
            path.cubicTo(
                center_x - curve_width * 0.25,
                baseline_y,
                center_x - curve_width * 0.15,
                peak_y,
                center_x,
                peak_y,
            )
            path.cubicTo(
                center_x + curve_width * 0.15,
                peak_y,
                center_x + curve_width * 0.25,
                baseline_y,
                right_x,
                baseline_y,
            )
            path.closeSubpath()

            # Gradient fill (semi-transparent)
            gradient = QLinearGradient(center_x, peak_y, center_x, baseline_y)
            fill_color = QColor(base_color.red(), base_color.green(), base_color.blue(), 55)
            grad_bottom = QColor(base_color.red(), base_color.green(), base_color.blue(), 10)
            gradient.setColorAt(0.0, fill_color)
            gradient.setColorAt(1.0, grad_bottom)

            painter.setBrush(QBrush(gradient))
            painter.setPen(QPen(base_color, 2))
            painter.drawPath(path)

            # Peak label with SSID & RSSI (clamped away from Y-axis text)
            label_text = f"{ap.ssid} ({ap.rssi_dbm} dBm)"
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            painter.setPen(QColor("#f0f6fc"))
            label_w = 160.0
            clamped_x = max(left_margin + label_w / 2.0 + 10.0, min(width - right_margin - label_w / 2.0 - 5.0, center_x))
            painter.drawText(QRectF(clamped_x - label_w / 2.0, peak_y - 18, label_w, 16), Qt.AlignmentFlag.AlignCenter, label_text)


class WifiSpectrumWidget(QWidget):  # type: ignore
    """Complete interactive Wi-Fi inspection page with spectrum curve visualizer and AP table."""

    def __init__(self, app: Any, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.current_band = SpectrumBand.BAND_2_4_GHZ
        self._init_ui()
        self.refresh_scan()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Row: Title & Subtitle on left, Band buttons & Scan button on right
        header_row = QHBoxLayout()
        header_text_box = QVBoxLayout()
        title = QLabel("Wi-Fi Spectrum & Wireless Signal Analysis")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Non-destructive 802.11 spectrum utilization, co-channel interference, and security posture.")
        subtitle.setObjectName("HeaderSubtitle")
        header_text_box.addWidget(title)
        header_text_box.addWidget(subtitle)
        header_row.addLayout(header_text_box)
        header_row.addStretch()

        # Action Buttons in Header
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(8)

        self.btn_24ghz = QPushButton("2.4 GHz Band")
        self.btn_24ghz.setMinimumWidth(130)
        self.btn_24ghz.setProperty("class", "PrimaryButton")
        self.btn_24ghz.clicked.connect(lambda: self._switch_band(SpectrumBand.BAND_2_4_GHZ))

        self.btn_5ghz = QPushButton("5 GHz Band")
        self.btn_5ghz.setMinimumWidth(130)
        self.btn_5ghz.setProperty("class", "SecondaryButton")
        self.btn_5ghz.clicked.connect(lambda: self._switch_band(SpectrumBand.BAND_5_GHZ))

        refresh_btn = QPushButton("Scan Airwaves")
        refresh_btn.setMinimumWidth(120)
        refresh_btn.setProperty("class", "SecondaryButton")
        refresh_btn.clicked.connect(self.refresh_scan)

        ctrl_box.addWidget(self.btn_24ghz)
        ctrl_box.addWidget(self.btn_5ghz)
        ctrl_box.addWidget(refresh_btn)
        header_row.addLayout(ctrl_box)

        layout.addLayout(header_row)

        # Full-width KPI summary cards row (4 even cards)
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self.card_aps = self._make_stat_card("Discovered APs", "0 APs", "#58a6ff")
        self.card_cleanest = self._make_stat_card("Cleanest Channels", "Scanning...", "#3fb950")
        self.card_peak = self._make_stat_card("Strongest Signal", "N/A", "#bc8cff")
        self.card_alerts = self._make_stat_card("Security Alerts", "0 Alerts", "#f85149")

        cards_row.addWidget(self.card_aps)
        cards_row.addWidget(self.card_cleanest)
        cards_row.addWidget(self.card_peak)
        cards_row.addWidget(self.card_alerts)

        layout.addLayout(cards_row)

        # Spectrum Curves Canvas
        self.spectrum_graph = SpectrumGraphWidget(self)
        layout.addWidget(self.spectrum_graph)

        # Access Point Details Table
        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(8)
        self.ap_table.setHorizontalHeaderLabels([
            "SSID",
            "BSSID",
            "RSSI",
            "Signal Quality",
            "Channel / Width",
            "Generation",
            "Security Protocol",
            "Cybersecurity Warnings",
        ])
        header = self.ap_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.ap_table.setColumnWidth(0, 135)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self.ap_table.setColumnWidth(1, 125)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.ap_table.setColumnWidth(6, 150)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)

        self.ap_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.ap_table)

    def _switch_band(self, band: SpectrumBand) -> None:
        """Switch active radio frequency band between 2.4 GHz and 5 GHz."""
        self.current_band = band
        if band == SpectrumBand.BAND_2_4_GHZ:
            self.btn_24ghz.setProperty("class", "PrimaryButton")
            self.btn_5ghz.setProperty("class", "SecondaryButton")
        else:
            self.btn_5ghz.setProperty("class", "PrimaryButton")
            self.btn_24ghz.setProperty("class", "SecondaryButton")

        # Force style re-polish
        self.btn_24ghz.style().polish(self.btn_24ghz)
        self.btn_5ghz.style().polish(self.btn_5ghz)

        self.refresh_scan()

    def refresh_scan(self) -> None:
        """Scan airwaves and update both visual spectrum and AP table."""
        aps: List[AccessPointInfo] = self.app.get_wifi_access_points()
        reports: List[ChannelCongestionReport] = self.app.analyze_wifi_spectrum(band=self.current_band)

        # Update spectrum graph
        self.spectrum_graph.set_data(aps, self.current_band)

        # Update KPI Stat Cards
        band_aps = [
            ap
            for ap in aps
            if (self.current_band == SpectrumBand.BAND_2_4_GHZ and ap.channel <= 14)
            or (self.current_band == SpectrumBand.BAND_5_GHZ and ap.channel > 14)
        ]
        self._update_stat_card(self.card_aps, "Discovered APs", f"{len(band_aps)} in {self.current_band.value}")

        recommended_channels = [str(r.channel) for r in reports if r.recommended]
        rec_text = f"CH {', '.join(recommended_channels)}" if recommended_channels else "None (Congested)"
        self._update_stat_card(self.card_cleanest, "Cleanest Channel", rec_text, "#3fb950")

        strongest_rssi = max((ap.rssi_dbm for ap in band_aps), default=-100)
        strongest_text = f"{strongest_rssi} dBm" if strongest_rssi > -100 else "None"
        self._update_stat_card(self.card_peak, "Strongest Signal", strongest_text, "#bc8cff")

        total_alerts = sum(len(ap.security_warnings) for ap in aps)
        alert_color = "#3fb950" if total_alerts == 0 else "#f85149"
        self._update_stat_card(self.card_alerts, "Security Alerts", f"{total_alerts} Warning{'s' if total_alerts != 1 else ''}", alert_color)

        # Populate AP Table
        self.ap_table.setRowCount(len(aps))
        for row, ap in enumerate(aps):
            self.ap_table.setItem(row, 0, QTableWidgetItem(ap.ssid))
            self.ap_table.setItem(row, 1, QTableWidgetItem(ap.bssid))
            self.ap_table.setItem(row, 2, QTableWidgetItem(f"{ap.rssi_dbm} dBm"))

            quality_str = f"[{'#' * int(ap.signal_percent / 16.6):<6}] {ap.signal_percent}%"
            self.ap_table.setItem(row, 3, QTableWidgetItem(quality_str))

            ch_width_str = f"CH {ap.channel} ({ap.channel_width_mhz} MHz)"
            self.ap_table.setItem(row, 4, QTableWidgetItem(ch_width_str))

            self.ap_table.setItem(row, 5, QTableWidgetItem(ap.standard.value))
            self.ap_table.setItem(row, 6, QTableWidgetItem(ap.security.value))

            warnings_str = " | ".join(ap.security_warnings) if ap.security_warnings else "Secure"
            warn_item = QTableWidgetItem(warnings_str)
            if ap.security_warnings:
                warn_item.setForeground(QBrush(QColor("#f85149")))
            else:
                warn_item.setForeground(QBrush(QColor("#3fb950")))
            self.ap_table.setItem(row, 7, warn_item)

    def _make_stat_card(self, title_text: str, value_text: str, color: str = "#f0f6fc") -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        title = QLabel(title_text)
        title.setObjectName("CardTitle")
        value = QLabel(value_text)
        value.setObjectName("ValueBadge")
        value.setStyleSheet(f"color: {color};")
        layout.addWidget(title)
        layout.addWidget(value)
        return card

    def _update_stat_card(self, card: QFrame, title_text: str, value_text: str, color: Optional[str] = None) -> None:
        labels = card.findChildren(QLabel)
        if len(labels) >= 2:
            labels[0].setText(title_text)
            labels[1].setText(value_text)
            if color:
                labels[1].setStyleSheet(f"color: {color};")
