"""Wi-Fi Spectrum visualizer and wireless access point security inspection widget."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import QPointF, QRectF, QThread, Qt  # type: ignore
    from PySide6.QtGui import (  # type: ignore
        QBrush,
        QColor,
        QFont,
        QLinearGradient,
        QPainter,
        QPainterPath,
        QPaintEvent,
        QPen,
    )
    from PySide6.QtWidgets import (  # type: ignore
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
    class QThread:  # type: ignore
        pass

from itsa_network_os.core.logger import get_logger
from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WifiSecurityProtocol,
    WirelessSpectrumAnalyzer,
)
from itsa_network_os.ui.desktop.wifi_worker import (
    ActiveThreadRegistry,
    WifiScanResult,
    WifiScanStatus,
    WifiScanWorker,
)

logger = get_logger("itsa_network_os.ui.desktop.wifi_canvas")


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

        # Worker lifecycle & state tracking
        self._thread: Optional[QThread] = None
        self._worker: Optional[WifiScanWorker] = None
        self._active_request_id: int = 0
        self._is_scanning: bool = False
        self._is_closed: bool = False
        self._cached_aps: List[AccessPointInfo] = []

        self._init_ui()
        self._load_initial_fixtures()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Row: Title & Subtitle on left, Band & Action buttons on right
        header_row = QHBoxLayout()
        header_text_box = QVBoxLayout()

        title_badge_row = QHBoxLayout()
        title_badge_row.setSpacing(10)
        title = QLabel("Wi-Fi Spectrum & Wireless Signal Analysis")
        title.setObjectName("HeaderTitle")
        title_badge_row.addWidget(title)

        # Visual provenance badge (Mock vs Live status)
        self.lbl_provenance_badge = QLabel("🧪 OFFLINE MOCK / SIMULATED FIXTURES")
        self.lbl_provenance_badge.setStyleSheet(
            "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        title_badge_row.addWidget(self.lbl_provenance_badge)
        title_badge_row.addStretch()

        header_text_box.addLayout(title_badge_row)

        subtitle = QLabel("Non-destructive 802.11 spectrum utilization, co-channel interference, and security posture.")
        subtitle.setObjectName("HeaderSubtitle")
        header_text_box.addWidget(subtitle)
        header_row.addLayout(header_text_box)
        header_row.addStretch()

        # Action Buttons in Header
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(8)

        self.btn_24ghz = QPushButton("2.4 GHz Band")
        self.btn_24ghz.setMinimumWidth(120)
        self.btn_24ghz.setProperty("class", "PrimaryButton")
        self.btn_24ghz.clicked.connect(lambda: self._switch_band(SpectrumBand.BAND_2_4_GHZ))

        self.btn_5ghz = QPushButton("5 GHz Band")
        self.btn_5ghz.setMinimumWidth(120)
        self.btn_5ghz.setProperty("class", "SecondaryButton")
        self.btn_5ghz.clicked.connect(lambda: self._switch_band(SpectrumBand.BAND_5_GHZ))

        self.btn_scan = QPushButton("Scan Airwaves")
        self.btn_scan.setMinimumWidth(120)
        self.btn_scan.setProperty("class", "SecondaryButton")
        self.btn_scan.clicked.connect(lambda: self.refresh_scan(force_live=False))

        self.btn_live_scan = QPushButton("Live Scan")
        self.btn_live_scan.setMinimumWidth(100)
        self.btn_live_scan.setProperty("class", "SecondaryButton")
        self.btn_live_scan.clicked.connect(lambda: self.refresh_scan(force_live=True))

        self.btn_cancel = QPushButton("Cancel Scan")
        self.btn_cancel.setMinimumWidth(100)
        self.btn_cancel.setProperty("class", "SecondaryButton")
        self.btn_cancel.clicked.connect(self.cancel_scan)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setVisible(False)

        ctrl_box.addWidget(self.btn_24ghz)
        ctrl_box.addWidget(self.btn_5ghz)
        ctrl_box.addWidget(self.btn_scan)
        ctrl_box.addWidget(self.btn_live_scan)
        ctrl_box.addWidget(self.btn_cancel)
        header_row.addLayout(ctrl_box)

        layout.addLayout(header_row)

        # Status and Diagnostic Banner
        self.status_banner = QLabel("")
        self.status_banner.setStyleSheet(
            "background-color: #161b22; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        self.status_banner.setVisible(False)
        layout.addWidget(self.status_banner)

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

    def _load_initial_fixtures(self) -> None:
        """Load initial offline mock fixtures synchronously to populate UI immediately on startup."""
        aps = (
            self.app.get_wifi_access_points(force_live=False)
            if self.app
            else WirelessSpectrumAnalyzer.get_access_points(use_mock=True)
        )
        reports = WirelessSpectrumAnalyzer.analyze_spectrum(aps, band=self.current_band)
        self._cached_aps = aps
        self._update_display(aps, reports)

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

        # Update display immediately from cached APs without blocking
        if self._cached_aps:
            reports = WirelessSpectrumAnalyzer.analyze_spectrum(self._cached_aps, band=self.current_band)
            self._update_display(self._cached_aps, reports)
        elif not self._is_scanning:
            self.refresh_scan()

    def refresh_scan(self, force_live: bool = False) -> None:
        """Scan airwaves asynchronously on a dedicated worker thread."""
        self.start_scan(force_live=force_live)

    def start_scan(self, force_live: bool = False) -> None:
        """Initiate non-blocking asynchronous wireless scan using dedicated QThread."""
        if self._is_scanning or (self._thread is not None and self._thread.isRunning()):
            logger.warning("Scan request ignored: an asynchronous scan is already in progress.")
            return

        self._is_scanning = True
        self._active_request_id += 1
        req_id = self._active_request_id

        # Update button controls to prevent overlapping requests
        self.btn_scan.setEnabled(False)
        self.btn_live_scan.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_cancel.setVisible(True)

        # Update loading indicators
        if force_live:
            self.lbl_provenance_badge.setText("⏳ LIVE SCANNING IN PROGRESS...")
            self.lbl_provenance_badge.setStyleSheet(
                "background-color: #1f3d59; color: #58a6ff; border: 1px solid #388bfd; "
                "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
            )
        else:
            self.lbl_provenance_badge.setText("⏳ REFRESHING SPECTRUM...")
            self.lbl_provenance_badge.setStyleSheet(
                "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
                "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
            )

        self._update_stat_card(self.card_cleanest, "Cleanest Channels", "Scanning...", "#58a6ff")
        self.status_banner.setText("Scanning wireless frequencies outside GUI thread...")
        self.status_banner.setStyleSheet(
            "background-color: #161b22; color: #58a6ff; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        self.status_banner.setVisible(True)

        # Clean up any previously finished thread references before starting new one
        self._cleanup_previous_thread()

        # Instantiate worker and dedicated QThread (unparented to ensure clean lifecycle)
        worker = WifiScanWorker(
            request_id=req_id,
            app=self.app,
            band=self.current_band,
            force_live=force_live,
        )
        thread = QThread()

        # Register thread with process-wide ActiveThreadRegistry to guarantee lifetime
        ActiveThreadRegistry.register(thread, worker)

        self._worker = worker
        self._thread = thread

        worker.moveToThread(thread)

        # Connect signals
        thread.started.connect(worker.execute_scan)
        worker.finished.connect(self._on_scan_finished)
        worker.failed.connect(self._on_scan_failed)
        worker.cancelled.connect(self._on_scan_cancelled)
        worker.status_changed.connect(self._on_scan_status_changed)

        # Thread completion and resource cleanup (DirectConnection ensures quit is called immediately in worker context)
        worker.finished.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        worker.failed.connect(thread.quit, Qt.ConnectionType.DirectConnection)
        worker.cancelled.connect(thread.quit, Qt.ConnectionType.DirectConnection)

        thread.finished.connect(self._on_thread_finished)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        thread.start()

    def cancel_scan(self) -> None:
        """Cooperatively cancel currently running scan."""
        if self._worker is not None and self._is_scanning:
            self.status_banner.setText("Cancelling wireless scan...")
            self._worker.request_cancellation()

    def _on_scan_finished(self, result: WifiScanResult) -> None:
        """Handle completed scan results on the Qt GUI thread."""
        if self._is_closed or result.request_id != self._active_request_id:
            logger.debug("Discarding stale or post-close scan result %d", result.request_id)
            return

        if self._thread is None or not self._thread.isRunning():
            self._is_scanning = False
            self._reset_scan_controls()
        else:
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setVisible(False)

        # Update cached APs
        self._cached_aps = result.access_points

        # Update display on GUI thread
        self._update_display(result.access_points, result.reports)

        # Provenance badge & status banner
        if result.is_mock:
            self.lbl_provenance_badge.setText("🧪 OFFLINE MOCK / SIMULATED FIXTURES")
            self.lbl_provenance_badge.setStyleSheet(
                "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
                "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
            )
            self.status_banner.setText(
                "Displaying simulated lab fixtures for offline demonstration. "
                "These profiles do NOT represent live wireless hardware observations."
            )
            self.status_banner.setStyleSheet(
                "background-color: #161b22; color: #8b949e; border: 1px solid #30363d; "
                "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
            )
            self.status_banner.setVisible(True)
        else:
            if len(result.access_points) == 0:
                self.lbl_provenance_badge.setText("📡 LIVE AIRWAVES (0 APs)")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                diag_msg = " | ".join(result.diagnostics) if result.diagnostics else "Scan cache unpopulated or no networks in range."
                self.status_banner.setText(f"Live Scan: 0 access points discovered. {diag_msg}")
                self.status_banner.setStyleSheet(
                    "background-color: #161b22; color: #f2cc60; border: 1px solid #bb8009; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
            else:
                self.lbl_provenance_badge.setText(f"📡 LIVE AIRWAVES ({len(result.access_points)} APs)")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #04260f; color: #3fb950; border: 1px solid #238636; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                self.status_banner.setText(
                    f"Live Scan: Successfully discovered {len(result.access_points)} wireless access points."
                )
                self.status_banner.setStyleSheet(
                    "background-color: #04260f; color: #3fb950; border: 1px solid #238636; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
            self.status_banner.setVisible(True)

    def _on_scan_failed(self, request_id: int, error_message: str) -> None:
        """Handle scan failure safely on the Qt GUI thread without crashing or mock fallback."""
        if self._is_closed or request_id != self._active_request_id:
            return

        if self._thread is None or not self._thread.isRunning():
            self._is_scanning = False
            self._reset_scan_controls()
        else:
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setVisible(False)

        self.lbl_provenance_badge.setText("⚠️ LIVE SCAN FAILED")
        self.lbl_provenance_badge.setStyleSheet(
            "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        self.status_banner.setText(
            f"Wireless scanning error: {error_message}. "
            "(Failed operations do NOT fall back to mock data or fabricate access points)."
        )
        self.status_banner.setStyleSheet(
            "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        self.status_banner.setVisible(True)

    def _on_scan_cancelled(self, request_id: int) -> None:
        """Handle scan cancellation on the Qt GUI thread."""
        if self._is_closed or request_id != self._active_request_id:
            return

        if self._thread is None or not self._thread.isRunning():
            self._is_scanning = False
            self._reset_scan_controls()
        else:
            self.btn_cancel.setEnabled(False)
            self.btn_cancel.setVisible(False)

        self.lbl_provenance_badge.setText("⛔ SCAN CANCELLED")
        self.lbl_provenance_badge.setStyleSheet(
            "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        self.status_banner.setText("Wireless scanning was cancelled by user request.")
        self.status_banner.setStyleSheet(
            "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        self.status_banner.setVisible(True)

    def _on_scan_status_changed(self, request_id: int, message: str) -> None:
        """Handle progressive status update on the Qt GUI thread."""
        if self._is_closed or request_id != self._active_request_id:
            return
        self.status_banner.setText(message)

    def _reset_scan_controls(self) -> None:
        """Reset button enabled and visibility states."""
        self.btn_scan.setEnabled(True)
        self.btn_live_scan.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.setVisible(False)

    def _update_display(self, aps: List[AccessPointInfo], reports: List[ChannelCongestionReport]) -> None:
        """Update spectrum graph, KPI cards, and access points table on the Qt GUI thread."""
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
        self._update_stat_card(
            self.card_alerts,
            "Security Alerts",
            f"{total_alerts} Warning{'s' if total_alerts != 1 else ''}",
            alert_color,
        )

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

    def _on_thread_finished(self) -> None:
        """Handle thread exit and re-enable scan controls deterministically."""
        if self._is_closed:
            return
        self._is_scanning = False
        self._reset_scan_controls()
        if self._thread is not None and not self._thread.isRunning():
            self._thread = None
            self._worker = None

    def _cleanup_previous_thread(self) -> None:
        """Safely detach references to previously completed thread."""
        if self._thread is not None:
            if not self._thread.isRunning():
                self._thread = None
                self._worker = None

    def _cleanup_active_worker(self, wait_ms: int = 500) -> None:
        """Safely cancel worker and wait for thread during destruction."""
        self._is_closed = True
        if self._worker is not None:
            try:
                self._worker.finished.disconnect(self._on_scan_finished)
            except (RuntimeError, TypeError):
                pass
            try:
                self._worker.failed.disconnect(self._on_scan_failed)
            except (RuntimeError, TypeError):
                pass
            try:
                self._worker.cancelled.disconnect(self._on_scan_cancelled)
            except (RuntimeError, TypeError):
                pass
            try:
                self._worker.status_changed.disconnect(self._on_scan_status_changed)
            except (RuntimeError, TypeError):
                pass
            self._worker.request_cancellation()

        if self._thread is not None:
            try:
                self._thread.finished.disconnect(self._on_thread_finished)
            except (RuntimeError, TypeError):
                pass

            if self._thread.isRunning():
                self._thread.quit()
                self._thread.wait(wait_ms)
                # If wait times out, ActiveThreadRegistry retains ownership of
                # the running QThread, preventing "QThread: Destroyed while thread is still running".
            self._thread = None
            self._worker = None

    def closeEvent(self, event: Any) -> None:
        """Ensure clean shutdown when widget is closed without leaving running threads."""
        self._is_closed = True
        self._cleanup_active_worker(wait_ms=500)
        if hasattr(super(), "closeEvent"):
            super().closeEvent(event)

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
