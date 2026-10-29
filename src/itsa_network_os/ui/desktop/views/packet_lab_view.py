"""Packet protocol laboratory desktop view."""

from __future__ import annotations

from typing import List, Optional

try:
    from PySide6.QtWidgets import (
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QListWidget,
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
from itsa_network_os.network.scope import ScopeViolationError
from itsa_network_os.security.lab import ParsedPacket


class PacketLabView(QWidget):  # type: ignore
    """Educational packet and protocol dissection laboratory view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.sample_packets: List[ParsedPacket] = []
        self.setAccessibleName("Packet Protocol Laboratory View")
        self.setAccessibleDescription("Isolated packet dissection and protocol analysis for cybersecurity learners.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header_row = QHBoxLayout()
        header_text = QVBoxLayout()
        title = QLabel("Educational Packet & Protocol Laboratory")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Isolated packet dissection and protocol analysis for cybersecurity learners.")
        subtitle.setObjectName("HeaderSubtitle")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header_row.addLayout(header_text)
        header_row.addStretch()

        self.lab_provenance_badge = QLabel("🧪 SYNTHETIC PACKET TRACE")
        self.lab_provenance_badge.setStyleSheet(
            "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        header_row.addWidget(self.lab_provenance_badge)
        layout.addLayout(header_row)

        ctrl_bar = QHBoxLayout()
        self.btn_synth_trace = QPushButton("Sample Trace")
        self.btn_synth_trace.setProperty("class", "SecondaryButton")
        self.btn_synth_trace.setAccessibleName("Load Sample Trace Button")
        self.btn_synth_trace.clicked.connect(self._load_synthetic_packets)

        self.btn_live_capture = QPushButton("Live Capture (Polkit)")
        self.btn_live_capture.setProperty("class", "SecondaryButton")
        self.btn_live_capture.setAccessibleName("Start Live Capture Button")
        self.btn_live_capture.clicked.connect(self._load_live_packets)

        ctrl_bar.addWidget(self.btn_synth_trace)
        ctrl_bar.addWidget(self.btn_live_capture)
        ctrl_bar.addStretch()
        layout.addLayout(ctrl_bar)

        self.lab_status_banner = QLabel("")
        self.lab_status_banner.setStyleSheet(
            "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        self.lab_status_banner.setVisible(False)
        layout.addWidget(self.lab_status_banner)

        self.packet_selector = QListWidget()
        self.packet_selector.setAccessibleName("Packet Selector List")
        self.packet_selector.setFixedHeight(120)
        self.packet_selector.currentRowChanged.connect(self._on_packet_selected)
        layout.addWidget(self.packet_selector)

        self.lab_table = QTableWidget()
        self.lab_table.setAccessibleName("Packet Dissection Details Table")
        self.lab_table.setColumnCount(3)
        self.lab_table.setHorizontalHeaderLabels(["Protocol Layer / Field", "Decoded Value", "Educational Cybersecurity Explanation"])
        self.lab_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lab_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.lab_table)

        self._load_synthetic_packets()

    def _load_synthetic_packets(self) -> None:
        self.lab_status_banner.setVisible(False)
        self.lab_provenance_badge.setText("🧪 SYNTHETIC PACKET TRACE")
        self.lab_provenance_badge.setStyleSheet(
            "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        self.sample_packets = self.app.get_packet_lab_trace(force_live=False)
        self._populate_packet_selector()

    def _load_live_packets(self) -> None:
        self.lab_status_banner.setVisible(False)
        try:
            live_pkts = self.app.get_packet_lab_trace(force_live=True)
            self.sample_packets = live_pkts
            self.lab_provenance_badge.setText(f"📡 LIVE AIRWAVES / CAP_NET_RAW ({len(live_pkts)} Pkts)")
            self.lab_provenance_badge.setStyleSheet(
                "background-color: #04260f; color: #3fb950; border: 1px solid #238636; "
                "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
            )
            self._populate_packet_selector()
        except PermissionError as exc:
            self.lab_status_banner.setText(f"PolicyKit Authorization Denied: {exc}")
            self.lab_status_banner.setVisible(True)
        except ScopeViolationError as exc:
            self.lab_status_banner.setText(f"Scope Configuration Error: {exc}")
            self.lab_status_banner.setVisible(True)
        except Exception as exc:
            self.lab_status_banner.setText(f"Privileged Packet Capture Unavailable: {exc}")
            self.lab_status_banner.setVisible(True)

    def _populate_packet_selector(self) -> None:
        self.packet_selector.clear()
        for pkt in self.sample_packets:
            item_text = f"Packet #{pkt.index} | {pkt.protocol:<8} | {pkt.src} -> {pkt.dst} | {pkt.summary}"
            self.packet_selector.addItem(item_text)

        if self.sample_packets:
            self.packet_selector.setCurrentRow(0)

    def _on_packet_selected(self, index: int) -> None:
        if index < 0 or index >= len(self.sample_packets):
            return
        pkt = self.sample_packets[index]

        rows = []
        for layer in pkt.layers:
            rows.append((f"[{layer.layer_name}]", "", ""))
            for f in layer.fields:
                rows.append((f"  • {f.name}", f.value, f.explanation))

        self.lab_table.setRowCount(len(rows))
        for row_idx, (col0, col1, col2) in enumerate(rows):
            self.lab_table.setItem(row_idx, 0, QTableWidgetItem(col0))
            self.lab_table.setItem(row_idx, 1, QTableWidgetItem(col1))
            self.lab_table.setItem(row_idx, 2, QTableWidgetItem(col2))
