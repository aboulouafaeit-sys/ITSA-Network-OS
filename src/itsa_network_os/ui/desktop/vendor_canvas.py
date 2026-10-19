"""Multi-Vendor Hardware & IP Surveillance Camera manager desktop canvas widget."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPushButton,
        QScrollArea,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.network.vendor_manager import (
    CameraTelemetry,
    DeviceCategory,
    DeviceSecurityStatus,
    DiscoveryMode,
    DiscoveryStatus,
    ManagedDevice,
    RouterOSTelemetry,
    VendorDiscoveryReport,
    VendorManagerEngine,
    WirelessLinkTelemetry,
)


class VendorDeviceManagerWidget(QWidget):  # type: ignore
    """Interactive desktop dashboard widget for inspecting multi-vendor devices and IP surveillance cameras."""

    def __init__(self, parent: Optional[QWidget] = None, app: Optional[Any] = None) -> None:
        super().__init__(parent)
        self.app = app or getattr(parent, "app", None)
        self.all_devices: List[ManagedDevice] = []
        self.current_filtered_devices: List[ManagedDevice] = []
        self.selected_device: Optional[ManagedDevice] = None
        self.active_category_filter: Optional[DeviceCategory] = None
        self.current_report: Optional[VendorDiscoveryReport] = None

        if not PYSIDE6_AVAILABLE:
            return

        self._build_ui()
        self.load_mock_fixtures()

    def _build_ui(self) -> None:
        """Construct user interface layout and controls."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # Header Title & Scan Button
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        title = QLabel("Multi-Vendor Hardware & IP Surveillance Device Manager")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")

        sub = QLabel(
            "Unified discovery and inspection for ONVIF/RTSP surveillance cameras, MikroTik (MNDP), "
            "Ubiquiti (airMAX/UniFi), TP-Link Pharos CPEs, and Linux servers."
        )
        sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        title_box.addWidget(title)
        title_box.addWidget(sub)

        # Provenance badge
        self.lbl_provenance_badge = QLabel("🧪 OFFLINE MOCK / SIMULATED FIXTURES")
        self.lbl_provenance_badge.setStyleSheet(
            "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
            "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
        )
        title_box.addWidget(self.lbl_provenance_badge)

        header_layout.addLayout(title_box, stretch=1)

        btn_box = QHBoxLayout()
        btn_box.setSpacing(8)

        self.btn_live_scan = QPushButton("📡 Start Live Passive Discovery")
        self.btn_live_scan.setToolTip(
            "Passively listen on UDP 5678 (MNDP) and UDP 3702 (ONVIF) for broadcast announcements.\n"
            "Strictly unprivileged and non-transmitting (zero active queries)."
        )
        self.btn_live_scan.setStyleSheet(
            "QPushButton { background-color: #1f6feb; color: #ffffff; font-weight: bold; "
            "border: none; border-radius: 6px; padding: 8px 14px; font-size: 12px; } "
            "QPushButton:hover { background-color: #388bfd; } "
            "QPushButton:pressed { background-color: #1158c7; }"
        )
        self.btn_live_scan.clicked.connect(lambda: self.start_live_discovery(timeout=5.0))
        btn_box.addWidget(self.btn_live_scan)

        self.btn_mock = QPushButton("🧪 Load Mock Fixtures")
        self.btn_mock.setToolTip("Load simulated laboratory hardware profiles for offline demonstration.")
        self.btn_mock.setStyleSheet(
            "QPushButton { background-color: #21262d; color: #c9d1d9; font-weight: bold; "
            "border: 1px solid #30363d; border-radius: 6px; padding: 8px 14px; font-size: 12px; } "
            "QPushButton:hover { background-color: #30363d; color: #ffffff; } "
            "QPushButton:pressed { background-color: #161b22; }"
        )
        self.btn_mock.clicked.connect(self.load_mock_fixtures)
        btn_box.addWidget(self.btn_mock)

        # Legacy alias for test compatibility
        self.btn_scan = self.btn_mock

        header_layout.addLayout(btn_box)
        main_layout.addLayout(header_layout)

        # Status & Diagnostic Notification Banner
        self.status_banner = QLabel("")
        self.status_banner.setWordWrap(True)
        self.status_banner.setStyleSheet(
            "background-color: #161b22; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
        )
        main_layout.addWidget(self.status_banner)

        # Filter Category Bar
        filter_card = QFrame()
        filter_card.setObjectName("VendorFilterCard")
        filter_card.setStyleSheet(
            "QFrame#VendorFilterCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        filter_layout = QHBoxLayout(filter_card)
        filter_layout.setContentsMargins(12, 8, 12, 8)
        filter_layout.setSpacing(8)

        lbl_filter = QLabel("Vendor Filter:")
        lbl_filter.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        filter_layout.addWidget(lbl_filter)

        self.filter_buttons: Dict[Optional[DeviceCategory], QPushButton] = {}
        filters = [
            ("All Devices", None),
            ("📹 Cameras", DeviceCategory.IP_CAMERA),
            ("⚙️ MikroTik", DeviceCategory.MIKROTIK),
            ("📡 Ubiquiti", DeviceCategory.UBIQUITI),
            ("📶 TP-Link CPE", DeviceCategory.TPLINK_CPE),
            ("🐧 Linux / Ubuntu", DeviceCategory.LINUX_SERVER),
        ]

        for text, cat in filters:
            btn = QPushButton(text)
            btn.setStyleSheet(self._filter_btn_style(cat == self.active_category_filter))
            btn.clicked.connect(lambda _, c=cat: self._on_filter_clicked(c))
            filter_layout.addWidget(btn)
            self.filter_buttons[cat] = btn

        filter_layout.addStretch()
        main_layout.addWidget(filter_card)

        # 4 KPI Stat Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_total = self._create_kpi_card("Total Managed Devices", "8 Online", "#58a6ff")
        self.card_cams = self._create_kpi_card("IP Surveillance Cameras", "2 Feeds", "#3fb950")
        self.card_wireless = self._create_kpi_card("Outdoor Wireless CPEs", "2 Links (PtP/PtMP)", "#f2cc60")
        self.card_sec = self._create_kpi_card("Security Alerts", "2 Advisories", "#f85149")

        stats_layout.addWidget(self.card_total)
        stats_layout.addWidget(self.card_cams)
        stats_layout.addWidget(self.card_wireless)
        stats_layout.addWidget(self.card_sec)
        main_layout.addLayout(stats_layout)

        # Center Split: Devices Table (Left 58%) + Telemetry Inspection Card (Right 42%)
        center_layout = QHBoxLayout()
        center_layout.setSpacing(12)

        # Left Table
        self.devices_table = QTableWidget(0, 6)
        self.devices_table.setHorizontalHeaderLabels(["Name", "Vendor", "Category", "IP Address", "Firmware", "Status"])
        self.devices_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.devices_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.devices_table.setColumnWidth(1, 85)
        self.devices_table.setColumnWidth(2, 130)
        self.devices_table.setColumnWidth(3, 105)
        self.devices_table.setColumnWidth(4, 110)
        self.devices_table.setColumnWidth(5, 75)
        self.devices_table.verticalHeader().setVisible(False)
        self.devices_table.setStyleSheet(
            "QTableWidget { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 8px; gridline-color: #21262d; } "
            "QHeaderView::section { background-color: #161b22; color: #8b949e; "
            "border: none; padding: 6px; font-size: 11px; font-weight: bold; } "
            "QTableWidget::item:selected { background-color: #1f6feb; color: #ffffff; }"
        )
        self.devices_table.itemSelectionChanged.connect(self._on_table_selection_changed)
        center_layout.addWidget(self.devices_table, stretch=6)

        # Right Telemetry Card
        self.telemetry_card = self._create_telemetry_card()
        center_layout.addWidget(self.telemetry_card, stretch=4)

        main_layout.addLayout(center_layout, stretch=1)

    def _filter_btn_style(self, is_active: bool) -> str:
        if is_active:
            return (
                "QPushButton { background-color: #1f6feb; color: #ffffff; font-weight: bold; "
                "border: 1px solid #388bfd; border-radius: 6px; padding: 5px 12px; font-size: 11px; }"
            )
        return (
            "QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 5px 12px; font-size: 11px; } "
            "QPushButton:hover { background-color: #30363d; color: #58a6ff; }"
        )

    def _create_kpi_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setObjectName("VendorKpiCard")
        card.setStyleSheet(
            "QFrame#VendorKpiCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")

        lbl_val = QLabel(initial_val)
        lbl_val.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        lbl_val.setStyleSheet(f"color: {color_hex};")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        card.setProperty("val_label", lbl_val)
        return card

    def _create_telemetry_card(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("TelemetryDetailCard")
        frame.setStyleSheet(
            "QFrame#TelemetryDetailCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        # Header info
        self.lbl_tel_title = QLabel("Device Telemetry & Service Inspector")
        self.lbl_tel_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.lbl_tel_title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(self.lbl_tel_title)

        self.lbl_tel_sub = QLabel("Select an equipment node to inspect RTSP streams, wireless signal, or OS metrics.")
        self.lbl_tel_sub.setStyleSheet("color: #8b949e; font-size: 11px;")
        self.lbl_tel_sub.setWordWrap(True)
        layout.addWidget(self.lbl_tel_sub)

        # Grid of General Specifications
        self.spec_grid = QGridLayout()
        self.spec_grid.setHorizontalSpacing(10)
        self.spec_grid.setVerticalSpacing(6)

        def add_spec(row: int, title_str: str) -> QLabel:
            lbl = QLabel(title_str)
            lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
            val = QLabel("—")
            val.setStyleSheet("color: #f0f6fc; font-size: 12px;")
            self.spec_grid.addWidget(lbl, row, 0)
            self.spec_grid.addWidget(val, row, 1)
            return val

        self.lbl_spec_ip = add_spec(0, "IP Address:")
        self.lbl_spec_mac = add_spec(1, "MAC Address:")
        self.lbl_spec_vendor = add_spec(2, "Vendor & Model:")
        self.lbl_spec_fw = add_spec(3, "Firmware / OS:")
        self.lbl_spec_proto = add_spec(4, "Discovery Protocol:")
        layout.addLayout(self.spec_grid)

        # Specialized Section Header
        self.lbl_specialized_header = QLabel("Specialized Telemetry:")
        self.lbl_specialized_header.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 11px; margin-top: 6px;")
        layout.addWidget(self.lbl_specialized_header)

        # Content Box (copyable text box)
        self.content_box = QLabel("—")
        self.content_box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.content_box.setStyleSheet(
            "background-color: #0d1117; color: #a5d6ff; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 8px 10px; font-family: monospace; font-size: 11px;"
        )
        self.content_box.setWordWrap(True)
        layout.addWidget(self.content_box)

        # Advisories Title & List
        self.lbl_advisory_title = QLabel("Security Advisories & Hardening:")
        self.lbl_advisory_title.setStyleSheet("color: #d29922; font-weight: bold; font-size: 11px; margin-top: 4px;")
        layout.addWidget(self.lbl_advisory_title)

        self.advisory_box = QLabel("None")
        self.advisory_box.setStyleSheet(
            "background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 6px 10px; font-size: 11px;"
        )
        self.advisory_box.setWordWrap(True)
        layout.addWidget(self.advisory_box)

        layout.addStretch()
        return frame

    def _on_filter_clicked(self, category: Optional[DeviceCategory]) -> None:
        """Handle category filter switch."""
        self.active_category_filter = category
        for cat, btn in self.filter_buttons.items():
            btn.setStyleSheet(self._filter_btn_style(cat == category))
        self._apply_filter()

    def load_mock_fixtures(self) -> None:
        """Explicitly load simulated laboratory hardware profiles for offline demonstration."""
        report = VendorManagerEngine.discover_devices(category_filter=None, mode=DiscoveryMode.MOCK)
        self._apply_report(report)

    def start_live_discovery(self, timeout: float = 5.0) -> None:
        """Execute explicit live passive broadcast listening."""
        if self.app is not None:
            report = self.app.discover_vendor_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=timeout,
            )
        else:
            report = VendorManagerEngine.discover_devices(
                mode=DiscoveryMode.LIVE_PASSIVE,
                timeout=timeout,
            )
        self._apply_report(report)

    def refresh_devices(self) -> None:
        """Backwards-compatible method for reloading mock devices."""
        self.load_mock_fixtures()

    def _apply_report(self, report: VendorDiscoveryReport) -> None:
        """Update UI state, badges, banners, and KPI cards from discovery report."""
        self.current_report = report
        self.all_devices = report.devices

        # Update Provenance Badge and Status Banner
        if report.is_mock:
            self.lbl_provenance_badge.setText("🧪 OFFLINE MOCK / SIMULATED FIXTURES")
            self.lbl_provenance_badge.setStyleSheet(
                "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
                "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
            )
            self.status_banner.setText(
                "Displaying simulated lab fixtures for offline demonstration. "
                "These profiles do NOT represent actual network traffic or live hardware observations."
            )
            self.status_banner.setStyleSheet(
                "background-color: #161b22; color: #d29922; border: 1px solid #bb8009; "
                "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
            )
            self.status_banner.setVisible(True)

        elif report.is_live:
            if report.status == DiscoveryStatus.COMPLETED:
                if report.total_devices == 0:
                    self.lbl_provenance_badge.setText("📡 LIVE PASSIVE (QUIET NETWORK - 0 DEVICES)")
                    self.lbl_provenance_badge.setStyleSheet(
                        "background-color: #0c2d6b; color: #58a6ff; border: 1px solid #1f6feb; "
                        "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                    )
                    self.status_banner.setText(
                        "Zero devices observed during passive listening interval. "
                        "Quiet network detected; passive listeners (MNDP UDP 5678, ONVIF UDP 3702) never transmit discovery queries. "
                        "This does NOT claim that the network contains no devices."
                    )
                    self.status_banner.setStyleSheet(
                        "background-color: #0c2d6b; color: #58a6ff; border: 1px solid #1f6feb; "
                        "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                    )
                else:
                    self.lbl_provenance_badge.setText(f"📡 LIVE PASSIVE DISCOVERY ({report.total_devices} DEVICES)")
                    self.lbl_provenance_badge.setStyleSheet(
                        "background-color: #0d381e; color: #3fb950; border: 1px solid #238636; "
                        "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                    )
                    self.status_banner.setText(
                        f"Live passive listening completed successfully. Discovered {report.total_devices} multi-vendor device(s)."
                    )
                    self.status_banner.setStyleSheet(
                        "background-color: #0d381e; color: #3fb950; border: 1px solid #238636; "
                        "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                    )
                self.status_banner.setVisible(True)

            elif report.status == DiscoveryStatus.PARTIAL:
                self.lbl_provenance_badge.setText("⚠️ LIVE PASSIVE (PARTIAL DEGRADED)")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                self.status_banner.setText(
                    f"Partial discovery results: {report.error_message or 'One listener failed.'} "
                    f"Preserving {report.total_devices} observation(s) from healthy listener."
                )
                self.status_banner.setStyleSheet(
                    "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
                self.status_banner.setVisible(True)

            elif report.status == DiscoveryStatus.FAILED:
                self.lbl_provenance_badge.setText("❌ LIVE DISCOVERY FAILED")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                self.status_banner.setText(
                    f"Discovery failed: {report.error_message or 'Unknown listener or socket error.'} "
                    "(Failed operations are not an empty scan and do not fall back to mock data)."
                )
                self.status_banner.setStyleSheet(
                    "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
                self.status_banner.setVisible(True)

            elif report.status == DiscoveryStatus.CANCELLED:
                self.lbl_provenance_badge.setText("⛔ LIVE DISCOVERY CANCELLED")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                self.status_banner.setText("Passive discovery operation was explicitly cancelled.")
                self.status_banner.setStyleSheet(
                    "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
                self.status_banner.setVisible(True)

            elif report.status == DiscoveryStatus.TIMED_OUT:
                self.lbl_provenance_badge.setText("⏱️ LIVE DISCOVERY TIMED OUT")
                self.lbl_provenance_badge.setStyleSheet(
                    "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
                    "border-radius: 4px; padding: 3px 8px; font-weight: bold; font-size: 11px;"
                )
                self.status_banner.setText(
                    f"Discovery workers timed out without normal completion: {report.error_message or ''}"
                )
                self.status_banner.setStyleSheet(
                    "background-color: #490202; color: #f85149; border: 1px solid #da3633; "
                    "border-radius: 6px; padding: 8px 12px; font-size: 12px;"
                )
                self.status_banner.setVisible(True)

        # Update KPI cards
        val_tot: QLabel = self.card_total.property("val_label")
        val_tot.setText(f"{report.total_devices} Devices")

        cam_count = sum(1 for d in self.all_devices if d.category == DeviceCategory.IP_CAMERA)
        val_cam: QLabel = self.card_cams.property("val_label")
        val_cam.setText(f"{cam_count} Feeds Online")

        cpe_count = sum(1 for d in self.all_devices if d.wireless_info is not None)
        val_cpe: QLabel = self.card_wireless.property("val_label")
        val_cpe.setText(f"{cpe_count} Wireless Links")

        val_sec: QLabel = self.card_sec.property("val_label")
        val_sec.setText(f"{report.vulnerable_device_count} Advisories")
        val_sec.setStyleSheet("color: #f85149;" if report.vulnerable_device_count > 0 else "color: #3fb950;")

        self._apply_filter()

    def _clear_details(self) -> None:
        """Clear telemetry inspection card when device list is empty."""
        self.selected_device = None
        self.lbl_tel_title.setText("(No Device Selected)")
        self.lbl_tel_sub.setText("Select a device from the inventory table to view hardware telemetry.")
        self.lbl_spec_ip.setText("-")
        self.lbl_spec_mac.setText("-")
        self.lbl_spec_vendor.setText("-")
        self.lbl_spec_fw.setText("-")
        self.lbl_spec_proto.setText("-")
        self.lbl_specialized_header.setText("Hardware Telemetry:")
        self.content_box.setText("No active telemetry records.")
        self.advisory_box.setText("No active security advisories.")
        self.advisory_box.setStyleSheet(
            "background-color: #0d1117; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 6px 10px; font-size: 11px;"
        )

    def _apply_filter(self) -> None:
        """Filter table rows based on active category selection."""
        if self.active_category_filter:
            self.current_filtered_devices = [d for d in self.all_devices if d.category == self.active_category_filter]
        else:
            self.current_filtered_devices = list(self.all_devices)

        self.devices_table.setRowCount(len(self.current_filtered_devices))
        for row_idx, d in enumerate(self.current_filtered_devices):
            self.devices_table.setItem(row_idx, 0, QTableWidgetItem(d.name))
            self.devices_table.setItem(row_idx, 1, QTableWidgetItem(d.vendor))
            self.devices_table.setItem(row_idx, 2, QTableWidgetItem(d.category.value))

            ip_item = QTableWidgetItem(d.ip_address)
            ip_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.devices_table.setItem(row_idx, 3, ip_item)

            self.devices_table.setItem(row_idx, 4, QTableWidgetItem(d.firmware_version.split(" ")[0]))

            status_str = "Secure" if d.security_status == DeviceSecurityStatus.SECURE else "Warning"
            status_item = QTableWidgetItem(status_str)
            if d.security_status == DeviceSecurityStatus.SECURE:
                status_item.setForeground(QColor("#3fb950"))
            else:
                status_item.setForeground(QColor("#d29922"))
            status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.devices_table.setItem(row_idx, 5, status_item)

        if self.current_filtered_devices:
            self.devices_table.selectRow(0)
        else:
            self._clear_details()

    def _on_table_selection_changed(self) -> None:
        """Update telemetry card when user selects a different row."""
        selected_rows = self.devices_table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        if row < 0 or row >= len(self.current_filtered_devices):
            return

        device = self.current_filtered_devices[row]
        self._display_device_telemetry(device)

    def _display_device_telemetry(self, device: ManagedDevice) -> None:
        """Render detailed device information in the right panel."""
        self.selected_device = device
        self.lbl_tel_title.setText(f"[{device.device_id}] {device.name}")
        self.lbl_tel_sub.setText(f"{device.category.value} • {device.vendor} {device.model}")

        self.lbl_spec_ip.setText(device.ip_address)
        self.lbl_spec_mac.setText(device.mac_address)
        self.lbl_spec_vendor.setText(f"{device.vendor} ({device.model})")
        self.lbl_spec_fw.setText(device.firmware_version)
        self.lbl_spec_proto.setText(device.discovery_protocol)

        # Specialized Details
        if device.camera_info:
            cam = device.camera_info
            self.lbl_specialized_header.setText("📹 IP Surveillance & RTSP Telemetry:")
            content = (
                f"RTSP Live Stream URI:\n{cam.rtsp_uri}\n\n"
                f"Video Format : {cam.resolution} @ {cam.fps} fps\n"
                f"Video Codec  : {cam.codec}\n"
                f"ONVIF Port   : {cam.onvif_port}\n"
                f"PTZ Control  : {'Supported (Pan-Tilt-Zoom Active)' if cam.ptz_supported else 'Fixed Lens'}"
            )
            self.content_box.setText(content)

        elif device.wireless_info:
            w = device.wireless_info
            self.lbl_specialized_header.setText("📡 Wireless Microwave / CPE Link Quality:")
            content = (
                f"Operating Mode : {w.wireless_mode}\n"
                f"Frequency/Band : {w.frequency_mhz} MHz ({w.channel_width_mhz} MHz Channel Width)\n"
                f"Link Signal    : RSSI {w.signal_rssi_dbm} dBm | Noise Floor {w.noise_floor_dbm} dBm\n"
                f"Link SNR / CCQ : SNR {w.snr_db} dB | CCQ Quality {w.ccq_percent}%\n"
                f"Throughput Rate: TX {w.tx_rate_mbps} Mbps / RX {w.rx_rate_mbps} Mbps\n"
                f"Calculated Span: {w.distance_km} km Line-of-Sight"
            )
            self.content_box.setText(content)

        elif device.router_info:
            r = device.router_info
            self.lbl_specialized_header.setText("⚙️ MikroTik RouterOS System Health:")
            content = (
                f"Hardware Board : {r.board_name} (Architecture: {r.architecture})\n"
                f"CPU Core Load  : {r.cpu_load_percent}%\n"
                f"Available RAM  : {r.free_memory_mb} MB Free\n"
                f"Active Uptime  : {r.uptime_str}\n"
                f"Active Ports   : {r.active_interfaces} interfaces up\n"
                f"DHCP Leases    : {r.active_leases} active client leases"
            )
            self.content_box.setText(content)

        else:
            self.lbl_specialized_header.setText("🐧 System Services & Protocol Details:")
            self.content_box.setText(
                f"Operating System: {device.model}\n"
                f"Discovery Ports : mDNS / Avahi (UDP 5353) & SSH (TCP 22)\n"
                f"System State    : Healthy / Active Production Node"
            )

        # Advisories
        if device.security_notes:
            adv_lines = [f"• {n}" for n in device.security_notes]
            self.advisory_box.setText("\n".join(adv_lines))
            if device.security_status != DeviceSecurityStatus.SECURE:
                self.advisory_box.setStyleSheet(
                    "background-color: #0d1117; color: #f85149; border: 1px solid #f85149; "
                    "border-radius: 6px; padding: 6px 10px; font-size: 11px; font-weight: bold;"
                )
            else:
                self.advisory_box.setStyleSheet(
                    "background-color: #0d1117; color: #3fb950; border: 1px solid #30363d; "
                    "border-radius: 6px; padding: 6px 10px; font-size: 11px;"
                )
        else:
            self.advisory_box.setText("No security warnings or vulnerabilities detected.")
            self.advisory_box.setStyleSheet(
                "background-color: #0d1117; color: #3fb950; border: 1px solid #30363d; "
                "border-radius: 6px; padding: 6px 10px; font-size: 11px;"
            )
