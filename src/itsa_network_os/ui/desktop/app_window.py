"""Main desktop application window for ITSA Network OS."""

from __future__ import annotations

import sys
from typing import Optional

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import (
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QPushButton,
        QStackedWidget,
        QStatusBar,
        QTabWidget,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QMainWindow = object  # type: ignore

from itsa_network_os import __app_name__, __version__
from itsa_network_os.app import Application
from itsa_network_os.ui.desktop.views import (
    AssetInventoryView,
    DNSDiagnosticsView,
    InterfacesView,
    LatencyBenchmarkView,
    PacketLabView,
    RoutingTableView,
    SecurityAuditView,
    SubnetCalculatorView,
    SystemOverviewView,
)


class MainWindow(QMainWindow):  # type: ignore
    """Primary desktop GUI window for ITSA Network OS."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        if not PYSIDE6_AVAILABLE:
            raise RuntimeError("PySide6 is required to run the desktop graphical interface.")

        super().__init__(parent)
        self.app = app
        self.setWindowTitle(f"{__app_name__} — Desktop Dashboard v{__version__}")
        self.resize(1180, 780)
        self.setMinimumSize(900, 600)

        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QWidget(self)
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)

        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # 1. Persistent Top Shell Header with Global Search and Status
        self.header = self._create_shell_header()
        root_layout.addWidget(self.header)

        # 2. Main Body: Left Sidebar + Center Stacked Pages
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Left Navigation Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("SidebarList")
        self.sidebar.setFixedWidth(240)
        self.sidebar.setAccessibleName("Primary Navigation Sidebar")

        nav_items = [
            ("📊 System Overview", self._create_health_page),
            ("🔢 Subnet Calculator", self._create_subnet_page),
            ("🌐 Network Interfaces", self._create_interfaces_page),
            ("⚡ DNS Diagnostics", self._create_dns_page),
            ("📶 Latency Benchmark", self._create_latency_page),
            ("🛡️ Security Audit", self._create_audit_page),
            ("🔬 Packet Protocol Lab", self._create_lab_page),
            ("🗺️ Routing Table", self._create_routes_page),
            ("🌐 Topology Visualizer", self._create_topology_page),
            ("📡 Wi-Fi & Spectrum", self._create_wifi_page),
            ("📈 Bandwidth & Flow", self._create_bandwidth_page),
            ("🔒 TLS & SSL Security", self._create_tls_page),
            ("🔀 OSPF & Dijkstra SPF", self._create_spf_page),
            ("📹 Multi-Vendor & Cameras", self._create_vendor_page),
        ]

        self.pages_stack = QStackedWidget()
        self.pages_stack.setAccessibleName("Application View Container")

        for title, page_builder in nav_items:
            item = QListWidgetItem(title)
            self.sidebar.addItem(item)
            self.pages_stack.addWidget(page_builder())

        self.sidebar.currentRowChanged.connect(self.pages_stack.setCurrentIndex)
        self.sidebar.setCurrentRow(0)

        body_layout.addWidget(self.sidebar)
        body_layout.addWidget(self.pages_stack)
        root_layout.addWidget(body_widget, stretch=1)

        # 3. Application Status Bar
        self.statusBar().showMessage(
            f"Platform: {__app_name__} v{__version__} | Privilege: Non-Root (Safe) | Database: In-Memory (Ephemeral)"
        )

    def _create_shell_header(self) -> QFrame:
        """Create persistent top shell header with branding, global search, and scope indicators."""
        header_frame = QFrame()
        header_frame.setObjectName("ShellHeader")
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(16, 8, 16, 8)
        h_layout.setSpacing(16)

        # Brand / Title
        brand_label = QLabel(f"<b>{__app_name__}</b> <span style='color: #8b949e;'>v{__version__}</span>")
        brand_label.setFont(QFont("Segoe UI", 13))
        brand_label.setStyleSheet("color: #58a6ff;")
        h_layout.addWidget(brand_label)

        # Global Asset Search Bar
        self.global_search_input = QLineEdit()
        self.global_search_input.setObjectName("GlobalSearchInput")
        self.global_search_input.setAccessibleName("Global Asset Search Input")
        self.global_search_input.setPlaceholderText("🔍 Global asset search (IP, MAC, vendor, hostname)...")
        self.global_search_input.setStyleSheet(
            "QLineEdit#GlobalSearchInput { background-color: #0d1117; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 6px 12px; color: #f0f6fc; font-size: 12px; } "
            "QLineEdit#GlobalSearchInput:focus { border: 1px solid #58a6ff; }"
        )
        self.global_search_input.textChanged.connect(self._on_global_search_changed)
        h_layout.addWidget(self.global_search_input, stretch=1)

        # Scope badge
        scope = self.app.get_authorized_scope()
        scope_text = f"Scope: {len(scope.cidrs)} CIDR(s)" if scope and scope.cidrs else "Scope: Unconstrained"
        self.scope_badge = QLabel(f"🛡️ {scope_text}")
        self.scope_badge.setStyleSheet(
            "background-color: #0d1117; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: bold;"
        )
        h_layout.addWidget(self.scope_badge)

        # Health status badge
        self.health_badge = QLabel("● HEALTHY")
        self.health_badge.setStyleSheet(
            "background-color: #04260f; color: #3fb950; border: 1px solid #238636; "
            "border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: bold;"
        )
        h_layout.addWidget(self.health_badge)

        return header_frame

    def _on_global_search_changed(self, text: str) -> None:
        """Forward global search query to asset inventory view and switch view."""
        if hasattr(self, "inventory_view"):
            self.inventory_view.search_input.setText(text)
            if text.strip():
                # Switch to Network Interfaces & Asset Inventory view
                self.sidebar.setCurrentRow(2)
                if hasattr(self, "interfaces_tabs"):
                    self.interfaces_tabs.setCurrentIndex(1)

    # =========================================================================
    # Page 1: System Overview & Health
    # =========================================================================
    def _create_health_page(self) -> QWidget:
        self.overview_view = SystemOverviewView(self.app, self)
        return self.overview_view

    # =========================================================================
    # Page 2: Subnet Calculator
    # =========================================================================
    def _create_subnet_page(self) -> QWidget:
        self.subnet_view = SubnetCalculatorView(self.app, self)
        self.subnet_input = self.subnet_view.subnet_input
        self.subnet_status_label = self.subnet_view.subnet_status_label
        self._on_calculate_subnet = self.subnet_view._on_calculate_subnet
        return self.subnet_view

    # =========================================================================
    # Page 3: Network Interfaces & Unified Asset Inventory
    # =========================================================================
    def _create_interfaces_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.interfaces_tabs = QTabWidget()
        self.interfaces_tabs.setAccessibleName("Interfaces and Asset Inventory Tabs")

        # Tab 1: Local Network Interfaces
        self.interfaces_view = InterfacesView(self.app, self)
        self.iface_table = self.interfaces_view.iface_table
        self._load_interfaces = self.interfaces_view._load_interfaces

        # Tab 2: Unified Asset Inventory & Detail Inspector
        self.inventory_view = AssetInventoryView(self.app, self)

        self.interfaces_tabs.addTab(self.interfaces_view, "🌐 Local Network Interfaces")
        self.interfaces_tabs.addTab(self.inventory_view, "📦 Unified Asset Inventory & Search")

        layout.addWidget(self.interfaces_tabs)
        return page

    # =========================================================================
    # Page 4: DNS Diagnostics
    # =========================================================================
    def _create_dns_page(self) -> QWidget:
        self.dns_view = DNSDiagnosticsView(self.app, self)
        self.dns_input = self.dns_view.dns_input
        self.dns_table = self.dns_view.dns_table
        self._on_resolve_dns = self.dns_view._on_resolve_dns
        return self.dns_view

    # =========================================================================
    # Page 5: Latency Benchmark
    # =========================================================================
    def _create_latency_page(self) -> QWidget:
        self.latency_view = LatencyBenchmarkView(self.app, self)
        self.lat_host_input = self.latency_view.lat_host_input
        self.lat_port_spin = self.latency_view.lat_port_spin
        self.lat_count_spin = self.latency_view.lat_count_spin
        self.lat_stats_label = self.latency_view.lat_stats_label
        self.lat_table = self.latency_view.lat_table
        self._on_run_latency = self.latency_view._on_run_latency
        return self.latency_view

    # =========================================================================
    # Page 6: Security Audit
    # =========================================================================
    def _create_audit_page(self) -> QWidget:
        self.audit_view = SecurityAuditView(self.app, self)
        self.audit_table = self.audit_view.audit_table
        self._run_audit_scan = self.audit_view._run_audit_scan
        return self.audit_view

    # =========================================================================
    # Page 7: Packet Protocol Lab
    # =========================================================================
    def _create_lab_page(self) -> QWidget:
        self.lab_view = PacketLabView(self.app, self)
        self.lab_table = self.lab_view.lab_table
        self.sample_packets = self.lab_view.sample_packets
        self._on_packet_selected = self.lab_view._on_packet_selected
        self.lab_provenance_badge = self.lab_view.lab_provenance_badge
        self.lab_status_banner = self.lab_view.lab_status_banner
        self.btn_synth_trace = self.lab_view.btn_synth_trace
        self.btn_live_capture = self.lab_view.btn_live_capture
        self.packet_selector = self.lab_view.packet_selector
        return self.lab_view

    # =========================================================================
    # Page 8: Routing Table
    # =========================================================================
    def _create_routes_page(self) -> QWidget:
        self.routes_view = RoutingTableView(self.app, self)
        self.routes_table = self.routes_view.routes_table
        self._load_routes = self.routes_view._load_routes
        return self.routes_view

    # =========================================================================
    # Page 9: Network Topology Visualizer
    # =========================================================================
    def _create_topology_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.topology_canvas import TopologyWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        topo = self.app.get_topology()
        self.topo_widget = TopologyWidget(topo, self)
        layout.addWidget(self.topo_widget)
        return page

    # =========================================================================
    # Page 10: Wi-Fi Spectrum & Signal Analysis
    # =========================================================================
    def _create_wifi_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.wifi_canvas import WifiSpectrumWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.wifi_widget = WifiSpectrumWidget(self.app, self)
        layout.addWidget(self.wifi_widget)
        return page

    # =========================================================================
    # Page 11: Live Bandwidth & Traffic Flow Monitor
    # =========================================================================
    def _create_bandwidth_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.bandwidth_canvas import BandwidthMonitorWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bandwidth_widget = BandwidthMonitorWidget(self.app, self)
        layout.addWidget(self.bandwidth_widget)
        return page

    # =========================================================================
    # Page 12: TLS / SSL Cryptographic Inspector
    # =========================================================================
    def _create_tls_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.tls_canvas import TLSInspectorWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.tls_widget = TLSInspectorWidget(self)
        layout.addWidget(self.tls_widget)
        return page

    # =========================================================================
    # Page 13: OSPF / Dijkstra Shortest Path First Simulator
    # =========================================================================
    def _create_spf_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.spf_canvas import SPFSimulatorWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.spf_widget = SPFSimulatorWidget(self)
        layout.addWidget(self.spf_widget)
        return page

    # =========================================================================
    # Page 14: Multi-Vendor Hardware & IP Surveillance Device Manager
    # =========================================================================
    def _create_vendor_page(self) -> QWidget:
        from itsa_network_os.ui.desktop.vendor_canvas import VendorDeviceManagerWidget

        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        self.vendor_widget = VendorDeviceManagerWidget(self)
        layout.addWidget(self.vendor_widget)
        return page
