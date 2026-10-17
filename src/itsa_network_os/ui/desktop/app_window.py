"""Main desktop application window for ITSA Network OS."""

from __future__ import annotations

import sys
from typing import Optional

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont, QIcon
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QStackedWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QMainWindow = object  # type: ignore

from itsa_network_os import __app_name__, __version__
from itsa_network_os.app import Application
from itsa_network_os.network.subnet import SubnetCalculationError


class MainWindow(QMainWindow):  # type: ignore
    """Primary desktop GUI window for ITSA Network OS."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        if not PYSIDE6_AVAILABLE:
            raise RuntimeError("PySide6 is required to run the desktop graphical interface.")

        super().__init__(parent)
        self.app = app
        self.setWindowTitle(f"{__app_name__} — Desktop Dashboard v{__version__}")
        self.resize(1120, 750)
        self.setMinimumSize(900, 600)

        self._init_ui()

    def _init_ui(self) -> None:
        central_widget = QWidget(self)
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Left Navigation Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("SidebarList")
        self.sidebar.setFixedWidth(240)

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
        ]

        self.pages_stack = QStackedWidget()

        for title, page_builder in nav_items:
            item = QListWidgetItem(title)
            self.sidebar.addItem(item)
            self.pages_stack.addWidget(page_builder())

        self.sidebar.currentRowChanged.connect(self.pages_stack.setCurrentIndex)
        self.sidebar.setCurrentRow(0)

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.pages_stack)

    # =========================================================================
    # Page 1: System Overview & Health
    # =========================================================================
    def _create_health_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("System Status & Environment Health")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Non-destructive runtime checks and least-privilege boundary verification.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        report = self.app.check_health()

        grid = QGridLayout()
        grid.setSpacing(16)

        grid.addWidget(self._make_card("Overall Status", report.status.value, "#3fb950" if report.status.value == "HEALTHY" else "#d29922"), 0, 0)
        grid.addWidget(self._make_card("Python Runtime", report.python_version, "#58a6ff"), 0, 1)
        grid.addWidget(self._make_card("Virtual Environment", "Isolated (Active)" if report.is_virtual_env else "System (Unisolated)", "#bc8cff"), 1, 0)
        grid.addWidget(self._make_card("Privilege Level", "Non-Root (Safe)" if report.user_non_root else "Root / Superuser", "#3fb950"), 1, 1)
        grid.addWidget(self._make_card("Architecture", f"{report.platform_name} ({report.architecture})", "#8b949e"), 2, 0)
        grid.addWidget(self._make_card("Free Disk Space", f"{report.disk_free_gb} GB", "#58a6ff"), 2, 1)

        layout.addLayout(grid)

        if report.issues:
            advisory_box = QFrame()
            advisory_box.setProperty("class", "CardFrame")
            adv_layout = QVBoxLayout(advisory_box)
            adv_title = QLabel("Advisory Notices:")
            adv_title.setStyleSheet("font-weight: bold; color: #f85149;")
            adv_layout.addWidget(adv_title)
            for issue in report.issues:
                adv_layout.addWidget(QLabel(f"• {issue}"))
            layout.addWidget(advisory_box)

        layout.addStretch()
        return page

    # =========================================================================
    # Page 2: Subnet Calculator
    # =========================================================================
    def _create_subnet_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("CIDR Subnet Calculator")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("RFC-compliant IPv4 and IPv6 subnet breakdown and host range planning.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        input_row = QHBoxLayout()
        self.subnet_input = QLineEdit("192.168.1.0/24")
        self.subnet_input.setPlaceholderText("Enter CIDR block (e.g. 10.0.0.0/22 or 172.16.0.0/16)")
        calc_btn = QPushButton("Calculate")
        calc_btn.setProperty("class", "PrimaryButton")
        calc_btn.clicked.connect(self._on_calculate_subnet)
        input_row.addWidget(self.subnet_input)
        input_row.addWidget(calc_btn)
        layout.addLayout(input_row)

        self.subnet_status_label = QLabel("")
        self.subnet_status_label.setStyleSheet("color: #f85149; font-weight: bold;")
        layout.addWidget(self.subnet_status_label)

        self.subnet_grid = QGridLayout()
        self.subnet_grid.setSpacing(16)

        self.card_net_addr = self._make_card("Network Address", "192.168.1.0")
        self.card_netmask = self._make_card("Subnet Netmask", "255.255.255.0")
        self.card_wildcard = self._make_card("Wildcard Hostmask", "0.0.0.255")
        self.card_broadcast = self._make_card("Broadcast Address", "192.168.1.255")
        self.card_usable_hosts = self._make_card("Usable Hosts", "254", "#3fb950")
        self.card_total_hosts = self._make_card("Total Capacity", "256", "#58a6ff")
        self.card_span = self._make_card("Usable Host Span", "192.168.1.1  ->  192.168.1.254", "#bc8cff")

        self.subnet_grid.addWidget(self.card_net_addr, 0, 0)
        self.subnet_grid.addWidget(self.card_netmask, 0, 1)
        self.subnet_grid.addWidget(self.card_wildcard, 1, 0)
        self.subnet_grid.addWidget(self.card_broadcast, 1, 1)
        self.subnet_grid.addWidget(self.card_usable_hosts, 2, 0)
        self.subnet_grid.addWidget(self.card_total_hosts, 2, 1)
        self.subnet_grid.addWidget(self.card_span, 3, 0, 1, 2)

        layout.addLayout(self.subnet_grid)
        layout.addStretch()
        return page

    def _on_calculate_subnet(self) -> None:
        cidr = self.subnet_input.text().strip()
        try:
            res = self.app.calculate_subnet(cidr)
            self.subnet_status_label.setText("")
            self._update_card(self.card_net_addr, "Network Address", res.network_address)
            self._update_card(self.card_netmask, "Subnet Netmask", res.netmask)
            self._update_card(self.card_wildcard, "Wildcard Hostmask", res.wildcard_mask)
            self._update_card(self.card_broadcast, "Broadcast Address", res.broadcast_address)
            self._update_card(self.card_usable_hosts, "Usable Hosts", f"{res.usable_hosts:,}", "#3fb950")
            self._update_card(self.card_total_hosts, "Total Capacity", f"{res.total_hosts:,}", "#58a6ff")
            self._update_card(self.card_span, "Usable Host Span", f"{res.first_usable_ip}  ->  {res.last_usable_ip}", "#bc8cff")
        except Exception as exc:
            self.subnet_status_label.setText(f"Error: {exc}")

    # =========================================================================
    # Page 3: Network Interfaces
    # =========================================================================
    def _create_interfaces_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Network Interfaces")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Safe read-only interface enumeration (uses offline mock provider by default).")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        top_bar = QHBoxLayout()
        refresh_btn = QPushButton("Refresh Interfaces")
        refresh_btn.setProperty("class", "SecondaryButton")
        refresh_btn.clicked.connect(self._load_interfaces)
        top_bar.addStretch()
        top_bar.addWidget(refresh_btn)
        layout.addLayout(top_bar)

        self.iface_table = QTableWidget()
        self.iface_table.setColumnCount(6)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "State", "Type", "MTU", "MAC Address", "Allocated Addresses"])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.iface_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.iface_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.iface_table)

        self._load_interfaces()
        return page

    def _load_interfaces(self) -> None:
        interfaces = self.app.get_network_interfaces()
        self.iface_table.setRowCount(len(interfaces))
        for row, iface in enumerate(interfaces):
            self.iface_table.setItem(row, 0, QTableWidgetItem(iface.name))
            self.iface_table.setItem(row, 1, QTableWidgetItem(iface.state.value))
            self.iface_table.setItem(row, 2, QTableWidgetItem(iface.interface_type.value))
            self.iface_table.setItem(row, 3, QTableWidgetItem(str(iface.mtu)))
            self.iface_table.setItem(row, 4, QTableWidgetItem(iface.mac_address))
            addrs = ", ".join(f"{a.address}/{a.prefix_length}" for a in iface.addresses)
            self.iface_table.setItem(row, 5, QTableWidgetItem(addrs if addrs else "(none)"))

    # =========================================================================
    # Page 4: DNS Diagnostics
    # =========================================================================
    def _create_dns_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
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
        self.dns_input.setPlaceholderText("Enter hostname to resolve (e.g., example.com)")
        query_btn = QPushButton("Resolve DNS")
        query_btn.setProperty("class", "PrimaryButton")
        query_btn.clicked.connect(self._on_resolve_dns)
        input_row.addWidget(self.dns_input)
        input_row.addWidget(query_btn)
        layout.addLayout(input_row)

        self.dns_meta_label = QLabel("Active Resolvers: System Default")
        self.dns_meta_label.setStyleSheet("color: #8b949e;")
        layout.addWidget(self.dns_meta_label)

        self.dns_table = QTableWidget()
        self.dns_table.setColumnCount(3)
        self.dns_table.setHorizontalHeaderLabels(["Record Type", "Resolved Address / Value", "TTL"])
        self.dns_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.dns_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.dns_table)

        self._on_resolve_dns()
        return page

    def _on_resolve_dns(self) -> None:
        host = self.dns_input.text().strip()
        if not host:
            return
        result = self.app.diagnose_dns(host)
        self.dns_meta_label.setText(
            f"Active Resolvers: {', '.join(result.system_resolvers)} | Latency: {result.response_time_ms} ms | Status: {result.status}"
        )
        self.dns_table.setRowCount(len(result.records))
        for row, rec in enumerate(result.records):
            self.dns_table.setItem(row, 0, QTableWidgetItem(rec.record_type))
            self.dns_table.setItem(row, 1, QTableWidgetItem(rec.value))
            self.dns_table.setItem(row, 2, QTableWidgetItem(str(rec.ttl) if rec.ttl else "Default"))

    # =========================================================================
    # Page 5: Latency Benchmark
    # =========================================================================
    def _create_latency_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
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
        self.lat_host_input.setPlaceholderText("Target Host (e.g. 1.1.1.1)")
        self.lat_port_spin = QSpinBox()
        self.lat_port_spin.setRange(1, 65535)
        self.lat_port_spin.setValue(443)
        self.lat_count_spin = QSpinBox()
        self.lat_count_spin.setRange(1, 20)
        self.lat_count_spin.setValue(4)

        test_btn = QPushButton("Run Benchmark")
        test_btn.setProperty("class", "PrimaryButton")
        test_btn.clicked.connect(self._on_run_latency)

        input_row.addWidget(QLabel("Host:"))
        input_row.addWidget(self.lat_host_input, stretch=2)
        input_row.addWidget(QLabel("Port:"))
        input_row.addWidget(self.lat_port_spin)
        input_row.addWidget(QLabel("Probes:"))
        input_row.addWidget(self.lat_count_spin)
        input_row.addWidget(test_btn)
        layout.addLayout(input_row)

        self.lat_stats_label = QLabel("Ready to benchmark.")
        self.lat_stats_label.setStyleSheet("color: #58a6ff; font-weight: bold;")
        layout.addWidget(self.lat_stats_label)

        self.lat_table = QTableWidget()
        self.lat_table.setColumnCount(3)
        self.lat_table.setHorizontalHeaderLabels(["Probe Sequence", "Round-Trip Latency (ms)", "Status / Error"])
        self.lat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lat_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.lat_table)

        self._on_run_latency()
        return page

    def _on_run_latency(self) -> None:
        host = self.lat_host_input.text().strip()
        port = self.lat_port_spin.value()
        count = self.lat_count_spin.value()
        if not host:
            return

        res = self.app.benchmark_latency(host, port=port, count=count)
        self.lat_stats_label.setText(
            f"Target: {res.target_host}:{res.target_port} | Loss: {res.packet_loss_percent}% | "
            f"Min: {res.min_latency_ms} ms | Avg: {res.avg_latency_ms} ms | Max: {res.max_latency_ms} ms | Jitter: {res.jitter_ms} ms"
        )
        self.lat_table.setRowCount(len(res.probes))
        for row, p in enumerate(res.probes):
            self.lat_table.setItem(row, 0, QTableWidgetItem(f"Seq #{p.sequence}"))
            self.lat_table.setItem(row, 1, QTableWidgetItem(f"{p.latency_ms:.2f}" if p.success else "N/A"))
            self.lat_table.setItem(row, 2, QTableWidgetItem("SUCCESS" if p.success else f"FAILED: {p.error}"))

    # =========================================================================
    # Page 6: Security Audit
    # =========================================================================
    def _create_audit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Cybersecurity Posture & Service Audit")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Non-destructive least-privilege auditing, open service bindings, and recommendations.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        top_row = QHBoxLayout()
        self.audit_score_card = self._make_card("Security Posture Score", "100/100", "#3fb950")
        self.audit_ports_card = self._make_card("Listening Local Ports", "None", "#58a6ff")
        top_row.addWidget(self.audit_score_card)
        top_row.addWidget(self.audit_ports_card)

        refresh_audit_btn = QPushButton("Re-run Audit")
        refresh_audit_btn.setProperty("class", "PrimaryButton")
        refresh_audit_btn.clicked.connect(self._run_audit_scan)
        top_row.addWidget(refresh_audit_btn)
        layout.addLayout(top_row)

        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(4)
        self.audit_table.setHorizontalHeaderLabels(["Category", "Severity", "Finding Title", "Recommendation"])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.audit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.audit_table)

        self._run_audit_scan()
        return page

    def _run_audit_scan(self) -> None:
        report = self.app.run_security_audit()
        score_color = "#3fb950" if report.overall_score >= 80 else "#d29922" if report.overall_score >= 60 else "#f85149"
        self._update_card(self.audit_score_card, "Security Posture Score", f"{report.overall_score}/100", score_color)
        ports_str = ", ".join(str(p) for p in report.open_local_ports) if report.open_local_ports else "(none)"
        self._update_card(self.audit_ports_card, "Listening Local Ports", ports_str)

        self.audit_table.setRowCount(len(report.findings))
        for row, f in enumerate(report.findings):
            self.audit_table.setItem(row, 0, QTableWidgetItem(f.category))
            self.audit_table.setItem(row, 1, QTableWidgetItem(f.severity.value))
            self.audit_table.setItem(row, 2, QTableWidgetItem(f.title))
            self.audit_table.setItem(row, 3, QTableWidgetItem(f.recommendation))

    # =========================================================================
    # Page 7: Packet Protocol Lab
    # =========================================================================
    def _create_lab_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Educational Packet & Protocol Laboratory")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Isolated packet dissection and protocol analysis for cybersecurity learners.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Packet selector list
        self.packet_selector = QListWidget()
        self.packet_selector.setFixedHeight(120)
        self.packet_selector.currentRowChanged.connect(self._on_packet_selected)
        layout.addWidget(self.packet_selector)

        # Details Table
        self.lab_table = QTableWidget()
        self.lab_table.setColumnCount(3)
        self.lab_table.setHorizontalHeaderLabels(["Protocol Layer / Field", "Decoded Value", "Educational Cybersecurity Explanation"])
        self.lab_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.lab_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.lab_table)

        self.sample_packets = self.app.get_packet_lab_trace()
        for pkt in self.sample_packets:
            item_text = f"Packet #{pkt.index} | {pkt.protocol:<8} | {pkt.src} -> {pkt.dst} | {pkt.summary}"
            self.packet_selector.addItem(item_text)

        if self.sample_packets:
            self.packet_selector.setCurrentRow(0)

        return page

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

    # =========================================================================
    # Page 8: Routing Table
    # =========================================================================
    def _create_routes_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("System Routing Table & VLAN Inspection")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Safe read-only routing table enumeration and VLAN subinterface discovery.")
        subtitle.setObjectName("HeaderSubtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        top_bar = QHBoxLayout()
        refresh_routes_btn = QPushButton("Refresh Routes")
        refresh_routes_btn.setProperty("class", "SecondaryButton")
        refresh_routes_btn.clicked.connect(self._load_routes)
        top_bar.addStretch()
        top_bar.addWidget(refresh_routes_btn)
        layout.addLayout(top_bar)

        self.routes_table = QTableWidget()
        self.routes_table.setColumnCount(6)
        self.routes_table.setHorizontalHeaderLabels(["Destination", "Gateway", "Netmask", "Interface", "Flags", "Metric"])
        self.routes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.routes_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.routes_table)

        self._load_routes()
        return page

    def _load_routes(self) -> None:
        routes = self.app.get_routing_table()
        self.routes_table.setRowCount(len(routes))
        for row, r in enumerate(routes):
            self.routes_table.setItem(row, 0, QTableWidgetItem(r.destination))
            self.routes_table.setItem(row, 1, QTableWidgetItem(r.gateway))
            self.routes_table.setItem(row, 2, QTableWidgetItem(r.netmask))
            self.routes_table.setItem(row, 3, QTableWidgetItem(r.interface))
            self.routes_table.setItem(row, 4, QTableWidgetItem(r.flags))
            self.routes_table.setItem(row, 5, QTableWidgetItem(str(r.metric)))

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
    # Helpers
    # =========================================================================
    def _make_card(self, title_text: str, value_text: str, color: str = "#f0f6fc") -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 14, 14, 14)
        t = QLabel(title_text)
        t.setObjectName("CardTitle")
        v = QLabel(value_text)
        v.setObjectName("ValueBadge")
        v.setStyleSheet(f"color: {color};")
        l.addWidget(t)
        l.addWidget(v)
        return card

    def _update_card(self, card: QFrame, title_text: str, value_text: str, color: Optional[str] = None) -> None:
        labels = card.findChildren(QLabel)
        if len(labels) >= 2:
            labels[0].setText(title_text)
            labels[1].setText(value_text)
            if color:
                labels[1].setStyleSheet(f"color: {color};")
