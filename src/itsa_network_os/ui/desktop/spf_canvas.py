"""OSPF Link-State & Dijkstra Shortest Path First (SPF) interactive desktop simulator canvas."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set, Tuple

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
        QSpinBox,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.network.spf import (
    DijkstraStep,
    LinkStatus,
    SPFLink,
    SPFRouteEntry,
    SPFRouterNode,
    SPFSimulationResult,
    SPFSimulatorEngine,
)


class SPFGraphWidget(QWidget):  # type: ignore
    """Custom graphical interactive canvas rendering OSPF router nodes, link costs, and SPF tree."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumHeight(320)
        self.simulation_result: Optional[SPFSimulationResult] = None
        self.active_step_index: int = -1  # -1 means full convergence
        self.node_rects: Dict[str, QRectF] = {}

    def set_simulation(self, result: SPFSimulationResult, step_index: int = -1) -> None:
        """Update simulation result and active Dijkstra step."""
        self.simulation_result = result
        self.active_step_index = step_index
        self.update()

    def paintEvent(self, event: Optional[QPaintEvent] = None) -> None:
        """Render router mesh, link costs, failed links, and shortest-path tree."""
        if not PYSIDE6_AVAILABLE or not self.simulation_result:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setRenderHint(QPainter.RenderHint.TextAntialiasing)

        res = self.simulation_result
        w = float(self.width())
        h = float(self.height())

        # Background gradient
        bg_grad = QLinearGradient(0, 0, w, h)
        bg_grad.setColorAt(0.0, QColor("#0d1117"))
        bg_grad.setColorAt(1.0, QColor("#161b22"))
        painter.fillRect(QRectF(0, 0, w, h), QBrush(bg_grad))

        # Scale coordinates to widget size
        base_w, base_h = 780.0, 320.0
        scale_x = max(0.5, (w - 80.0) / base_w)
        scale_y = max(0.5, (h - 60.0) / base_h)

        node_positions: Dict[str, QPointF] = {}
        for n in res.nodes:
            px = 40.0 + n.x * scale_x
            py = 30.0 + n.y * scale_y
            node_positions[n.node_id] = QPointF(px, py)

        # Determine which links belong to the current confirmed SPF tree
        spf_link_pairs: Set[Tuple[str, str]] = set()
        if self.active_step_index >= 0 and self.active_step_index < len(res.steps):
            step = res.steps[self.active_step_index]
            for child, parent in step.predecessors.items():
                spf_link_pairs.add((parent, child))
                spf_link_pairs.add((child, parent))
        else:
            # Full convergence: trace all paths in routing table
            for route in res.routes:
                for i in range(len(route.full_path) - 1):
                    p1, p2 = route.full_path[i], route.full_path[i + 1]
                    spf_link_pairs.add((p1, p2))
                    spf_link_pairs.add((p2, p1))

        # 1. Draw Links
        for link in res.links:
            if link.source not in node_positions or link.target not in node_positions:
                continue

            p1 = node_positions[link.source]
            p2 = node_positions[link.target]
            is_failed = link.status == LinkStatus.DOWN
            is_spf = (link.source, link.target) in spf_link_pairs

            if is_failed:
                # Severed Link: red dashed line
                pen = QPen(QColor("#f85149"), 2.5, Qt.PenStyle.DashLine)
                painter.setPen(pen)
                painter.drawLine(p1, p2)
            elif is_spf:
                # Confirmed SPF Tree path: glowing golden/amber line
                glow_pen = QPen(QColor(242, 204, 96, 70), 7.0)
                painter.setPen(glow_pen)
                painter.drawLine(p1, p2)

                spf_pen = QPen(QColor("#f2cc60"), 3.2, Qt.PenStyle.SolidLine)
                painter.setPen(spf_pen)
                painter.drawLine(p1, p2)
            else:
                # Regular inactive topology link
                pen = QPen(QColor("#30363d"), 1.8)
                painter.setPen(pen)
                painter.drawLine(p1, p2)

            # Draw Cost Badge at midpoint
            mid_x = (p1.x() + p2.x()) / 2.0
            mid_y = (p1.y() + p2.y()) / 2.0

            badge_text = f"Cost: {link.cost}" if not is_failed else "DOWN"
            badge_bg = QColor("#f85149") if is_failed else (QColor("#1f6feb") if is_spf else QColor("#21262d"))
            badge_fg = QColor("#ffffff") if (is_failed or is_spf) else QColor("#8b949e")

            badge_rect = QRectF(mid_x - 28, mid_y - 10, 56, 20)
            painter.setBrush(QBrush(badge_bg))
            painter.setPen(QPen(QColor("#30363d"), 1.0))
            painter.drawRoundedRect(badge_rect, 4, 4)

            painter.setPen(badge_fg)
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
            painter.drawText(badge_rect, Qt.AlignmentFlag.AlignCenter, badge_text)

        # 2. Draw Router Nodes
        self.node_rects.clear()
        node_radius = 24.0

        for n in res.nodes:
            pos = node_positions[n.node_id]
            is_root = n.node_id == res.source_router
            is_confirmed = False
            is_tentative = False

            if self.active_step_index >= 0 and self.active_step_index < len(res.steps):
                step = res.steps[self.active_step_index]
                is_confirmed = n.node_id in step.confirmed_tree
                is_tentative = n.node_id in step.tentative_distances and not is_confirmed
            else:
                is_confirmed = True

            # Node glow for root
            if is_root:
                painter.setPen(QPen(QColor(88, 166, 255, 60), 8.0))
                painter.drawEllipse(pos, node_radius + 4, node_radius + 4)

            # Node body color
            if is_root:
                body_color = QColor("#1f6feb")  # Royal blue for root
                border_color = QColor("#58a6ff")
            elif is_confirmed:
                body_color = QColor("#238636")  # Green for settled
                border_color = QColor("#3fb950")
            elif is_tentative:
                body_color = QColor("#9e6a03")  # Amber for candidate
                border_color = QColor("#d29922")
            else:
                body_color = QColor("#21262d")  # Dark gray for unvisited
                border_color = QColor("#30363d")

            painter.setBrush(QBrush(body_color))
            painter.setPen(QPen(border_color, 2.0))
            painter.drawEllipse(pos, node_radius, node_radius)

            # Node ID Text (R1, R2, ...)
            painter.setPen(QColor("#ffffff"))
            painter.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            text_rect = QRectF(pos.x() - node_radius, pos.y() - node_radius, node_radius * 2, node_radius * 2)
            painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, n.node_id)

            # Sub-label: Router ID IP below node
            ip_rect = QRectF(pos.x() - 55, pos.y() + node_radius + 3, 110, 16)
            painter.setPen(QColor("#8b949e"))
            painter.setFont(QFont("Segoe UI", 8))
            painter.drawText(ip_rect, Qt.AlignmentFlag.AlignCenter, n.router_id)

            self.node_rects[n.node_id] = text_rect


class SPFSimulatorWidget(QWidget):  # type: ignore
    """Complete desktop widget for Dijkstra Shortest Path First calculation and OSPF link-state simulation."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.current_result: Optional[SPFSimulationResult] = None
        self.step_index: int = -1  # -1 represents full convergence

        if not PYSIDE6_AVAILABLE:
            return

        self._build_ui()
        self.run_simulation("R1", None)

    def _build_ui(self) -> None:
        """Construct user interface layout and controls."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # Header Title
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        title = QLabel("OSPF / Dijkstra Shortest Path First (SPF) Routing Simulator")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")

        sub = QLabel(
            "Interactive step-by-step Link-State Database (LSDB) SPF tree computation, dynamic failover, "
            "and shortest path convergence."
        )
        sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        header_layout.addWidget(title)
        header_layout.addWidget(sub)
        main_layout.addLayout(header_layout)

        # Control Card
        control_card = QFrame()
        control_card.setObjectName("SPFControlCard")
        control_card.setStyleSheet(
            "QFrame#SPFControlCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        ctrl_layout = QVBoxLayout(control_card)
        ctrl_layout.setContentsMargins(14, 10, 14, 10)
        ctrl_layout.setSpacing(8)

        # Row 1: Source Root & Link Failure Selectors
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        lbl_root = QLabel("SPF Root Router:")
        lbl_root.setStyleSheet("color: #c9d1d9; font-weight: bold; font-size: 12px;")
        self.combo_root = QComboBox()
        self.combo_root.setStyleSheet(
            "QComboBox { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 5px 12px; font-size: 12px; }"
        )
        for r_id in ["R1", "R2", "R3", "R4", "R5", "R6"]:
            self.combo_root.addItem(f"Router {r_id}", r_id)

        lbl_failure = QLabel("Link Failure Simulation:")
        lbl_failure.setStyleSheet("color: #c9d1d9; font-weight: bold; font-size: 12px;")
        self.combo_failure = QComboBox()
        self.combo_failure.setStyleSheet(
            "QComboBox { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 5px 12px; font-size: 12px; }"
        )
        self.combo_failure.addItem("None (All Links Operational)", None)
        self.combo_failure.addItem("Sever Link R1-R2 (10G Fiber)", "R1-R2")
        self.combo_failure.addItem("Sever Link R2-R4 (10G Core)", "R2-R4")
        self.combo_failure.addItem("Sever Link R5-R6 (10G WAN)", "R5-R6")
        self.combo_failure.addItem("Sever Link R2-R3 (Inter-Core)", "R2-R3")
        self.combo_failure.addItem("Sever Link R1-R3 (1G Copper)", "R1-R3")

        self.btn_run = QPushButton("⚡ Calculate SPF Tree")
        self.btn_run.setStyleSheet(
            "QPushButton { background-color: #238636; color: #ffffff; font-weight: bold; "
            "border: none; border-radius: 6px; padding: 7px 18px; font-size: 12px; } "
            "QPushButton:hover { background-color: #2ea043; } "
            "QPushButton:pressed { background-color: #1a6f2c; }"
        )
        self.btn_run.clicked.connect(self._on_run_clicked)

        row1.addWidget(lbl_root)
        row1.addWidget(self.combo_root, stretch=2)
        row1.addWidget(lbl_failure)
        row1.addWidget(self.combo_failure, stretch=3)
        row1.addWidget(self.btn_run)
        ctrl_layout.addLayout(row1)

        # Row 2: Step-by-Step Player Controls
        row2 = QHBoxLayout()
        row2.setSpacing(8)

        player_lbl = QLabel("Step-by-Step Dissection:")
        player_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row2.addWidget(player_lbl)

        self.btn_prev = QPushButton("◀ Previous Step")
        self.btn_prev.setStyleSheet(self._button_style())
        self.btn_prev.clicked.connect(self._on_prev_step)

        self.lbl_step_status = QLabel("Step: Fully Converged")
        self.lbl_step_status.setStyleSheet("color: #f2cc60; font-weight: bold; font-size: 12px; padding: 0 8px;")

        self.btn_next = QPushButton("Next Step ▶")
        self.btn_next.setStyleSheet(self._button_style())
        self.btn_next.clicked.connect(self._on_next_step)

        self.btn_full = QPushButton("Show Final Tree")
        self.btn_full.setStyleSheet(self._button_style())
        self.btn_full.clicked.connect(self._on_show_full)

        row2.addWidget(self.btn_prev)
        row2.addWidget(self.lbl_step_status)
        row2.addWidget(self.btn_next)
        row2.addWidget(self.btn_full)
        row2.addStretch()
        ctrl_layout.addLayout(row2)

        main_layout.addWidget(control_card)

        # 4 KPI Metrics
        kpi_layout = QHBoxLayout()
        kpi_layout.setSpacing(12)

        self.card_status = self._create_kpi_card("Convergence Status", "Optimal SPF Tree", "#3fb950")
        self.card_latency = self._create_kpi_card("SPF Calculation Time", "0.2 ms", "#58a6ff")
        self.card_cost = self._create_kpi_card("Max Path Metric", "Cost: 35", "#f2cc60")
        self.card_reach = self._create_kpi_card("Topology Reachability", "6 / 6 Nodes (100%)", "#3fb950")

        kpi_layout.addWidget(self.card_status)
        kpi_layout.addWidget(self.card_latency)
        kpi_layout.addWidget(self.card_cost)
        kpi_layout.addWidget(self.card_reach)
        main_layout.addLayout(kpi_layout)

        # Center Split: Graph Canvas (Left 60%) + Details/Trace (Right 40%)
        center_layout = QHBoxLayout()
        center_layout.setSpacing(12)

        # Left Graph Canvas
        self.graph_widget = SPFGraphWidget(self)
        center_layout.addWidget(self.graph_widget, stretch=6)

        # Right Tabs: Routing Table & Dijkstra Step Trace
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #30363d; background-color: #161b22; border-radius: 8px; } "
            "QTabBar::tab { background-color: #0d1117; color: #8b949e; border: 1px solid #30363d; "
            "padding: 6px 14px; border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: bold; } "
            "QTabBar::tab:selected { background-color: #161b22; color: #58a6ff; border-bottom: none; }"
        )

        # Tab 1: Routing Table
        self.table_routes = QTableWidget(0, 5)
        self.table_routes.setHorizontalHeaderLabels(["Dest", "Subnet", "Cost", "Next-Hop", "Shortest Path"])
        self.table_routes.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_routes.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table_routes.setColumnWidth(0, 48)
        self.table_routes.setColumnWidth(1, 95)
        self.table_routes.setColumnWidth(2, 50)
        self.table_routes.setColumnWidth(3, 90)
        self.table_routes.verticalHeader().setVisible(False)
        self.table_routes.setStyleSheet(
            "QTableWidget { background-color: #0d1117; color: #f0f6fc; border: none; gridline-color: #21262d; } "
            "QHeaderView::section { background-color: #161b22; color: #8b949e; "
            "border: none; padding: 6px; font-size: 11px; font-weight: bold; }"
        )
        self.tabs.addTab(self.table_routes, "OSPF Routing Table")

        # Tab 2: Dijkstra Trace Log
        self.table_trace = QTableWidget(0, 3)
        self.table_trace.setHorizontalHeaderLabels(["Step", "Node", "Mathematical Explanation & Relaxation"])
        self.table_trace.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_trace.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_trace.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_trace.verticalHeader().setVisible(False)
        self.table_trace.setStyleSheet(
            "QTableWidget { background-color: #0d1117; color: #f0f6fc; border: none; gridline-color: #21262d; } "
            "QHeaderView::section { background-color: #161b22; color: #8b949e; "
            "border: none; padding: 6px; font-size: 11px; font-weight: bold; }"
        )
        self.tabs.addTab(self.table_trace, "Dijkstra Step Trace")

        center_layout.addWidget(self.tabs, stretch=4)
        main_layout.addLayout(center_layout, stretch=1)

    def _button_style(self) -> str:
        return (
            "QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; "
            "border-radius: 5px; padding: 4px 10px; font-size: 11px; } "
            "QPushButton:hover { background-color: #30363d; border-color: #58a6ff; color: #58a6ff; }"
        )

    def _create_kpi_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        card = QFrame()
        card.setObjectName("SPFKpiCard")
        card.setStyleSheet(
            "QFrame#SPFKpiCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
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

    def _on_run_clicked(self) -> None:
        source_id = str(self.combo_root.currentData() or "R1")
        failed_link = self.combo_failure.currentData()
        self.run_simulation(source_id, failed_link)

    def run_simulation(self, source_id: str = "R1", failed_link: Optional[str] = None) -> None:
        """Execute Dijkstra SPF engine and update dashboard widgets."""
        result = SPFSimulatorEngine.calculate_spf(source_id=source_id, failed_link_id=failed_link)
        self.current_result = result
        self.step_index = -1
        self._render_result(result)

    def _on_prev_step(self) -> None:
        if not self.current_result:
            return
        if self.step_index == -1:
            self.step_index = len(self.current_result.steps) - 1
        elif self.step_index > 0:
            self.step_index -= 1
        self._update_step_view()

    def _on_next_step(self) -> None:
        if not self.current_result:
            return
        if self.step_index == -1:
            self.step_index = 0
        elif self.step_index < len(self.current_result.steps) - 1:
            self.step_index += 1
        self._update_step_view()

    def _on_show_full(self) -> None:
        self.step_index = -1
        self._update_step_view()

    def _update_step_view(self) -> None:
        if not self.current_result:
            return

        if self.step_index == -1:
            self.lbl_step_status.setText("Step: Fully Converged")
        else:
            self.lbl_step_status.setText(f"Step: {self.step_index + 1} / {len(self.current_result.steps)}")

        self.graph_widget.set_simulation(self.current_result, self.step_index)

    def _render_result(self, result: SPFSimulationResult) -> None:
        """Render metrics, routing table, and execution trace."""
        # Update KPI cards
        val_status: QLabel = self.card_status.property("val_label")
        if result.failed_link_id:
            val_status.setText("Failover Re-converged")
            val_status.setStyleSheet("color: #d29922;")
        else:
            val_status.setText("Optimal Converged")
            val_status.setStyleSheet("color: #3fb950;")

        val_lat: QLabel = self.card_latency.property("val_label")
        val_lat.setText(f"{result.convergence_time_ms} ms")

        max_cost = max((r.total_cost for r in result.routes), default=0)
        val_cost: QLabel = self.card_cost.property("val_label")
        val_cost.setText(f"Cost: {max_cost}")

        reachable_count = len(result.nodes) - len(result.unreachable_nodes)
        val_reach: QLabel = self.card_reach.property("val_label")
        val_reach.setText(f"{reachable_count} / {len(result.nodes)} Reachable")

        # Update Routing Table
        self.table_routes.setRowCount(len(result.routes))
        for row_idx, r in enumerate(result.routes):
            self.table_routes.setItem(row_idx, 0, QTableWidgetItem(r.destination_node))
            self.table_routes.setItem(row_idx, 1, QTableWidgetItem(r.destination_subnet))

            cost_item = QTableWidgetItem(str(r.total_cost))
            cost_item.setForeground(QColor("#f2cc60"))
            cost_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table_routes.setItem(row_idx, 2, cost_item)

            self.table_routes.setItem(row_idx, 3, QTableWidgetItem(f"{r.next_hop_router} ({r.next_hop_ip})"))

            path_str = " ➔ ".join(r.full_path)
            path_item = QTableWidgetItem(path_str)
            path_item.setForeground(QColor("#58a6ff"))
            self.table_routes.setItem(row_idx, 4, path_item)

        # Update Dijkstra Trace Table
        self.table_trace.setRowCount(len(result.steps))
        for row_idx, s in enumerate(result.steps):
            step_item = QTableWidgetItem(f"#{s.step_number}")
            step_item.setForeground(QColor("#8b949e"))
            self.table_trace.setItem(row_idx, 0, step_item)

            node_item = QTableWidgetItem(s.current_node)
            node_item.setForeground(QColor("#58a6ff"))
            node_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.table_trace.setItem(row_idx, 1, node_item)

            expl_item = QTableWidgetItem(s.explanation)
            expl_item.setForeground(QColor("#f0f6fc"))
            self.table_trace.setItem(row_idx, 2, expl_item)

        self._update_step_view()
