"""Interactive 2D Network Topology Canvas with pan, zoom, and node inspector."""

from __future__ import annotations

from typing import Dict, Optional

try:
    from PySide6.QtCore import QPointF, QRectF, Qt
    from PySide6.QtGui import (
        QBrush,
        QColor,
        QFont,
        QPainter,
        QPen,
        QWheelEvent,
    )
    from PySide6.QtWidgets import (
        QFrame,
        QGraphicsEllipseItem,
        QGraphicsItem,
        QGraphicsLineItem,
        QGraphicsRectItem,
        QGraphicsScene,
        QGraphicsSimpleTextItem,
        QGraphicsView,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.network.topology import (
    NetworkTopology,
    NodeStatus,
    TopologyLink,
    TopologyNode,
    TopologyNodeType,
)


class TopologyCanvasView(QGraphicsView):  # type: ignore
    """Pan and zoom interactive viewport for network graph."""

    def __init__(self, scene: QGraphicsScene, parent: Optional[QWidget] = None) -> None:
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setBackgroundBrush(QBrush(QColor("#0d1117")))
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

    def wheelEvent(self, event: QWheelEvent) -> None:
        """Handle zoom in and zoom out via mouse wheel."""
        zoom_in_factor = 1.15
        zoom_out_factor = 1.0 / zoom_in_factor
        if event.angleDelta().y() > 0:
            self.scale(zoom_in_factor, zoom_in_factor)
        else:
            self.scale(zoom_out_factor, zoom_out_factor)


class TopologyWidget(QWidget):  # type: ignore
    """Complete interactive topology visualizer component with controls and inspector."""

    TYPE_COLORS = {
        TopologyNodeType.INTERNET: ("#f0883e", "#281a10"),
        TopologyNodeType.GATEWAY: ("#58a6ff", "#0d1b2a"),
        TopologyNodeType.ROUTER: ("#58a6ff", "#0d1b2a"),
        TopologyNodeType.SWITCH: ("#bc8cff", "#1e102d"),
        TopologyNodeType.SERVER: ("#3fb950", "#0e2313"),
        TopologyNodeType.WORKSTATION: ("#56d364", "#0e2313"),
        TopologyNodeType.SUBNET: ("#d29922", "#261c0c"),
    }

    def __init__(self, topology: NetworkTopology, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.topology = topology
        self.selected_node: Optional[TopologyNode] = None
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(12)

        # Left / Center Area: Toolbar + Viewport
        canvas_col = QVBoxLayout()
        canvas_col.setContentsMargins(0, 0, 0, 0)
        canvas_col.setSpacing(8)

        # Control toolbar
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("<b>Network Topology Visualizer</b> (Interactive Node-Link Canvas)"))
        toolbar.addStretch()

        legend = QLabel(
            "<span style='color: #3fb950; font-weight: bold;'>— Verified</span> &nbsp; "
            "<span style='color: #bc8cff; font-weight: bold;'>- - Inferred</span> &nbsp; "
            "<span style='color: #79c0ff; font-weight: bold;'>··· Configured</span>"
        )
        legend.setToolTip(
            "— Verified: Direct protocol proof (LLDP/Netlink)\n"
            "- - Inferred: Heuristic correlation (Subnet/Routing)\n"
            "··· Configured: Statically defined service (Reachability unverified)"
        )
        legend.setStyleSheet("font-size: 11px; padding: 2px 8px; background-color: #161b22; border-radius: 4px;")
        toolbar.addWidget(legend)

        zoom_in_btn = QPushButton("+ Zoom In")
        zoom_in_btn.setProperty("class", "SecondaryButton")
        zoom_in_btn.clicked.connect(lambda: self.view.scale(1.2, 1.2))
        toolbar.addWidget(zoom_in_btn)

        zoom_out_btn = QPushButton("- Zoom Out")
        zoom_out_btn.setProperty("class", "SecondaryButton")
        zoom_out_btn.clicked.connect(lambda: self.view.scale(0.8, 0.8))
        toolbar.addWidget(zoom_out_btn)

        reset_btn = QPushButton("Reset View")
        reset_btn.setProperty("class", "SecondaryButton")
        reset_btn.clicked.connect(self._reset_view)
        toolbar.addWidget(reset_btn)

        canvas_col.addLayout(toolbar)

        # Graphics Scene & View
        self.scene = QGraphicsScene(0, 0, 950, 560)
        self.view = TopologyCanvasView(self.scene, self)
        canvas_col.addWidget(self.view, stretch=1)

        main_layout.addLayout(canvas_col, stretch=3)

        # Right Side: Node Details Inspector Card
        self.detail_card = QFrame()
        self.detail_card.setProperty("class", "CardFrame")
        self.detail_card.setFixedWidth(280)
        detail_layout = QVBoxLayout(self.detail_card)
        detail_layout.setContentsMargins(16, 16, 16, 16)
        detail_layout.setSpacing(10)

        self.detail_title = QLabel("Node Inspector")
        self.detail_title.setObjectName("CardTitle")
        detail_layout.addWidget(self.detail_title)

        self.detail_info = QLabel("Click any node on the topology canvas to inspect device metadata, interfaces, and link statistics.")
        self.detail_info.setWordWrap(True)
        self.detail_info.setStyleSheet("color: #8b949e; font-size: 13px;")
        detail_layout.addWidget(self.detail_info)

        detail_layout.addStretch()
        main_layout.addWidget(self.detail_card, stretch=1)

        self._render_graph()

    def _reset_view(self) -> None:
        self.view.resetTransform()
        self.view.centerOn(475, 280)

    @classmethod
    def _get_link_pen(cls, link_type: str) -> tuple[QPen, str]:
        """Return (QPen, category_label) based on epistemic relationship semantics."""
        lt_upper = str(link_type).upper()
        if "VERIFIED" in lt_upper or lt_upper == "ETHERNET":
            pen = QPen(QColor("#3fb950"), 2, Qt.PenStyle.SolidLine)
            return pen, "[Verified]"
        elif "INFERRED" in lt_upper or lt_upper in ("ROUTED", "WIRELESS"):
            pen = QPen(QColor("#bc8cff"), 2, Qt.PenStyle.DashLine)
            return pen, "[Inferred]"
        elif "CONFIGURED" in lt_upper:
            pen = QPen(QColor("#79c0ff"), 2, Qt.PenStyle.DotLine)
            return pen, "[Configured]"
        else:
            pen = QPen(QColor("#8b949e"), 1.5, Qt.PenStyle.SolidLine)
            return pen, "[Standard]"

    def _render_graph(self) -> None:
        self.scene.clear()

        # Map node coordinates
        node_coords: Dict[str, QPointF] = {}
        for n in self.topology.nodes:
            node_coords[n.id] = QPointF(n.x, n.y)

        # 1. Draw Links with epistemic styling
        for link in self.topology.links:
            p1 = node_coords.get(link.source_id)
            p2 = node_coords.get(link.target_id)
            if p1 and p2:
                pen, rel_badge = self._get_link_pen(link.link_type)
                line = self.scene.addLine(p1.x(), p1.y(), p2.x(), p2.y(), pen)
                line.setZValue(1)

                # Link speed badge in midpoint
                mid_x = (p1.x() + p2.x()) / 2
                mid_y = (p1.y() + p2.y()) / 2
                badge_text = self.scene.addSimpleText(f"{link.speed_mbps}M | {link.latency_ms}ms")
                badge_text.setFont(QFont("Segoe UI", 8))
                badge_text.setBrush(QBrush(QColor("#8b949e")))
                badge_text.setPos(mid_x - 30, mid_y - 8)
                badge_text.setZValue(2)

        # 2. Draw Nodes
        node_width, node_height = 140, 56
        for n in self.topology.nodes:
            center = node_coords[n.id]
            rect_x = center.x() - (node_width / 2)
            rect_y = center.y() - (node_height / 2)

            border_hex, bg_hex = self.TYPE_COLORS.get(n.node_type, ("#58a6ff", "#161b22"))

            rect_item = self.scene.addRect(
                QRectF(rect_x, rect_y, node_width, node_height),
                QPen(QColor(border_hex), 1.5),
                QBrush(QColor(bg_hex)),
            )
            rect_item.setZValue(3)
            rect_item.setFlags(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
            rect_item.setData(0, n.id)

            # Status dot
            dot_color = QColor("#3fb950") if n.status == NodeStatus.ONLINE else QColor("#f85149")
            dot = self.scene.addEllipse(rect_x + 8, rect_y + 10, 8, 8, QPen(Qt.PenStyle.NoPen), QBrush(dot_color))
            dot.setZValue(4)

            # Node Label
            label_text = self.scene.addSimpleText(n.label[:18])
            label_text.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            label_text.setBrush(QBrush(QColor("#f0f6fc")))
            label_text.setPos(rect_x + 22, rect_y + 8)
            label_text.setZValue(4)

            # Node IP / Type
            ip_text = self.scene.addSimpleText(f"{n.ip_address}")
            ip_text.setFont(QFont("Segoe UI", 8))
            ip_text.setBrush(QBrush(QColor("#8b949e")))
            ip_text.setPos(rect_x + 22, rect_y + 28)
            ip_text.setZValue(4)

        self.scene.selectionChanged.connect(self._on_selection_changed)

    def _on_selection_changed(self) -> None:
        items = self.scene.selectedItems()
        if not items:
            return

        selected_item = items[0]
        node_id = selected_item.data(0)
        if node_id:
            for node in self.topology.nodes:
                if node.id == node_id:
                    self._display_node_details(node)
                    return

        # Fallback to approximate coordinate matching if item data not set
        rect = selected_item.boundingRect()
        center_x = rect.x() + (rect.width() / 2)
        center_y = rect.y() + (rect.height() / 2)

        for node in self.topology.nodes:
            if abs(node.x - center_x) < 5 and abs(node.y - center_y) < 5:
                self._display_node_details(node)
                break

    def _display_node_details(self, node: TopologyNode) -> None:
        self.detail_title.setText(f"{node.label}")
        lines = [
            f"<b>Node ID:</b> {node.id}",
            f"<b>Device Type:</b> {node.node_type.value}",
            f"<b>IP Address:</b> {node.ip_address}",
            f"<b>MAC Address:</b> {node.mac_address or 'N/A'}",
            f"<b>Status:</b> <span style='color: #3fb950;'>{node.status.value}</span>",
            "<hr style='border: 1px solid #30363d;'>",
            "<b>Device Metadata:</b>",
        ]
        for k, v in node.details.items():
            lines.append(f"• <b>{k}:</b> {v}")

        # List connected links
        connected = [l for l in self.topology.links if l.source_id == node.id or l.target_id == node.id]
        if connected:
            lines.append("<hr style='border: 1px solid #30363d;'><b>Interconnects:</b>")
            for c in connected:
                neighbor = c.target_id if c.source_id == node.id else c.source_id
                lines.append(f"• To: {neighbor} ({c.speed_mbps} Mbps, {c.latency_ms} ms)")

        self.detail_info.setText("<br>".join(lines))
