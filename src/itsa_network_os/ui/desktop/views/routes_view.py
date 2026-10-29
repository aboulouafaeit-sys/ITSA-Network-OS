"""Routing table and VLAN inspection desktop view."""

from __future__ import annotations

from typing import Optional

try:
    from PySide6.QtWidgets import (
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

from itsa_network_os.app import Application


class RoutingTableView(QWidget):  # type: ignore
    """System routing table and VLAN inspection view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.setAccessibleName("Routing Table View")
        self.setAccessibleDescription("Safe read-only routing table enumeration and VLAN subinterface discovery.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
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
        refresh_routes_btn.setAccessibleName("Refresh Routes Button")
        refresh_routes_btn.clicked.connect(self._load_routes)
        top_bar.addStretch()
        top_bar.addWidget(refresh_routes_btn)
        layout.addLayout(top_bar)

        self.routes_table = QTableWidget()
        self.routes_table.setAccessibleName("Routing Table Entries")
        self.routes_table.setColumnCount(6)
        self.routes_table.setHorizontalHeaderLabels(["Destination", "Gateway", "Netmask", "Interface", "Flags", "Metric"])
        self.routes_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.routes_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.routes_table)

        self._load_routes()

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
