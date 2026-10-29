"""Network interfaces enumeration desktop view."""

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


class InterfacesView(QWidget):  # type: ignore
    """Network Interfaces enumeration view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.setAccessibleName("Network Interfaces View")
        self.setAccessibleDescription("Safe read-only interface enumeration.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
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
        refresh_btn.setAccessibleName("Refresh Interfaces Button")
        refresh_btn.clicked.connect(self._load_interfaces)
        top_bar.addStretch()
        top_bar.addWidget(refresh_btn)
        layout.addLayout(top_bar)

        self.iface_table = QTableWidget()
        self.iface_table.setAccessibleName("Network Interfaces Table")
        self.iface_table.setColumnCount(6)
        self.iface_table.setHorizontalHeaderLabels(["Interface", "State", "Type", "MTU", "MAC Address", "Allocated Addresses"])
        self.iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.iface_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.iface_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.iface_table)

        self._load_interfaces()

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
