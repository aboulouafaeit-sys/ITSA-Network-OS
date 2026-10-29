"""Subnet calculator desktop view."""

from __future__ import annotations

from typing import Optional

try:
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.app import Application


class SubnetCalculatorView(QWidget):  # type: ignore
    """CIDR Subnet Calculator view component."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.setAccessibleName("CIDR Subnet Calculator View")
        self.setAccessibleDescription("RFC-compliant IPv4 and IPv6 subnet breakdown and host range planning.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
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
        self.subnet_input.setAccessibleName("CIDR Subnet Input")
        self.subnet_input.setPlaceholderText("Enter CIDR block (e.g. 10.0.0.0/22 or 172.16.0.0/16)")
        calc_btn = QPushButton("Calculate")
        calc_btn.setProperty("class", "PrimaryButton")
        calc_btn.setAccessibleName("Calculate Subnet Button")
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

    def _make_card(self, title_text: str, value_text: str, color: str = "#f0f6fc") -> QFrame:
        card = QFrame()
        card.setProperty("class", "CardFrame")
        card.setAccessibleName(f"{title_text}: {value_text}")
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
