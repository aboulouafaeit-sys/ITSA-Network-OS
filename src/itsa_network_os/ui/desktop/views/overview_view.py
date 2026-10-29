"""System Overview and Runtime Health desktop view."""

from __future__ import annotations

from typing import Any, Optional

try:
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QLabel,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.app import Application


class SystemOverviewView(QWidget):  # type: ignore
    """System Status & Environment Health diagnostics view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.setAccessibleName("System Overview and Environment Health View")
        self.setAccessibleDescription("Non-destructive runtime checks and least-privilege boundary verification.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
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
