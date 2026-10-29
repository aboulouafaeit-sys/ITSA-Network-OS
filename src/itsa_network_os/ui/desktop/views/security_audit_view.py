"""Security audit desktop view."""

from __future__ import annotations

from typing import Optional

try:
    from PySide6.QtWidgets import (
        QFrame,
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


class SecurityAuditView(QWidget):  # type: ignore
    """Cybersecurity posture and local service auditing view."""

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.setAccessibleName("Security Audit View")
        self.setAccessibleDescription("Non-destructive least-privilege auditing, open service bindings, and recommendations.")
        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
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
        refresh_audit_btn.setAccessibleName("Re-run Audit Button")
        refresh_audit_btn.clicked.connect(self._run_audit_scan)
        top_row.addWidget(refresh_audit_btn)
        layout.addLayout(top_row)

        self.audit_table = QTableWidget()
        self.audit_table.setAccessibleName("Security Audit Findings Table")
        self.audit_table.setColumnCount(4)
        self.audit_table.setHorizontalHeaderLabels(["Category", "Severity", "Finding Title", "Recommendation"])
        self.audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.audit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.audit_table)

        self._run_audit_scan()

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
