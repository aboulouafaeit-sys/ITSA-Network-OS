"""TLS and SSL Cryptographic Inspector desktop canvas widget."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

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
        QSpinBox,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

from itsa_network_os.security.tls import (
    CipherSecurityLevel,
    TLSInspectionReport,
    TLSInspectorEngine,
    X509CertificateInfo,
)


class TLSInspectorWidget(QWidget):  # type: ignore
    """Interactive desktop dashboard widget for inspecting TLS/SSL certificates and ciphers."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.current_report: Optional[TLSInspectionReport] = None

        if not PYSIDE6_AVAILABLE:
            return

        self._build_ui()
        # Load default demonstration target
        self.inspect_target("cloudflare.com", 443)

    def _build_ui(self) -> None:
        """Construct widget layout and control elements."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # Header section
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        header_title = QLabel("TLS / SSL Cryptographic & Certificate Inspector")
        header_title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header_title.setStyleSheet("color: #58a6ff;")

        header_sub = QLabel(
            "Non-destructive cryptographic handshake analysis, X.509 certificate chain validation, "
            "and cipher suite posture audit."
        )
        header_sub.setStyleSheet("color: #8b949e; font-size: 12px;")
        header_layout.addWidget(header_title)
        header_layout.addWidget(header_sub)
        main_layout.addLayout(header_layout)

        # Target input controls card
        input_card = QFrame()
        input_card.setObjectName("InputCard")
        input_card.setStyleSheet(
            "QFrame#InputCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        card_vbox = QVBoxLayout(input_card)
        card_vbox.setContentsMargins(14, 10, 14, 10)
        card_vbox.setSpacing(8)

        # Top row: Input fields & Inspect action
        row1_layout = QHBoxLayout()
        row1_layout.setSpacing(10)

        host_label = QLabel("Target Host / Domain:")
        host_label.setStyleSheet("color: #c9d1d9; font-weight: bold; font-size: 12px;")
        self.host_input = QLineEdit("cloudflare.com")
        self.host_input.setStyleSheet(
            "QLineEdit { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 6px 12px; font-family: monospace; font-size: 13px; } "
            "QLineEdit:focus { border: 1px solid #58a6ff; }"
        )
        self.host_input.returnPressed.connect(self._on_inspect_clicked)

        port_label = QLabel("Port:")
        port_label.setStyleSheet("color: #c9d1d9; font-weight: bold; font-size: 12px;")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        self.port_input.setFixedWidth(85)
        self.port_input.setStyleSheet(
            "QSpinBox { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 5px 8px; font-size: 12px; }"
        )

        self.btn_inspect = QPushButton("🔒 Inspect Endpoint")
        self.btn_inspect.setStyleSheet(
            "QPushButton { background-color: #238636; color: #ffffff; font-weight: bold; "
            "border: none; border-radius: 6px; padding: 7px 18px; font-size: 12px; } "
            "QPushButton:hover { background-color: #2ea043; } "
            "QPushButton:pressed { background-color: #1a6f2c; }"
        )
        self.btn_inspect.clicked.connect(self._on_inspect_clicked)

        row1_layout.addWidget(host_label)
        row1_layout.addWidget(self.host_input, stretch=4)
        row1_layout.addWidget(port_label)
        row1_layout.addWidget(self.port_input)
        row1_layout.addWidget(self.btn_inspect)
        card_vbox.addLayout(row1_layout)

        # Bottom row: Quick target presets
        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(8)

        presets_lbl = QLabel("Quick Demonstrations:")
        presets_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row2_layout.addWidget(presets_lbl)

        btn_preset_cf = QPushButton("Cloudflare (Modern TLS 1.3 / ECC)")
        btn_preset_cf.setStyleSheet(self._preset_btn_style())
        btn_preset_cf.clicked.connect(lambda: self.inspect_target("cloudflare.com", 443))

        btn_preset_legacy = QPushButton("Legacy Vulnerable (TLS 1.0 / 3DES / Expired)")
        btn_preset_legacy.setStyleSheet(self._preset_btn_style())
        btn_preset_legacy.clicked.connect(lambda: self.inspect_target("legacy.internal", 443))

        btn_preset_gw = QPushButton("Gateway Router (Self-Signed / 2048-bit RSA)")
        btn_preset_gw.setStyleSheet(self._preset_btn_style())
        btn_preset_gw.clicked.connect(lambda: self.inspect_target("gateway.local", 8443))

        row2_layout.addWidget(btn_preset_cf)
        row2_layout.addWidget(btn_preset_legacy)
        row2_layout.addWidget(btn_preset_gw)
        row2_layout.addStretch()
        card_vbox.addLayout(row2_layout)

        main_layout.addWidget(input_card)

        # 4 KPI Stat Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(12)

        self.card_score = self._create_kpi_card("Security Posture Score", "100 / 100", "#3fb950")
        self.card_proto = self._create_kpi_card("Negotiated Protocol", "TLSv1.3", "#58a6ff")
        self.card_cipher = self._create_kpi_card("Cipher Suite Posture", "Strong (PFS/AEAD)", "#3fb950")
        self.card_cert = self._create_kpi_card("Certificate Validity", "VALID (278d left)", "#3fb950")

        stats_layout.addWidget(self.card_score)
        stats_layout.addWidget(self.card_proto)
        stats_layout.addWidget(self.card_cipher)
        stats_layout.addWidget(self.card_cert)
        main_layout.addLayout(stats_layout)

        # Middle Content Split (Two Cards side-by-side)
        middle_layout = QHBoxLayout()
        middle_layout.setSpacing(12)

        # Left Card: Certificate Details
        self.cert_details_card = self._create_cert_details_card()
        middle_layout.addWidget(self.cert_details_card, stretch=5)

        # Right Card: Cryptographic Posture & Vulnerabilities
        self.security_card = self._create_security_card()
        middle_layout.addWidget(self.security_card, stretch=5)

        main_layout.addLayout(middle_layout, stretch=1)

    def _preset_btn_style(self) -> str:
        return (
            "QPushButton { background-color: #21262d; color: #c9d1d9; border: 1px solid #30363d; "
            "border-radius: 5px; padding: 4px 10px; font-size: 11px; } "
            "QPushButton:hover { background-color: #30363d; border-color: #58a6ff; color: #58a6ff; }"
        )

    def _create_kpi_card(self, title: str, initial_val: str, color_hex: str) -> QFrame:
        """Create a styled key performance indicator metric card."""
        card = QFrame()
        card.setObjectName("KpiCard")
        card.setStyleSheet(
            "QFrame#KpiCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")

        lbl_val = QLabel(initial_val)
        lbl_val.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        lbl_val.setStyleSheet(f"color: {color_hex};")

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        card.setProperty("val_label", lbl_val)
        return card

    def _create_cert_details_card(self) -> QFrame:
        """Create panel displaying X.509 certificate public key metadata."""
        frame = QFrame()
        frame.setObjectName("CertDetailsCard")
        frame.setStyleSheet(
            "QFrame#CertDetailsCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        card_title = QLabel("📜 X.509 Public Key Certificate & Trust Chain")
        card_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        card_title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(card_title)

        grid = QGridLayout()
        grid.setContentsMargins(0, 4, 0, 4)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)

        def add_row(row: int, label_text: str) -> QLabel:
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px;")
            val = QLabel("—")
            val.setStyleSheet("color: #f0f6fc; font-size: 12px;")
            grid.addWidget(lbl, row, 0)
            grid.addWidget(val, row, 1)
            return val

        self.lbl_cn = add_row(0, "Subject Common Name:")
        self.lbl_issuer = add_row(1, "Issuer Authority / Org:")
        self.lbl_validity = add_row(2, "Validity Span:")
        self.lbl_key = add_row(3, "Key Specification:")
        self.lbl_sig = add_row(4, "Signature Algorithm:")
        self.lbl_serial = add_row(5, "Serial Number:")

        layout.addLayout(grid)

        # Fingerprint box
        fp_title = QLabel("SHA-256 Fingerprint:")
        fp_title.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px; margin-top: 4px;")
        layout.addWidget(fp_title)

        self.lbl_fingerprint = QLabel("—")
        self.lbl_fingerprint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_fingerprint.setStyleSheet(
            "background-color: #0d1117; color: #79c0ff; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 6px 8px; font-family: monospace; font-size: 10px;"
        )
        self.lbl_fingerprint.setWordWrap(True)
        layout.addWidget(self.lbl_fingerprint)

        # SANs list
        san_title = QLabel("Subject Alternative Names (SANs):")
        san_title.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px; margin-top: 4px;")
        layout.addWidget(san_title)

        self.lbl_sans = QLabel("—")
        self.lbl_sans.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_sans.setStyleSheet(
            "background-color: #0d1117; color: #a5d6ff; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 6px 8px; font-size: 11px;"
        )
        self.lbl_sans.setWordWrap(True)
        layout.addWidget(self.lbl_sans)

        layout.addStretch()
        return frame

    def _create_security_card(self) -> QFrame:
        """Create panel displaying cipher suite analysis and vulnerabilities."""
        frame = QFrame()
        frame.setObjectName("SecurityFindingsCard")
        frame.setStyleSheet(
            "QFrame#SecurityFindingsCard { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; }"
        )
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        card_title = QLabel("🛡️ Cryptographic Suite & Security Posture")
        card_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        card_title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(card_title)

        # Cipher Suite box
        cipher_title = QLabel("Negotiated Cipher Suite:")
        cipher_title.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px;")
        layout.addWidget(cipher_title)

        self.lbl_cipher_name = QLabel("—")
        self.lbl_cipher_name.setStyleSheet(
            "background-color: #0d1117; color: #3fb950; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 7px 10px; font-family: monospace; font-size: 12px; font-weight: bold;"
        )
        layout.addWidget(self.lbl_cipher_name)

        # Findings & Advisories Table
        table_title = QLabel("Security Findings & Hardening Advisories:")
        table_title.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 11px; margin-top: 6px;")
        layout.addWidget(table_title)

        self.findings_table = QTableWidget(0, 2)
        self.findings_table.setHorizontalHeaderLabels(["Classification", "Diagnostic Finding / Recommendation"])
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings_table.setColumnWidth(0, 135)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setStyleSheet(
            "QTableWidget { background-color: #0d1117; color: #f0f6fc; border: 1px solid #30363d; "
            "border-radius: 6px; gridline-color: #21262d; } "
            "QHeaderView::section { background-color: #161b22; color: #8b949e; "
            "border: none; padding: 6px; font-size: 11px; font-weight: bold; }"
        )
        layout.addWidget(self.findings_table, stretch=1)

        return frame

    def _on_inspect_clicked(self) -> None:
        """Handle user inspection request."""
        host = self.host_input.text().strip() or "cloudflare.com"
        port = self.port_input.value()
        self.inspect_target(host, port)

    def inspect_target(self, host: str, port: int = 443) -> None:
        """Execute inspection and update graphical dashboard."""
        self.host_input.setText(host)
        self.port_input.setValue(port)

        # Run non-destructive inspection engine
        report = TLSInspectorEngine.inspect(host=host, port=port, use_mock=True)
        self.current_report = report
        self._render_report(report)

    def _render_report(self, report: TLSInspectionReport) -> None:
        """Render report data across KPI cards, certificate details, and advisories."""
        # Update KPI Cards
        score_lbl: QLabel = self.card_score.property("val_label")
        score_color = "#3fb950" if report.overall_score >= 80 else ("#d29922" if report.overall_score >= 50 else "#f85149")
        score_lbl.setText(f"{report.overall_score} / 100")
        score_lbl.setStyleSheet(f"color: {score_color};")

        proto_lbl: QLabel = self.card_proto.property("val_label")
        proto_color = "#3fb950" if report.negotiated_protocol == "TLSv1.3" else ("#58a6ff" if report.negotiated_protocol == "TLSv1.2" else "#f85149")
        proto_lbl.setText(report.negotiated_protocol)
        proto_lbl.setStyleSheet(f"color: {proto_color};")

        cipher_lbl: QLabel = self.card_cipher.property("val_label")
        cipher_color = "#3fb950" if report.cipher_security == CipherSecurityLevel.STRONG else (
            "#d29922" if report.cipher_security == CipherSecurityLevel.MODERATE else "#f85149"
        )
        cipher_lbl.setText(report.cipher_security.value.split(" ")[0])
        cipher_lbl.setStyleSheet(f"color: {cipher_color};")

        cert = report.certificate_chain[0] if report.certificate_chain else None
        cert_lbl: QLabel = self.card_cert.property("val_label")
        if cert:
            if cert.is_expired:
                cert_lbl.setText("EXPIRED")
                cert_lbl.setStyleSheet("color: #f85149;")
            elif cert.is_self_signed:
                cert_lbl.setText("SELF-SIGNED")
                cert_lbl.setStyleSheet("color: #d29922;")
            else:
                cert_lbl.setText(f"VALID ({cert.days_until_expiration}d)")
                cert_lbl.setStyleSheet("color: #3fb950;")

            # Fill certificate card details
            self.lbl_cn.setText(cert.subject_cn)
            self.lbl_issuer.setText(f"{cert.issuer_cn} ({cert.issuer_organization})")
            self.lbl_validity.setText(f"{cert.valid_from}  -->  {cert.valid_to}")
            self.lbl_key.setText(f"{cert.key_type} {cert.key_bits}-bit")
            self.lbl_sig.setText(cert.signature_algorithm)
            self.lbl_serial.setText(cert.serial_number or "—")
            self.lbl_fingerprint.setText(cert.fingerprint_sha256 or "—")
            self.lbl_sans.setText(", ".join(cert.san_list) if cert.san_list else "None")

        # Fill Cipher Name
        self.lbl_cipher_name.setText(report.negotiated_cipher)
        self.lbl_cipher_name.setStyleSheet(
            f"background-color: #0d1117; color: {cipher_color}; border: 1px solid #30363d; "
            f"border-radius: 4px; padding: 7px 10px; font-family: monospace; font-size: 12px; font-weight: bold;"
        )

        # Fill Findings Table
        findings: List[Tuple[str, str, str]] = []
        for v in report.vulnerabilities:
            findings.append(("VULNERABILITY", v, "#f85149"))
        for r in report.recommendations:
            findings.append(("RECOMMENDATION", r, "#3fb950"))

        if not findings:
            findings.append(("POSTURE SECURE", "All cryptographic checks and certificate validations passed with zero warnings.", "#3fb950"))

        self.findings_table.setRowCount(len(findings))
        for row_idx, (f_type, f_msg, color) in enumerate(findings):
            type_item = QTableWidgetItem(f_type)
            type_item.setForeground(QColor(color))
            type_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))

            msg_item = QTableWidgetItem(f_msg)
            msg_item.setForeground(QColor("#f0f6fc"))

            self.findings_table.setItem(row_idx, 0, type_item)
            self.findings_table.setItem(row_idx, 1, msg_item)
