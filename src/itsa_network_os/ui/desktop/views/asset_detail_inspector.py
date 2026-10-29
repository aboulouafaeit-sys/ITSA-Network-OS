"""Reusable, evidence-aware Asset Detail Inspector desktop component."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QScrollArea,
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

from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    AssetIdentity,
    EntityStatus,
    NetworkAsset,
    RelationshipType,
)
from itsa_network_os.storage.redaction import CredentialRedactor


class AssetDetailInspector(QWidget):  # type: ignore
    """Evidence-aware detail inspector for a selected NetworkAsset."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.current_asset: Optional[NetworkAsset] = None
        self.current_graph: Optional[AssetGraph] = None
        self.setAccessibleName("Asset Detail Inspector")
        self.setAccessibleDescription("Detailed inspection of asset identity, interfaces, IP history, and evidence provenance.")

        if PYSIDE6_AVAILABLE:
            self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # Header card
        self.header_card = QFrame()
        self.header_card.setObjectName("InspectorHeaderCard")
        self.header_card.setProperty("class", "CardFrame")
        h_layout = QVBoxLayout(self.header_card)
        h_layout.setContentsMargins(14, 12, 14, 12)
        h_layout.setSpacing(4)

        self.lbl_title = QLabel("(No Asset Selected)")
        self.lbl_title.setFont(QFont("Segoe UI", 15, QFont.Weight.Bold))
        self.lbl_title.setStyleSheet("color: #58a6ff;")
        self.lbl_title.setAccessibleName("Selected Asset Title")

        self.lbl_sub = QLabel("Select an asset from the inventory to inspect identity, evidence, and topology.")
        self.lbl_sub.setStyleSheet("color: #8b949e; font-size: 12px;")

        self.badge_row = QHBoxLayout()
        self.lbl_status_badge = QLabel("OFFLINE")
        self.lbl_status_badge.setStyleSheet(
            "background-color: #21262d; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 11px;"
        )
        self.lbl_confidence_badge = QLabel("Confidence: 100%")
        self.lbl_confidence_badge.setStyleSheet(
            "background-color: #04260f; color: #3fb950; border: 1px solid #238636; "
            "border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 11px;"
        )
        self.badge_row.addWidget(self.lbl_status_badge)
        self.badge_row.addWidget(self.lbl_confidence_badge)
        self.badge_row.addStretch()

        h_layout.addWidget(self.lbl_title)
        h_layout.addWidget(self.lbl_sub)
        h_layout.addLayout(self.badge_row)
        main_layout.addWidget(self.header_card)

        # Tabs for detail facets
        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Asset Inspector Facet Tabs")

        self.tab_identity = self._create_identity_tab()
        self.tab_ports = self._create_ports_tab()
        self.tab_ip_history = self._create_ip_history_tab()
        self.tab_topology = self._create_topology_tab()
        self.tab_evidence = self._create_evidence_tab()

        self.tabs.addTab(self.tab_identity, "Identity & Attributes")
        self.tabs.addTab(self.tab_ports, "Ports & Interfaces")
        self.tabs.addTab(self.tab_ip_history, "IP Binding Timeline")
        self.tabs.addTab(self.tab_topology, "Topology Links")
        self.tabs.addTab(self.tab_evidence, "Evidence Provenance")

        main_layout.addWidget(self.tabs, stretch=1)

    def _create_identity_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        grid = QGridLayout()
        grid.setSpacing(10)

        labels = [
            ("Asset UUID:", "lbl_uuid"),
            ("Category:", "lbl_cat"),
            ("Vendor:", "lbl_vendor"),
            ("Model:", "lbl_model"),
            ("Firmware:", "lbl_firmware"),
            ("Primary MAC:", "lbl_mac"),
            ("Management IPs:", "lbl_ips"),
            ("Identity Confidence:", "lbl_conf_text"),
            ("External IDs:", "lbl_ext_ids"),
        ]

        self.identity_fields: Dict[str, QLabel] = {}
        for row, (label_text, attr_name) in enumerate(labels):
            lbl_title = QLabel(label_text)
            lbl_title.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 12px;")
            lbl_val = QLabel("-")
            lbl_val.setStyleSheet("color: #f0f6fc; font-size: 12px;")
            lbl_val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(lbl_title, row, 0)
            grid.addWidget(lbl_val, row, 1)
            self.identity_fields[attr_name] = lbl_val

        layout.addLayout(grid)
        layout.addStretch()
        return w

    def _create_ports_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        self.ports_table = QTableWidget(0, 5)
        self.ports_table.setAccessibleName("Physical Ports and Interfaces Table")
        self.ports_table.setHorizontalHeaderLabels(["Port / Interface", "Type / Medium", "MAC Address", "Speed / MTU", "State"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ports_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.ports_table)
        return w

    def _create_ip_history_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        self.ip_table = QTableWidget(0, 6)
        self.ip_table.setAccessibleName("IP Binding History Timeline Table")
        self.ip_table.setHorizontalHeaderLabels(["IP Address", "Interface", "Status", "Scope", "First Seen", "Last Seen"])
        self.ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ip_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.ip_table)
        return w

    def _create_topology_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        self.topo_table = QTableWidget(0, 5)
        self.topo_table.setAccessibleName("Connected Topology Interconnects Table")
        self.topo_table.setHorizontalHeaderLabels(["Direction", "Neighbor Asset", "Relationship Type", "Confidence", "Latency / Bandwidth"])
        self.topo_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.topo_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.topo_table)
        return w

    def _create_evidence_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(10, 10, 10, 10)

        self.conflict_banner = QLabel("")
        self.conflict_banner.setStyleSheet(
            "background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; "
            "border-radius: 4px; padding: 6px 10px; font-weight: bold; font-size: 11px;"
        )
        self.conflict_banner.setVisible(False)
        layout.addWidget(self.conflict_banner)

        self.evidence_table = QTableWidget(0, 5)
        self.evidence_table.setAccessibleName("Evidence Records and Observation Provenance Table")
        self.evidence_table.setHorizontalHeaderLabels(["Attribute / Target", "Observed Value", "Source Protocol", "Verification", "Observed At (UTC)"])
        self.evidence_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.evidence_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.evidence_table)
        return w

    def inspect_asset(self, asset: Optional[NetworkAsset], graph: Optional[AssetGraph] = None) -> None:
        """Bind and render a NetworkAsset with complete evidence and relationship details."""
        self.current_asset = asset
        self.current_graph = graph

        if asset is None:
            self.lbl_title.setText("(No Asset Selected)")
            self.lbl_sub.setText("Select an asset from the inventory to inspect identity, evidence, and topology.")
            self.lbl_status_badge.setText("OFFLINE")
            self.lbl_status_badge.setStyleSheet("background-color: #21262d; color: #8b949e; border: 1px solid #30363d; border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 11px;")
            self.lbl_confidence_badge.setText("Confidence: -")
            for field in self.identity_fields.values():
                field.setText("-")
            self.ports_table.setRowCount(0)
            self.ip_table.setRowCount(0)
            self.topo_table.setRowCount(0)
            self.evidence_table.setRowCount(0)
            self.conflict_banner.setVisible(False)
            return

        # 1. Update Header
        self.lbl_title.setText(asset.name)
        cat_str = asset.category.value if asset.category else "Unknown"
        self.lbl_sub.setText(f"Asset Category: {cat_str} | ID: {asset.id}")

        stat_str = asset.status.value if asset.status else "UNKNOWN"
        stat_color = "#3fb950" if stat_str == "ONLINE" else "#d29922" if stat_str in ("DEGRADED", "STALE") else "#8b949e"
        self.lbl_status_badge.setText(stat_str)
        self.lbl_status_badge.setStyleSheet(f"background-color: #161b22; color: {stat_color}; border: 1px solid {stat_color}; border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 11px;")

        conf = asset.identity.confidence
        conf_str = f"Confidence: {int(conf * 100)}%"
        conf_color = "#3fb950" if conf >= 0.9 else "#d29922" if conf >= 0.6 else "#f85149"
        self.lbl_confidence_badge.setText(conf_str)
        self.lbl_confidence_badge.setStyleSheet(f"background-color: #161b22; color: {conf_color}; border: 1px solid {conf_color}; border-radius: 4px; padding: 2px 8px; font-weight: bold; font-size: 11px;")

        # 2. Update Identity Tab
        self.identity_fields["lbl_uuid"].setText(asset.id)
        self.identity_fields["lbl_cat"].setText(asset.category.value)

        vendor_display = asset.vendor
        if asset.identity.vendor_guess and asset.identity.vendor_guess != asset.vendor:
            vendor_display += f" (Inferred: {asset.identity.vendor_guess})"
        self.identity_fields["lbl_vendor"].setText(vendor_display)

        model_display = asset.model
        if asset.identity.model_guess and asset.identity.model_guess != asset.model:
            model_display += f" (Inferred: {asset.identity.model_guess})"
        self.identity_fields["lbl_model"].setText(model_display)

        self.identity_fields["lbl_firmware"].setText(asset.firmware_version)
        self.identity_fields["lbl_mac"].setText(asset.identity.primary_mac or "(none)")
        self.identity_fields["lbl_ips"].setText(", ".join(asset.management_ips) if asset.management_ips else "(none)")
        self.identity_fields["lbl_conf_text"].setText(f"{conf:.2f} / 1.00 ({conf_str})")

        ext_ids_str = ", ".join(f"{k}={v}" for k, v in asset.identity.external_ids.items())
        self.identity_fields["lbl_ext_ids"].setText(ext_ids_str if ext_ids_str else "(none)")

        # 3. Update Ports & Interfaces Tab
        combined_ports: List[tuple[str, str, str, str, str]] = []
        for port_id, port in asset.ports.items():
            vlans = f"VLAN {port.untagged_vlan}" if port.untagged_vlan else ""
            if port.tagged_vlans:
                vlans += f" Tagged: {port.tagged_vlans}"
            speed_str = f"{port.speed_mbps} Mbps" if port.speed_mbps else port.medium
            combined_ports.append((port.name, port.medium, port.mac_address or "-", speed_str, "UP" if port.is_up else "DOWN"))

        for iface_name, iface in asset.interfaces.items():
            if iface_name not in [p.name for p in asset.ports.values()]:
                combined_ports.append((iface.name, iface.interface_type.value, iface.mac_address, f"MTU {iface.mtu}", iface.state.value))

        self.ports_table.setRowCount(len(combined_ports))
        for row, (p_name, p_type, p_mac, p_speed, p_state) in enumerate(combined_ports):
            self.ports_table.setItem(row, 0, QTableWidgetItem(p_name))
            self.ports_table.setItem(row, 1, QTableWidgetItem(p_type))
            self.ports_table.setItem(row, 2, QTableWidgetItem(p_mac))
            self.ports_table.setItem(row, 3, QTableWidgetItem(p_speed))
            self.ports_table.setItem(row, 4, QTableWidgetItem(p_state))

        # 4. Update IP Binding History Tab
        self.ip_table.setRowCount(len(asset.ip_history))
        for row, rec in enumerate(asset.ip_history):
            self.ip_table.setItem(row, 0, QTableWidgetItem(rec.ip_address))
            self.ip_table.setItem(row, 1, QTableWidgetItem(rec.interface_name or "-"))
            status_item = QTableWidgetItem("CURRENT" if rec.is_current else "HISTORICAL")
            status_item.setForeground(QColor("#3fb950" if rec.is_current else "#8b949e"))
            self.ip_table.setItem(row, 2, status_item)
            self.ip_table.setItem(row, 3, QTableWidgetItem(rec.scope or "global"))
            self.ip_table.setItem(row, 4, QTableWidgetItem(rec.first_seen.split("T")[0]))
            self.ip_table.setItem(row, 5, QTableWidgetItem(rec.last_seen.split("T")[0]))

        # 5. Update Topology Links Tab
        connected_links: List[tuple[str, str, str, str, str]] = []
        if graph:
            for link in graph.links.values():
                if link.source_asset_id == asset.id:
                    target_asset = graph.get_asset(link.target_asset_id)
                    target_name = target_asset.name if target_asset else link.target_asset_id
                    rel_type = link.relationship_type.value
                    conf_val = f"{int(link.confidence * 100)}%"
                    perf = f"{link.latency_ms or 0}ms / {link.bandwidth_mbps or 0}Mbps"
                    connected_links.append(("Outbound ->", target_name, rel_type, conf_val, perf))
                elif link.target_asset_id == asset.id:
                    src_asset = graph.get_asset(link.source_asset_id)
                    src_name = src_asset.name if src_asset else link.source_asset_id
                    rel_type = link.relationship_type.value
                    conf_val = f"{int(link.confidence * 100)}%"
                    perf = f"{link.latency_ms or 0}ms / {link.bandwidth_mbps or 0}Mbps"
                    connected_links.append(("<- Inbound", src_name, rel_type, conf_val, perf))

        self.topo_table.setRowCount(len(connected_links))
        for row, (dir_str, n_name, r_type, r_conf, r_perf) in enumerate(connected_links):
            self.topo_table.setItem(row, 0, QTableWidgetItem(dir_str))
            self.topo_table.setItem(row, 1, QTableWidgetItem(n_name))
            self.topo_table.setItem(row, 2, QTableWidgetItem(r_type))
            self.topo_table.setItem(row, 3, QTableWidgetItem(r_conf))
            self.topo_table.setItem(row, 4, QTableWidgetItem(r_perf))

        # 6. Update Evidence Tab & Conflict Warnings
        has_any_conflict = False
        evidence_rows: List[tuple[str, str, str, str, str]] = []

        # From attribute histories
        for attr_name, hist in asset.attribute_histories.items():
            if hist.has_conflict:
                has_any_conflict = True
            for obs in hist.observations:
                sanitized_dict, _ = CredentialRedactor.redact({attr_name: obs.value})
                redacted_val = sanitized_dict.get(attr_name, obs.value)
                proto_str = obs.evidence.source_protocol.value if hasattr(obs.evidence.source_protocol, "value") else str(obs.evidence.source_protocol)
                ver_str = "Verified Fact" if obs.evidence.is_verified_fact else "Inferred"
                evidence_rows.append((attr_name, str(redacted_val), proto_str, ver_str, obs.observed_at))

        # From direct evidence records
        for ev in asset.evidence_records:
            proto_str = ev.source_protocol.value if hasattr(ev.source_protocol, "value") else str(ev.source_protocol)
            ver_str = "Verified Fact" if ev.is_verified_fact else "Inferred"
            attr_display = ev.attribute or "Discovery Proof"
            sanitized_details, _ = CredentialRedactor.redact(ev.details or "-")
            evidence_rows.append((attr_display, str(sanitized_details), proto_str, ver_str, ev.timestamp))

        self.conflict_banner.setVisible(has_any_conflict)
        if has_any_conflict:
            self.conflict_banner.setText("⚠️ Conflicting observations detected across observation sources for one or more attributes.")

        self.evidence_table.setRowCount(len(evidence_rows))
        for row, (col0, col1, col2, col3, col4) in enumerate(evidence_rows):
            self.evidence_table.setItem(row, 0, QTableWidgetItem(col0))
            self.evidence_table.setItem(row, 1, QTableWidgetItem(col1))
            self.evidence_table.setItem(row, 2, QTableWidgetItem(col2))
            self.evidence_table.setItem(row, 3, QTableWidgetItem(col3))
            self.evidence_table.setItem(row, 4, QTableWidgetItem(col4))
