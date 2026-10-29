"""Unified Asset Inventory and Global Search desktop view."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import Qt, Signal
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QComboBox,
        QFrame,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QPushButton,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False
    QWidget = object  # type: ignore

    def Signal(*args: Any, **kwargs: Any) -> Any:  # type: ignore
        class _Signal:
            def connect(self, slot: Any) -> None:
                pass
            def emit(self, *a: Any, **kw: Any) -> None:
                pass
        return _Signal()

from itsa_network_os.app import Application
from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    EntityStatus,
    NetworkAsset,
    normalize_mac_address,
)
from itsa_network_os.ui.desktop.views.asset_detail_inspector import AssetDetailInspector
from itsa_network_os.ui.desktop.workers import AsyncOperationWorker, AsyncWorkerRunner


class AssetInventoryView(QWidget):  # type: ignore
    """Unified Asset Inventory table and integrated detail inspection view."""

    asset_selected = Signal(object)  # NetworkAsset

    def __init__(self, app: Application, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.app = app
        self.graph: Optional[AssetGraph] = None
        self.all_assets: List[NetworkAsset] = []
        self.displayed_assets: List[NetworkAsset] = []
        self.current_selected_asset: Optional[NetworkAsset] = None
        self.active_category_filter: Optional[AssetCategory] = None
        self._request_counter: int = 0
        self._is_loading: bool = False
        self._active_worker: Optional[AsyncOperationWorker] = None

        self.setAccessibleName("Unified Asset Inventory View")
        self.setAccessibleDescription("Comprehensive device inventory, identity verification, and evidentiary provenance.")

        if PYSIDE6_AVAILABLE:
            self._init_ui()
            self._load_initial_inventory()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        # 1. Header Row
        header_layout = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(4)

        title = QLabel("Unified Network Asset Inventory")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #58a6ff;")

        subtitle = QLabel("Canonical multi-vendor infrastructure assets, physical ports, IP bindings, and evidence provenance.")
        subtitle.setStyleSheet("color: #8b949e; font-size: 12px;")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box, stretch=1)

        # Refresh button
        self.btn_refresh = QPushButton("🔄 Refresh Inventory")
        self.btn_refresh.setProperty("class", "SecondaryButton")
        self.btn_refresh.setAccessibleName("Refresh Asset Inventory")
        self.btn_refresh.clicked.connect(self.refresh_inventory)
        header_layout.addWidget(self.btn_refresh)

        main_layout.addLayout(header_layout)

        # 2. Search & Filter Bar
        search_card = QFrame()
        search_card.setProperty("class", "CardFrame")
        search_layout = QHBoxLayout(search_card)
        search_layout.setContentsMargins(12, 8, 12, 8)
        search_layout.setSpacing(10)

        search_lbl = QLabel("🔍 Global Search:")
        search_lbl.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 12px;")
        search_layout.addWidget(search_lbl)

        self.search_input = QLineEdit()
        self.search_input.setAccessibleName("Global Asset Search Input")
        self.search_input.setPlaceholderText("Search by system name, IP, MAC, vendor, or category...")
        self.search_input.textChanged.connect(self._on_search_text_changed)
        search_layout.addWidget(self.search_input, stretch=2)

        cat_lbl = QLabel("Category:")
        cat_lbl.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 12px;")
        search_layout.addWidget(cat_lbl)

        self.category_combo = QComboBox()
        self.category_combo.setAccessibleName("Category Filter Dropdown")
        self.category_combo.addItem("All Categories", None)
        for cat in AssetCategory:
            if cat != AssetCategory.UNKNOWN:
                self.category_combo.addItem(cat.value.replace("_", " ").title(), cat)
        self.category_combo.currentIndexChanged.connect(self._on_category_combo_changed)
        search_layout.addWidget(self.category_combo)

        main_layout.addWidget(search_card)

        # 3. Status Notification Banner
        self.status_banner = QLabel("")
        self.status_banner.setWordWrap(True)
        self.status_banner.setStyleSheet(
            "background-color: #161b22; color: #8b949e; border: 1px solid #30363d; "
            "border-radius: 6px; padding: 6px 12px; font-size: 12px;"
        )
        main_layout.addWidget(self.status_banner)

        # 4. Center Splitter: Table (Left 58%) and Detail Inspector (Right 42%)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Table container
        table_container = QWidget()
        tc_layout = QVBoxLayout(table_container)
        tc_layout.setContentsMargins(0, 0, 0, 0)

        self.inventory_table = QTableWidget(0, 7)
        self.inventory_table.setAccessibleName("Asset Inventory Table")
        self.inventory_table.setHorizontalHeaderLabels([
            "Asset Name",
            "Category",
            "Vendor / Model",
            "Primary IP",
            "Primary MAC",
            "Freshness",
            "Status",
        ])
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.inventory_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.inventory_table.setColumnWidth(1, 100)
        self.inventory_table.setColumnWidth(2, 130)
        self.inventory_table.setColumnWidth(3, 110)
        self.inventory_table.setColumnWidth(4, 125)
        self.inventory_table.setColumnWidth(5, 80)
        self.inventory_table.setColumnWidth(6, 75)
        self.inventory_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.inventory_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.inventory_table.itemSelectionChanged.connect(self._on_table_selection_changed)
        tc_layout.addWidget(self.inventory_table)

        splitter.addWidget(table_container)

        # Right: Detail Inspector
        self.inspector = AssetDetailInspector(self)
        splitter.addWidget(self.inspector)

        splitter.setSizes([620, 450])
        main_layout.addWidget(splitter, stretch=1)

    def _load_initial_inventory(self) -> None:
        """Populate initial inventory synchronously from cached or seeded graph without extra discovery."""
        self.graph = self.app.get_asset_graph(refresh=False)
        self.all_assets = list(self.graph.assets.values())
        self.apply_filter()

    def refresh_inventory(self, refresh: bool = True) -> None:
        """Fetch latest AssetGraph from Application facade asynchronously and repopulate table."""
        if self._is_loading:
            return

        self._is_loading = True
        if hasattr(self, "btn_refresh") and self.btn_refresh is not None:
            self.btn_refresh.setEnabled(False)
            self.btn_refresh.setText("🔄 Loading...")
        self.status_banner.setText("Loading asset domain data...")

        self._request_counter += 1
        req_id = self._request_counter

        worker = AsyncOperationWorker(req_id, self.app.get_asset_graph, refresh=refresh)
        self._active_worker = worker

        AsyncWorkerRunner.launch(
            worker,
            on_finished=self._on_inventory_finished,
            on_failed=self._on_inventory_failed,
        )

    def _on_inventory_finished(self, req_id: int, graph: Any) -> None:
        """Handle completed inventory refresh on GUI thread."""
        if req_id != self._request_counter:
            return

        try:
            if not hasattr(self, "btn_refresh") or self.btn_refresh is None:
                return

            self._is_loading = False
            self.btn_refresh.setEnabled(True)
            self.btn_refresh.setText("🔄 Refresh Inventory")
            self.graph = graph
            self.all_assets = list(self.graph.assets.values())
            self.apply_filter()
        except RuntimeError:
            return

    def _on_inventory_failed(self, req_id: int, error_msg: str) -> None:
        """Handle inventory refresh failure on GUI thread."""
        if req_id != self._request_counter:
            return

        try:
            if not hasattr(self, "btn_refresh") or self.btn_refresh is None:
                return

            self._is_loading = False
            self.btn_refresh.setEnabled(True)
            self.btn_refresh.setText("🔄 Refresh Inventory")
            self.status_banner.setText(f"Failed to load asset domain: {error_msg}")
        except RuntimeError:
            return

    def _on_search_text_changed(self, text: str) -> None:
        self.apply_filter()

    def _on_category_combo_changed(self, index: int) -> None:
        self.active_category_filter = self.category_combo.currentData()
        self.apply_filter()

    def apply_filter(self) -> None:
        """Apply active text search query and category filter to asset list."""
        query = self.search_input.text().strip().lower()

        filtered: List[NetworkAsset] = []
        for asset in self.all_assets:
            # 1. Category check
            if self.active_category_filter and asset.category != self.active_category_filter:
                continue

            # 2. Text query check
            if query:
                name_match = query in asset.name.lower()
                vendor_match = query in asset.vendor.lower() or (asset.identity.vendor_guess and query in asset.identity.vendor_guess.lower())
                model_match = query in asset.model.lower() or (asset.identity.model_guess and query in asset.identity.model_guess.lower())
                ip_match = any(query in ip for ip in asset.management_ips)
                mac_match = bool(asset.identity.primary_mac and query in asset.identity.primary_mac.lower())
                cat_match = query in asset.category.value.lower()
                id_match = query in asset.id.lower()

                if not (name_match or vendor_match or model_match or ip_match or mac_match or cat_match or id_match):
                    continue

            filtered.append(asset)

        self.displayed_assets = filtered
        self._render_table()

    def _render_table(self) -> None:
        """Populate QTableWidget rows from displayed_assets."""
        query = self.search_input.text().strip()
        total_count = len(self.all_assets)
        shown_count = len(self.displayed_assets)

        # Update status banner
        if total_count == 0:
            self.status_banner.setText("No assets available in property graph. Execute discovery or inspection to populate.")
            self.status_banner.setStyleSheet("background-color: #161b22; color: #8b949e; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; font-size: 12px;")
        elif shown_count == 0:
            self.status_banner.setText(f"No assets matching query '{query}'. (0 of {total_count} shown).")
            self.status_banner.setStyleSheet("background-color: #382400; color: #f2cc60; border: 1px solid #bb8009; border-radius: 6px; padding: 6px 12px; font-size: 12px;")
        else:
            self.status_banner.setText(f"Displaying {shown_count} of {total_count} assets from property graph.")
            self.status_banner.setStyleSheet("background-color: #0d381e; color: #3fb950; border: 1px solid #238636; border-radius: 6px; padding: 6px 12px; font-size: 12px;")

        self.inventory_table.setRowCount(shown_count)

        for row_idx, asset in enumerate(self.displayed_assets):
            # 0: Name
            name_item = QTableWidgetItem(asset.name)
            name_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.inventory_table.setItem(row_idx, 0, name_item)

            # 1: Category
            self.inventory_table.setItem(row_idx, 1, QTableWidgetItem(asset.category.value))

            # 2: Vendor / Model
            vm_str = f"{asset.vendor} {asset.model}"
            self.inventory_table.setItem(row_idx, 2, QTableWidgetItem(vm_str))

            # 3: Primary IP
            ip_str = asset.management_ips[0] if asset.management_ips else "-"
            self.inventory_table.setItem(row_idx, 3, QTableWidgetItem(ip_str))

            # 4: Primary MAC
            mac_str = asset.identity.primary_mac or "-"
            self.inventory_table.setItem(row_idx, 4, QTableWidgetItem(mac_str))

            # 5: Freshness
            has_conflict = any(h.has_conflict for h in asset.attribute_histories.values())
            is_stale = any(obs.is_stale() for h in asset.attribute_histories.values() for obs in h.observations)

            if has_conflict:
                fresh_item = QTableWidgetItem("⚠️ Conflict")
                fresh_item.setForeground(QColor("#f85149"))
            elif is_stale:
                fresh_item = QTableWidgetItem("⏱️ Stale")
                fresh_item.setForeground(QColor("#d29922"))
            else:
                fresh_item = QTableWidgetItem("✓ Fresh")
                fresh_item.setForeground(QColor("#3fb950"))
            self.inventory_table.setItem(row_idx, 5, fresh_item)

            # 6: Status
            stat_item = QTableWidgetItem(asset.status.value)
            if asset.status == EntityStatus.ONLINE:
                stat_item.setForeground(QColor("#3fb950"))
            else:
                stat_item.setForeground(QColor("#8b949e"))
            stat_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.inventory_table.setItem(row_idx, 6, stat_item)

        if self.displayed_assets:
            self.inventory_table.selectRow(0)
        else:
            self.inspector.inspect_asset(None)

    def _on_table_selection_changed(self) -> None:
        selected_rows = self.inventory_table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        if 0 <= row < len(self.displayed_assets):
            asset = self.displayed_assets[row]
            self.current_selected_asset = asset
            self.inspector.inspect_asset(asset, self.graph)
            self.asset_selected.emit(asset)

    def select_asset_by_id(self, asset_id: str) -> bool:
        """Select asset in inventory table by its UUID string."""
        for row, asset in enumerate(self.displayed_assets):
            if asset.id == asset_id:
                self.inventory_table.selectRow(row)
                return True
        return False
