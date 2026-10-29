"""Unit tests for unified AssetInventoryView and global search interaction."""

import unittest

try:
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    AssetIdentity,
    EntityStatus,
    NetworkAsset,
)
from itsa_network_os.ui.desktop.views.asset_inventory_view import AssetInventoryView


class TestAssetInventoryView(unittest.TestCase):
    """Test AssetInventoryView population, search filtering, selection, and empty states."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for inventory view tests")
        self.app = Application(config=AppConfig(database_file=":memory:"))
        self.view = AssetInventoryView(self.app)

    def test_inventory_initial_population(self) -> None:
        # Table should contain host asset and mock assets
        self.assertGreater(self.view.inventory_table.rowCount(), 0)
        self.assertGreaterEqual(len(self.view.all_assets), 1)
        self.assertIn("Displaying", self.view.status_banner.text())

    def test_inventory_category_filtering(self) -> None:
        # Filter for IP cameras
        self.view.active_category_filter = AssetCategory.IP_CAMERA
        self.view.apply_filter()

        cams = self.view.displayed_assets
        self.assertGreater(len(cams), 0)
        self.assertTrue(all(a.category == AssetCategory.IP_CAMERA for a in cams))

        # Reset filter
        self.view.active_category_filter = None
        self.view.apply_filter()
        self.assertGreater(len(self.view.displayed_assets), len(cams))

    def test_inventory_global_search_matching(self) -> None:
        # Search by specific keyword
        self.view.search_input.setText("cam")
        self.view.apply_filter()

        matched = self.view.displayed_assets
        self.assertGreater(len(matched), 0)
        for a in matched:
            text_pool = f"{a.name} {a.vendor} {a.model} {a.category.value}".lower()
            self.assertIn("cam", text_pool)

    def test_inventory_no_search_matches_state(self) -> None:
        self.view.search_input.setText("non_existent_target_string_xyz_12345")
        self.view.apply_filter()

        self.assertEqual(len(self.view.displayed_assets), 0)
        self.assertEqual(self.view.inventory_table.rowCount(), 0)
        self.assertIn("No assets matching query", self.view.status_banner.text())
        self.assertEqual(self.view.inspector.lbl_title.text(), "(No Asset Selected)")

    def test_inventory_row_selection_updates_inspector(self) -> None:
        self.view.search_input.setText("")
        self.view.apply_filter()

        self.view.inventory_table.selectRow(0)
        selected_asset = self.view.current_selected_asset
        self.assertIsNotNone(selected_asset)
        self.assertEqual(self.view.inspector.lbl_title.text(), selected_asset.name)

    def test_select_asset_by_id(self) -> None:
        first_asset = self.view.all_assets[0]
        found = self.view.select_asset_by_id(first_asset.id)
        self.assertTrue(found)
        self.assertEqual(self.view.current_selected_asset.id, first_asset.id)

    def test_inventory_empty_graph_state(self) -> None:
        # Manually set empty assets
        self.view.all_assets = []
        self.view.apply_filter()

        self.assertEqual(self.view.inventory_table.rowCount(), 0)
        self.assertIn("No assets available in property graph", self.view.status_banner.text())


if __name__ == "__main__":
    unittest.main()
