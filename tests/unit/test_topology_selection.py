"""Unit tests for topology link styling and stable node selection."""

import unittest

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False

from itsa_network_os.network.topology import (
    NetworkTopology,
    NodeStatus,
    TopologyLink,
    TopologyNode,
    TopologyNodeType,
)
from itsa_network_os.ui.desktop.topology_canvas import TopologyWidget


class TestTopologySemantics(unittest.TestCase):
    """Test topology epistemic link styles, node user data, and stable selection."""

    @classmethod
    def setUpClass(cls) -> None:
        if PYSIDE6_AVAILABLE:
            cls.qt_app = QApplication.instance() or QApplication(["test_app", "-platform", "offscreen"])
        else:
            cls.qt_app = None

    def setUp(self) -> None:
        if not PYSIDE6_AVAILABLE:
            self.skipTest("PySide6 required for topology tests")

        self.node1 = TopologyNode(id="n1", label="Gateway-R1", node_type=TopologyNodeType.GATEWAY, ip_address="192.168.1.1", status=NodeStatus.ONLINE, x=100.0, y=100.0)
        self.node2 = TopologyNode(id="n2", label="Switch-SW1", node_type=TopologyNodeType.SWITCH, ip_address="192.168.1.2", status=NodeStatus.ONLINE, x=250.0, y=100.0)
        self.node3 = TopologyNode(id="n3", label="DNS-Srv", node_type=TopologyNodeType.SERVER, ip_address="192.168.1.53", status=NodeStatus.ONLINE, x=400.0, y=100.0)

        self.link_verified = TopologyLink(id="l1", source_id="n1", target_id="n2", link_type="VERIFIED_L2_NEIGHBOR", speed_mbps=1000)
        self.link_inferred = TopologyLink(id="l2", source_id="n2", target_id="n3", link_type="INFERRED_SAME_SUBNET", speed_mbps=100)
        self.link_configured = TopologyLink(id="l3", source_id="n1", target_id="n3", link_type="CONFIGURED_DNS", speed_mbps=1000)
        self.link_unknown = TopologyLink(id="l4", source_id="n1", target_id="n2", link_type="UNKNOWN_LINK", speed_mbps=100)

        self.topo = NetworkTopology(
            nodes=[self.node1, self.node2, self.node3],
            links=[self.link_verified, self.link_inferred, self.link_configured, self.link_unknown],
        )
        self.widget = TopologyWidget(self.topo)

    def test_link_pen_styles(self) -> None:
        # Verified link: Solid line, green
        pen_v, badge_v = TopologyWidget._get_link_pen("VERIFIED_L2_NEIGHBOR")
        self.assertEqual(pen_v.style(), Qt.PenStyle.SolidLine)
        self.assertEqual(pen_v.color().name(), "#3fb950")
        self.assertIn("Verified", badge_v)

        # Inferred link: Dashed line, purple
        pen_i, badge_i = TopologyWidget._get_link_pen("INFERRED_SAME_SUBNET")
        self.assertEqual(pen_i.style(), Qt.PenStyle.DashLine)
        self.assertEqual(pen_i.color().name(), "#bc8cff")
        self.assertIn("Inferred", badge_i)

        # Configured link: Dotted line, cyan
        pen_c, badge_c = TopologyWidget._get_link_pen("CONFIGURED_GATEWAY")
        self.assertEqual(pen_c.style(), Qt.PenStyle.DotLine)
        self.assertEqual(pen_c.color().name(), "#79c0ff")
        self.assertIn("Configured", badge_c)

        # Standard / Unknown link: Solid line, gray
        pen_u, badge_u = TopologyWidget._get_link_pen("UNKNOWN")
        self.assertEqual(pen_u.style(), Qt.PenStyle.SolidLine)
        self.assertEqual(pen_u.color().name(), "#8b949e")

    def test_node_id_user_data_and_selection(self) -> None:
        # Find graphics items with data(0) set
        rect_items = [it for it in self.widget.scene.items() if it.data(0) is not None]
        self.assertEqual(len(rect_items), 3)

        item_node_ids = {it.data(0) for it in rect_items}
        self.assertEqual(item_node_ids, {"n1", "n2", "n3"})

        # Select n2's item and verify details updated
        n2_item = next(it for it in rect_items if it.data(0) == "n2")
        n2_item.setSelected(True)
        self.widget._on_selection_changed()

        self.assertEqual(self.widget.detail_title.text(), "Switch-SW1")
        self.assertIn("Node ID:</b> n2", self.widget.detail_info.text())


if __name__ == "__main__":
    unittest.main()
