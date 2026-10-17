"""Unit tests for network topology engine."""

import unittest
from itsa_network_os.network.topology import (
    NetworkTopology,
    NodeStatus,
    TopologyDiscoveryEngine,
    TopologyLink,
    TopologyNode,
    TopologyNodeType,
)


class TestTopologyEngine(unittest.TestCase):
    """Test topology discovery, serialization, and coordinate layout."""

    def test_default_topology_discovery(self) -> None:
        topo = TopologyDiscoveryEngine.get_default_topology()
        self.assertIsInstance(topo, NetworkTopology)
        self.assertGreaterEqual(len(topo.nodes), 5)
        self.assertGreaterEqual(len(topo.links), 4)

    def test_topology_serialization(self) -> None:
        topo = TopologyDiscoveryEngine.get_default_topology()
        data = topo.to_dict()
        self.assertIn("nodes", data)
        self.assertIn("links", data)
        self.assertIsInstance(data["nodes"], list)
        self.assertIsInstance(data["links"], list)

        first_node = data["nodes"][0]
        self.assertIn("id", first_node)
        self.assertIn("node_type", first_node)
        self.assertIn("x", first_node)
        self.assertIn("y", first_node)

    def test_hierarchical_layout_coordinates(self) -> None:
        topo = TopologyDiscoveryEngine.get_default_topology()
        topo.compute_hierarchical_layout(width=1000.0, height=600.0)

        # Ensure all nodes have non-zero positive coordinates
        for n in topo.nodes:
            self.assertGreater(n.x, 0.0)
            self.assertGreater(n.y, 0.0)
            self.assertLessEqual(n.x, 1000.0)
            self.assertLessEqual(n.y, 600.0)


if __name__ == "__main__":
    unittest.main()
