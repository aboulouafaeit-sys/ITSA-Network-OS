"""Unit tests for OSPF / Dijkstra Shortest Path First simulator and link-state models."""

from __future__ import annotations

import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.spf import (
    DijkstraStep,
    LinkStatus,
    SPFLink,
    SPFRouteEntry,
    SPFRouterNode,
    SPFSimulationResult,
    SPFSimulatorEngine,
)


class TestSPFSimulator(unittest.TestCase):
    """Test suite for OSPF Dijkstra SPF calculation, trace steps, and failover re-convergence."""

    def test_default_topology_creation(self) -> None:
        """Verify default topology generates standard 6-router mesh network."""
        nodes, links = SPFSimulatorEngine.get_default_topology()

        self.assertEqual(len(nodes), 6)
        self.assertEqual(len(links), 8)

        node_ids = [n.node_id for n in nodes]
        self.assertListEqual(node_ids, ["R1", "R2", "R3", "R4", "R5", "R6"])

        for link in links:
            self.assertEqual(link.status, LinkStatus.UP)
            self.assertGreater(link.cost, 0)
            self.assertIn("/", link.subnet)

    def test_dijkstra_spf_calculation_normal(self) -> None:
        """Verify optimal Dijkstra shortest path calculation from root R1."""
        result = SPFSimulatorEngine.calculate_spf(source_id="R1")

        self.assertIsInstance(result, SPFSimulationResult)
        self.assertEqual(result.source_router, "R1")
        self.assertIsNone(result.failed_link_id)
        self.assertEqual(len(result.routes), 5)
        self.assertEqual(len(result.unreachable_nodes), 0)

        routes_by_dest = {r.destination_node: r for r in result.routes}

        # Check optimal paths
        # R1 -> R2: cost 10
        self.assertEqual(routes_by_dest["R2"].total_cost, 10)
        self.assertEqual(routes_by_dest["R2"].next_hop_router, "R2")

        # R1 -> R3: cost 15 (R1 -> R2 -> R3: 10 + 5 = 15, beats direct link cost 20)
        self.assertEqual(routes_by_dest["R3"].total_cost, 15)
        self.assertEqual(routes_by_dest["R3"].full_path, ["R1", "R2", "R3"])

        # R1 -> R4: cost 15 (R1 -> R2 -> R4: 10 + 5 = 15)
        self.assertEqual(routes_by_dest["R4"].total_cost, 15)
        self.assertEqual(routes_by_dest["R4"].full_path, ["R1", "R2", "R4"])

        # R1 -> R5: cost 25 (R1 -> R2 -> R4 -> R5: 10 + 5 + 10 = 25)
        self.assertEqual(routes_by_dest["R5"].total_cost, 25)

        # R1 -> R6: cost 35 (10 + 5 + 10 + 10 = 35)
        self.assertEqual(routes_by_dest["R6"].total_cost, 35)

        # Check execution trace
        self.assertGreaterEqual(len(result.steps), 6)
        step0 = result.steps[0]
        self.assertEqual(step0.step_number, 0)
        self.assertIn("R1", step0.explanation)

    def test_link_failure_and_reconvergence(self) -> None:
        """Verify dynamic SPF re-convergence when primary link R1-R2 is severed."""
        result = SPFSimulatorEngine.calculate_spf(source_id="R1", failed_link_id="R1-R2")

        self.assertEqual(result.failed_link_id, "R1-R2")
        self.assertIn("Failover", result.convergence_status)

        routes_by_dest = {r.destination_node: r for r in result.routes}

        # With R1-R2 down, traffic must exit via R3 (direct link cost 20)
        self.assertEqual(routes_by_dest["R3"].total_cost, 20)
        self.assertEqual(routes_by_dest["R3"].next_hop_router, "R3")

        # Path to R2 is now via R3 (R1 -> R3 -> R2: 20 + 5 = 25)
        self.assertEqual(routes_by_dest["R2"].total_cost, 25)
        self.assertEqual(routes_by_dest["R2"].next_hop_router, "R3")
        self.assertEqual(routes_by_dest["R2"].full_path, ["R1", "R3", "R2"])

        # Path to R6 is now via R3 -> R5 -> R6 (20 + 15 + 10 = 45)
        self.assertEqual(routes_by_dest["R6"].total_cost, 45)
        self.assertEqual(routes_by_dest["R6"].next_hop_router, "R3")

    def test_invalid_source_raises_error(self) -> None:
        """Ensure non-existent source router raises ValueError."""
        with self.assertRaises(ValueError):
            SPFSimulatorEngine.calculate_spf(source_id="R99")

    def test_app_simulate_spf_service(self) -> None:
        """Ensure Application service layer dispatches SPF simulation correctly."""
        app = Application(config=AppConfig(database_file=":memory:"))
        res = app.simulate_spf(source="R2", failed_link=None)

        self.assertEqual(res.source_router, "R2")
        self.assertEqual(len(res.routes), 5)

    def test_spf_result_serialization(self) -> None:
        """Verify SPFSimulationResult converts cleanly to dict."""
        res = SPFSimulatorEngine.calculate_spf(source_id="R1")
        data = res.to_dict()

        self.assertEqual(data["source_router"], "R1")
        self.assertIsInstance(data["nodes"], list)
        self.assertIsInstance(data["links"], list)
        self.assertIsInstance(data["routes"], list)
        self.assertIsInstance(data["steps"], list)
        self.assertIn("destination_subnet", data["routes"][0])


if __name__ == "__main__":
    unittest.main()
