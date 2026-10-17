"""Unit tests for latency benchmarking module."""

import unittest
from itsa_network_os.network.latency import LatencyBenchmarkResult, LatencyTester


class TestLatencyTester(unittest.TestCase):
    """Test non-root latency benchmarking logic."""

    def test_mock_latency_benchmark(self) -> None:
        result = LatencyTester.benchmark("1.1.1.1", port=443, count=4, use_mock=True)
        self.assertIsInstance(result, LatencyBenchmarkResult)
        self.assertEqual(result.target_host, "1.1.1.1")
        self.assertEqual(result.target_port, 443)
        self.assertEqual(result.probes_sent, 4)
        self.assertEqual(result.probes_received, 4)
        self.assertEqual(result.packet_loss_percent, 0.0)
        self.assertGreater(result.avg_latency_ms, 0.0)
        self.assertEqual(len(result.probes), 4)

    def test_latency_result_to_dict_serializable(self) -> None:
        result = LatencyTester.benchmark("8.8.8.8", port=53, count=3, use_mock=True)
        data = result.to_dict()
        self.assertIn("target_host", data)
        self.assertIn("probes", data)
        self.assertEqual(len(data["probes"]), 3)
        self.assertIn("packet_loss_percent", data)


if __name__ == "__main__":
    unittest.main()
