"""Unit tests for live bandwidth monitoring and traffic flow analysis."""

import unittest

from itsa_network_os.network.bandwidth import (
    BandwidthRate,
    InterfaceTrafficSample,
    TrafficMonitorEngine,
    format_bytes_rate,
    format_total_bytes,
)


class TestTrafficMonitorEngine(unittest.TestCase):
    """Test throughput calculations, byte formatting, and flow sampling."""

    def test_format_bytes_rate(self) -> None:
        self.assertEqual(format_bytes_rate(-10), "0.00 B/s")
        self.assertEqual(format_bytes_rate(512), "512.0 B/s")
        self.assertEqual(format_bytes_rate(1024), "1.00 KB/s")
        self.assertEqual(format_bytes_rate(1024 * 1024), "1.00 MB/s")
        self.assertEqual(format_bytes_rate(2.5 * 1024 * 1024), "2.50 MB/s")
        self.assertEqual(format_bytes_rate(1.5 * 1024 * 1024 * 1024), "1.50 GB/s")

    def test_format_total_bytes(self) -> None:
        self.assertEqual(format_total_bytes(500), "500 B")
        self.assertEqual(format_total_bytes(2048), "2.0 KB")
        self.assertEqual(format_total_bytes(10 * 1024 * 1024), "10.00 MB")
        self.assertEqual(format_total_bytes(5 * 1024 * 1024 * 1024), "5.00 GB")

    def test_sample_mock_interfaces(self) -> None:
        engine = TrafficMonitorEngine(use_mock=True)
        samples = engine.sample_all()

        self.assertIsInstance(samples, list)
        self.assertGreaterEqual(len(samples), 3)

        iface_names = [s.interface_name for s in samples]
        self.assertIn("eth0", iface_names)
        self.assertIn("wlan0", iface_names)
        self.assertIn("lo", iface_names)

        for s in samples:
            self.assertGreater(s.rx_bytes, 0)
            self.assertGreater(s.tx_bytes, 0)
            self.assertGreater(s.rx_packets, 0)
            self.assertGreater(s.tx_packets, 0)

    def test_calculate_rates_delta(self) -> None:
        engine = TrafficMonitorEngine(use_mock=True)

        # First sample
        samples1 = engine.sample_all()
        rates1 = engine.calculate_rates(samples1)
        self.assertEqual(len(rates1), len(samples1))

        for r in rates1:
            self.assertGreater(r.rx_bytes_sec, 0)
            self.assertGreater(r.tx_bytes_sec, 0)
            self.assertIn("B/s", r.rx_rate_formatted)

        # Second sample after small step
        samples2 = engine.sample_all()
        rates2 = engine.calculate_rates(samples2)
        self.assertEqual(len(rates2), len(samples2))

        for r in rates2:
            self.assertGreater(r.rx_bytes_sec, 0)
            self.assertGreater(r.tx_bytes_sec, 0)
            self.assertGreater(r.total_rx_bytes, 0)
            self.assertEqual(r.rx_errors, 0)
            self.assertEqual(r.tx_errors, 0)

    def test_bandwidth_rate_serialization(self) -> None:
        sample = InterfaceTrafficSample(
            interface_name="eth0",
            timestamp=1000.0,
            rx_bytes=100_000,
            tx_bytes=50_000,
            rx_packets=100,
            tx_packets=50,
        )
        data = sample.to_dict()
        self.assertEqual(data["interface_name"], "eth0")
        self.assertEqual(data["rx_bytes"], 100_000)

        rate = BandwidthRate(
            interface_name="eth0",
            duration_seconds=1.0,
            rx_bytes_sec=1024.0,
            tx_bytes_sec=512.0,
            rx_rate_formatted="1.00 KB/s",
            tx_rate_formatted="512.0 B/s",
            rx_packets_sec=10.0,
            tx_packets_sec=5.0,
            total_rx_bytes=100_000,
            total_tx_bytes=50_000,
            total_rx_packets=100,
            total_tx_packets=50,
        )
        rate_dict = rate.to_dict()
        self.assertEqual(rate_dict["interface_name"], "eth0")
        self.assertEqual(rate_dict["rx_rate_formatted"], "1.00 KB/s")
        self.assertEqual(rate_dict["duration_seconds"], 1.0)


if __name__ == "__main__":
    unittest.main()
