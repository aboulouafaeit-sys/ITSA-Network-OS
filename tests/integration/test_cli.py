"""Integration tests for application CLI."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from itsa_network_os.main import main


class TestCLIIntegration(unittest.TestCase):
    """End-to-end integration tests for command line entry point."""

    def test_cli_empty_args_shows_banner_and_help(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main([])
        self.assertEqual(code, 0)
        self.assertIn("ITSA Network OS", stdout_buf.getvalue())

    def test_cli_health_check(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--health"])
        self.assertEqual(code, 0)
        self.assertIn("System Status", stdout_buf.getvalue())

    def test_cli_health_check_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--health", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIn("status", output)
        self.assertIn("python_version", output)

    def test_cli_calc_subnet_success(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--calc-subnet", "10.0.0.0/24"])
        self.assertEqual(code, 0)
        self.assertIn("Subnet Breakdown", stdout_buf.getvalue())
        self.assertIn("254", stdout_buf.getvalue())

    def test_cli_calc_subnet_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--calc-subnet", "192.168.1.0/24", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertEqual(output["network_address"], "192.168.1.0")
        self.assertEqual(output["usable_hosts"], 254)

    def test_cli_calc_subnet_invalid(self) -> None:
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = main(["--calc-subnet", "invalid-cidr"])
        self.assertEqual(code, 1)
        self.assertIn("Error", stderr_buf.getvalue())

    def test_cli_list_interfaces(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--list-interfaces"])
        self.assertEqual(code, 0)
        self.assertIn("eth0", stdout_buf.getvalue())

    def test_cli_dns_query(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--dns", "example.com"])
        self.assertEqual(code, 0)
        self.assertIn("DNS Resolution", stdout_buf.getvalue())

    def test_cli_dns_query_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--dns", "example.com", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertEqual(output["target_host"], "example.com")
        self.assertEqual(output["status"], "SUCCESS")

    def test_cli_latency_benchmark(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--latency", "1.1.1.1", "--port", "443", "--count", "2"])
        self.assertEqual(code, 0)
        self.assertIn("Latency Benchmark", stdout_buf.getvalue())

    def test_cli_latency_benchmark_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--latency", "1.1.1.1", "--port", "443", "--count", "2", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertEqual(output["target_host"], "1.1.1.1")
        self.assertEqual(output["probes_sent"], 2)

    def test_cli_audit(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--audit"])
        self.assertEqual(code, 0)
        self.assertIn("Cybersecurity Posture Audit", stdout_buf.getvalue())

    def test_cli_audit_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--audit", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIn("overall_score", output)
        self.assertIn("findings", output)

    def test_cli_lab(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--lab"])
        self.assertEqual(code, 0)
        self.assertIn("Educational Cybersecurity Laboratory", stdout_buf.getvalue())

    def test_cli_lab_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--lab", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertGreater(len(output), 0)

    def test_cli_routes(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--routes"])
        self.assertEqual(code, 0)
        self.assertIn("Destination", stdout_buf.getvalue())

    def test_cli_routes_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--routes", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertGreater(len(output), 0)

    def test_cli_topology(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--topology"])
        self.assertEqual(code, 0)
        self.assertIn("Network Topology Graph", stdout_buf.getvalue())
        self.assertIn("wan-0", stdout_buf.getvalue())

    def test_cli_topology_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--topology", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIn("nodes", output)
        self.assertIn("links", output)
        self.assertGreater(len(output["nodes"]), 0)

    def test_cli_wifi_scan(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--wifi-scan"])
        self.assertEqual(code, 0)
        self.assertIn("Discovered Wi-Fi Access Points", stdout_buf.getvalue())
        self.assertIn("ITSA-Corp-Secure", stdout_buf.getvalue())

    def test_cli_wifi_scan_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--wifi-scan", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertGreaterEqual(len(output), 5)
        self.assertEqual(output[0]["ssid"], "ITSA-Corp-Secure")

    def test_cli_wifi_spectrum_2_4ghz(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--wifi-spectrum"])
        self.assertEqual(code, 0)
        self.assertIn("Wireless Spectrum Analysis", stdout_buf.getvalue())
        self.assertIn("2.4 GHz", stdout_buf.getvalue())
        self.assertIn("CH 1", stdout_buf.getvalue())

    def test_cli_wifi_spectrum_5ghz_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--wifi-spectrum", "--band", "5ghz", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertGreaterEqual(len(output), 15)
        channels = [item["channel"] for item in output]
        self.assertIn(36, channels)
        self.assertIn(149, channels)

    def test_cli_bandwidth(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--bandwidth"])
        self.assertEqual(code, 0)
        self.assertIn("Live Network Interface Bandwidth", stdout_buf.getvalue())
        self.assertIn("eth0", stdout_buf.getvalue())

    def test_cli_bandwidth_json(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main(["--bandwidth", "--json"])
        self.assertEqual(code, 0)
        output = json.loads(stdout_buf.getvalue())
        self.assertIsInstance(output, list)
        self.assertGreaterEqual(len(output), 3)
        self.assertEqual(output[0]["interface_name"], "eth0")
        self.assertIn("rx_bytes_sec", output[0])


if __name__ == "__main__":
    unittest.main()

