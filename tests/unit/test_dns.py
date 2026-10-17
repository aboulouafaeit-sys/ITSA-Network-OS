"""Unit tests for DNS diagnostics module."""

import unittest
from itsa_network_os.network.dns import DNSDiagnosticResult, DNSDiagnostics


class TestDNSDiagnostics(unittest.TestCase):
    """Test safe DNS query resolution and mock handling."""

    def test_mock_dns_query(self) -> None:
        result = DNSDiagnostics.query("example.com", use_mock=True)
        self.assertIsInstance(result, DNSDiagnosticResult)
        self.assertEqual(result.target_host, "example.com")
        self.assertEqual(result.status, "SUCCESS")
        self.assertGreater(len(result.records), 0)
        self.assertGreater(result.response_time_ms, 0.0)

    def test_mock_dns_to_dict_serializable(self) -> None:
        result = DNSDiagnostics.query("cloudflare.com", use_mock=True)
        data = result.to_dict()
        self.assertIn("target_host", data)
        self.assertIn("records", data)
        self.assertIn("response_time_ms", data)
        self.assertEqual(data["status"], "SUCCESS")

    def test_get_system_resolvers_returns_list(self) -> None:
        resolvers = DNSDiagnostics.get_system_resolvers()
        self.assertIsInstance(resolvers, list)
        self.assertGreater(len(resolvers), 0)


if __name__ == "__main__":
    unittest.main()
