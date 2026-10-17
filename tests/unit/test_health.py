"""Unit tests for system health inspection service."""

import unittest
from itsa_network_os.core.health import HealthCheckService, HealthStatus, SystemHealthReport


class TestHealthService(unittest.TestCase):
    """Test read-only health checks."""

    def test_run_health_check_returns_report(self) -> None:
        report = HealthCheckService.run_health_check()
        self.assertIsInstance(report, SystemHealthReport)
        self.assertIn(report.status, [HealthStatus.HEALTHY, HealthStatus.WARNING, HealthStatus.DEGRADED])
        self.assertTrue(len(report.python_version) > 0)
        self.assertTrue(len(report.architecture) > 0)

    def test_to_dict_serializable(self) -> None:
        report = HealthCheckService.run_health_check()
        data = report.to_dict()
        self.assertIn("status", data)
        self.assertIn("python_version", data)
        self.assertIn("is_virtual_env", data)
        self.assertIsInstance(data["issues"], list)


if __name__ == "__main__":
    unittest.main()
