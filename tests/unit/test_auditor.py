"""Unit tests for security auditor module."""

import unittest
from itsa_network_os.security.auditor import SecurityAuditReport, SecurityAuditor, Severity


class TestSecurityAuditor(unittest.TestCase):
    """Test non-destructive security auditing."""

    def test_mock_security_audit(self) -> None:
        report = SecurityAuditor.run_audit(use_mock=True)
        self.assertIsInstance(report, SecurityAuditReport)
        self.assertGreaterEqual(report.overall_score, 0)
        self.assertLessEqual(report.overall_score, 100)
        self.assertGreater(len(report.findings), 0)

    def test_security_audit_to_dict(self) -> None:
        report = SecurityAuditor.run_audit(use_mock=True)
        data = report.to_dict()
        self.assertIn("overall_score", data)
        self.assertIn("findings", data)
        self.assertIn("open_local_ports", data)

    def test_live_audit_safe_run(self) -> None:
        # Verify that live audit completes safely without raising errors
        report = SecurityAuditor.run_audit(use_mock=False)
        self.assertIsInstance(report, SecurityAuditReport)
        self.assertTrue(any(f.category == "Privilege Boundary" for f in report.findings))


if __name__ == "__main__":
    unittest.main()
