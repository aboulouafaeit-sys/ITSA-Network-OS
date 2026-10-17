"""Unit tests for TLS/SSL cryptographic inspector engine and models."""

from __future__ import annotations

import unittest

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.security.tls import (
    CipherSecurityLevel,
    TLSInspectionReport,
    TLSInspectorEngine,
    X509CertificateInfo,
)
from itsa_network_os.security.validator import SecurityValidationError


class TestTLSInspector(unittest.TestCase):
    """Test suite for TLS/SSL certificate decoding and cryptographic evaluation."""

    def test_tls_inspector_default_mock(self) -> None:
        """Test standard TLS inspection returns valid report with modern security posture."""
        report = TLSInspectorEngine.inspect("cloudflare.com", 443, use_mock=True)

        self.assertIsInstance(report, TLSInspectionReport)
        self.assertEqual(report.target_host, "cloudflare.com")
        self.assertEqual(report.target_port, 443)
        self.assertEqual(report.negotiated_protocol, "TLSv1.3")
        self.assertEqual(report.cipher_security, CipherSecurityLevel.STRONG)
        self.assertEqual(report.overall_score, 100)
        self.assertGreaterEqual(len(report.certificate_chain), 1)

        cert = report.certificate_chain[0]
        self.assertEqual(cert.subject_cn, "*.cloudflare.com")
        self.assertFalse(cert.is_expired)
        self.assertFalse(cert.is_self_signed)
        self.assertIn("cloudflare.com", cert.san_list)
        self.assertNotEqual(cert.fingerprint_sha256, "")

    def test_tls_inspector_legacy_vulnerable_mock(self) -> None:
        """Test legacy target inspection flags 3DES, TLS 1.0, and expired certificate."""
        report = TLSInspectorEngine.inspect("legacy.internal", 443, use_mock=True)

        self.assertEqual(report.negotiated_protocol, "TLSv1.0")
        self.assertEqual(report.cipher_security, CipherSecurityLevel.INSECURE)
        self.assertLessEqual(report.overall_score, 20)
        self.assertGreaterEqual(len(report.vulnerabilities), 2)
        self.assertTrue(any("TLSv1.0" in v for v in report.vulnerabilities))
        self.assertTrue(any("3DES" in v for v in report.vulnerabilities))
        self.assertGreaterEqual(len(report.recommendations), 2)

        cert = report.certificate_chain[0]
        self.assertTrue(cert.is_expired)
        self.assertLess(cert.days_until_expiration, 0)

    def test_tls_inspector_self_signed_mock(self) -> None:
        """Test self-signed target inspection flags self-signed certificate warning."""
        report = TLSInspectorEngine.inspect("gateway.local", 8443, use_mock=True)

        cert = report.certificate_chain[0]
        self.assertTrue(cert.is_self_signed)
        self.assertTrue(any("self-signed" in v.lower() for v in report.vulnerabilities))
        self.assertLess(report.overall_score, 100)

    def test_tls_app_service_integration(self) -> None:
        """Test Application.inspect_tls handles input validation and execution."""
        app = Application(config=AppConfig(database_file=":memory:", use_mock_network=True))

        # Valid execution
        report = app.inspect_tls("example.com", port=443)
        self.assertEqual(report.target_host, "example.com")
        self.assertEqual(report.overall_score, 100)

        # Invalid host with injection characters
        with self.assertRaises(SecurityValidationError):
            app.inspect_tls("example.com; rm -rf /")

        # Invalid port
        with self.assertRaises(SecurityValidationError):
            app.inspect_tls("example.com", port=70000)

    def test_tls_report_serialization(self) -> None:
        """Test serialization of TLSInspectionReport to dict."""
        report = TLSInspectorEngine.inspect("example.com", 443, use_mock=True)
        d = report.to_dict()

        self.assertEqual(d["target_host"], "example.com")
        self.assertEqual(d["cipher_security"], CipherSecurityLevel.STRONG.value)
        self.assertIsInstance(d["certificate_chain"], list)
        self.assertIn("fingerprint_sha256", d["certificate_chain"][0])


if __name__ == "__main__":
    unittest.main()
