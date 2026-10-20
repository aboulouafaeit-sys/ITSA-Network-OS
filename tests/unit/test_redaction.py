"""Unit tests for automated credential and sensitive data redaction (TASK-012)."""

import copy
import unittest
from typing import Any, Dict, List

from itsa_network_os.storage.redaction import (
    CredentialRedactor,
    RedactionError,
    RedactionResult,
    redact_sensitive_data,
)


class TestCredentialRedactor(unittest.TestCase):
    """Exhaustive tests for CredentialRedactor across structured payloads, URLs, and edge cases."""

    def test_nested_dictionary_and_list_redaction(self) -> None:
        """Requirement 1: Nested dictionaries and lists have sensitive keys masked."""
        payload = {
            "device": {
                "name": "Core-Switch",
                "auth": {
                    "admin_password": "SuperSecretPassword123!",
                    "enable_pwd": "EnableSecret456!",
                },
                "vlans": [
                    {"id": 10, "name": "Management", "snmp_community": "private_corp"},
                    {"id": 20, "name": "Users"},
                ],
            }
        }
        sanitized, count = CredentialRedactor.redact(payload)
        self.assertEqual(count, 3)
        self.assertEqual(sanitized["device"]["auth"]["admin_password"], "***REDACTED***")
        self.assertEqual(sanitized["device"]["auth"]["enable_pwd"], "***REDACTED***")
        self.assertEqual(sanitized["device"]["vlans"][0]["snmp_community"], "***REDACTED***")
        self.assertEqual(sanitized["device"]["name"], "Core-Switch")
        self.assertEqual(sanitized["device"]["vlans"][1]["name"], "Users")

    def test_case_and_separator_variations(self) -> None:
        """Requirement 2: Case and separator variations (kebab, snake, camel, upper) are detected."""
        variations = {
            "PASSWORD": "val1",
            "PassWord": "val2",
            "api-key": "val3",
            "api_key": "val4",
            "apiKey": "val5",
            "client_secret": "val6",
            "clientSecret": "val7",
            "ACCESS-TOKEN": "val8",
            "wpa_passphrase": "val9",
            "pre-shared-key": "val10",
        }
        sanitized, count = CredentialRedactor.redact(variations)
        self.assertEqual(count, 10)
        for k in variations:
            self.assertEqual(sanitized[k], "***REDACTED***", f"Key '{k}' was not redacted")

    def test_rtsp_and_http_url_credentials(self) -> None:
        """Requirement 3: RTSP, HTTP, and HTTPS URLs with embedded userinfo are sanitized."""
        urls = {
            "camera_rtsp": "rtsp://admin:CameraPass2026@192.168.1.100:554/ch01/live",
            "api_http": "http://service_user:AuthSecret99@10.0.0.5:8080/v1/metrics",
            "webhook_https": "https://deployer:ghp_secretToken@api.github.com/webhook",
        }
        sanitized, count = CredentialRedactor.redact(urls)
        self.assertEqual(count, 3)
        self.assertEqual(
            sanitized["camera_rtsp"],
            "rtsp://admin:***REDACTED***@192.168.1.100:554/ch01/live",
        )
        self.assertEqual(
            sanitized["api_http"],
            "http://service_user:***REDACTED***@10.0.0.5:8080/v1/metrics",
        )
        self.assertEqual(
            sanitized["webhook_https"],
            "https://deployer:***REDACTED***@api.github.com/webhook",
        )

    def test_percent_encoded_url_credentials(self) -> None:
        """Requirement 4: Percent-encoded username and password in URLs are sanitized."""
        url = "rtsp://admin%40corp:%24%25%5E%26secret%20123@gateway.local/live"
        sanitized, count = CredentialRedactor.redact(url)
        self.assertEqual(count, 1)
        self.assertEqual(
            sanitized,
            "rtsp://admin%40corp:***REDACTED***@gateway.local/live",
        )

    def test_ipv6_urls_and_optional_ports(self) -> None:
        """Requirement 5: IPv6 URLs with optional ports and embedded userinfo are sanitized."""
        url_with_port = "rtsp://operator:p%40ss@[2001:db8::1]:8554/stream"
        url_without_port = "https://admin:secret@[fe80::1ff:fe00:1]/management"
        url_user_only = "http://token_user@[2001:db8:85a3::8a2e:370:7334]/api"

        s1, c1 = CredentialRedactor.redact(url_with_port)
        s2, c2 = CredentialRedactor.redact(url_without_port)
        s3, c3 = CredentialRedactor.redact(url_user_only)

        self.assertEqual(c1, 1)
        self.assertEqual(s1, "rtsp://operator:***REDACTED***@[2001:db8::1]:8554/stream")

        self.assertEqual(c2, 1)
        self.assertEqual(s2, "https://admin:***REDACTED***@[fe80::1ff:fe00:1]/management")

        self.assertEqual(c3, 1)
        self.assertEqual(s3, "http://***REDACTED***@[2001:db8:85a3::8a2e:370:7334]/api")

    def test_bearer_authorization_values(self) -> None:
        """Requirement 6: Bearer authorization headers and embedded tokens are redacted."""
        text = "Request failed: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123 received 401"
        sanitized, count = CredentialRedactor.redact(text)
        self.assertEqual(count, 1)
        self.assertNotIn("eyJhbGci", sanitized)
        self.assertIn("Authorization: Bearer ***REDACTED***", sanitized)

    def test_pem_private_key_blocks(self) -> None:
        """Requirement 7: PEM private key blocks are redacted while public certificates are preserved."""
        pem_bundle = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1234567890abcdef==\n"
            "-----END RSA PRIVATE KEY-----\n"
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBkTCB+wIBADANBgkqhkiG9w0BAQsFADAN\n"
            "-----END CERTIFICATE-----"
        )
        sanitized, count = CredentialRedactor.redact(pem_bundle)
        self.assertEqual(count, 1)
        self.assertNotIn("0Y1234567890abcdef", sanitized)
        self.assertIn("-----BEGIN PRIVATE KEY----- ***REDACTED KEY*** -----END PRIVATE KEY-----", sanitized)
        # Public certificate must remain intact
        self.assertIn("-----BEGIN CERTIFICATE-----", sanitized)
        self.assertIn("MIIBkTCB+wIBADANBgkqhkiG9w0BAQsFADAN", sanitized)

    def test_snmp_community_values(self) -> None:
        """Requirement 8: SNMP community strings in keys or inline text are sanitized."""
        payload = {
            "target": "10.0.0.1",
            "snmp_community": "public_read_only",
            "write_community": "super_private_rw",
            "config_note": "polling with community=monitoring_secret via snmpwalk",
        }
        sanitized, count = CredentialRedactor.redact(payload)
        self.assertEqual(count, 3)
        self.assertEqual(sanitized["snmp_community"], "***REDACTED***")
        self.assertEqual(sanitized["write_community"], "***REDACTED***")
        self.assertIn("community=***REDACTED***", sanitized["config_note"])
        self.assertNotIn("monitoring_secret", sanitized["config_note"])

    def test_wifi_psk_and_passphrase_fields(self) -> None:
        """Requirement 9: Wi-Fi pre-shared keys, WPS pins, and passphrases are sanitized."""
        wifi_info = {
            "ssid": "SecureCorp-Office",
            "wpa_key": "WPA2PersonalSecretKey123",
            "psk": "PreSharedKeyHex98765",
            "wps_pin": 12345670,
        }
        sanitized, count = CredentialRedactor.redact(wifi_info)
        self.assertEqual(count, 3)
        self.assertEqual(sanitized["ssid"], "SecureCorp-Office")
        self.assertEqual(sanitized["wpa_key"], "***REDACTED***")
        self.assertEqual(sanitized["psk"], "***REDACTED***")
        self.assertEqual(sanitized["wps_pin"], "***REDACTED***")

    def test_unchanged_non_sensitive_values(self) -> None:
        """Requirement 10: Non-sensitive diagnostic telemetry, metrics, and network IPs remain intact."""
        safe_data = {
            "host": "192.168.1.1",
            "mac": "00:11:22:33:44:55",
            "latency_ms": 14.5,
            "packet_loss": 0.0,
            "is_active": True,
            "interfaces": ["eth0", "wlan0"],
            "notes": "Routine latency benchmark to gateway",
            "empty_val": None,
        }
        sanitized, count = CredentialRedactor.redact(safe_data)
        self.assertEqual(count, 0)
        self.assertEqual(sanitized, safe_data)

    def test_deep_copy_and_caller_immutability(self) -> None:
        """Requirement 11: Redaction creates an independent copy; caller input is never modified."""
        original = {
            "credentials": {
                "admin_password": "OriginalSecretPassword",
                "nested_list": ["item1", {"token": "secret_token_val"}],
            }
        }
        original_copy = copy.deepcopy(original)

        sanitized, count = CredentialRedactor.redact(original)
        self.assertEqual(count, 2)

        # Original input must be completely unchanged
        self.assertEqual(original, original_copy)
        self.assertEqual(
            original["credentials"]["admin_password"], "OriginalSecretPassword"
        )
        self.assertEqual(
            original["credentials"]["nested_list"][1]["token"], "secret_token_val"
        )

        # Sanitized output has modifications
        self.assertEqual(sanitized["credentials"]["admin_password"], "***REDACTED***")
        self.assertEqual(
            sanitized["credentials"]["nested_list"][1]["token"], "***REDACTED***"
        )

    def test_multiple_secrets_within_single_payload(self) -> None:
        """Requirement 12: Multiple secrets within a single text block or payload are counted and masked."""
        complex_text = (
            "Found camera at rtsp://admin:pass1@192.168.1.50/stream. "
            "Backup endpoint is http://user:pass2@10.0.0.1/api. "
            "Use Bearer eyJhbGciOiJIUzI1NiI.testToken for auth with password: MyPassword99."
        )
        sanitized, count = CredentialRedactor.redact(complex_text)
        self.assertEqual(count, 4)
        self.assertNotIn("pass1", sanitized)
        self.assertNotIn("pass2", sanitized)
        self.assertNotIn("testToken", sanitized)
        self.assertNotIn("MyPassword99", sanitized)
        self.assertIn("rtsp://admin:***REDACTED***@192.168.1.50/stream", sanitized)
        self.assertIn("http://user:***REDACTED***@10.0.0.1/api", sanitized)
        self.assertIn("Bearer ***REDACTED***", sanitized)
        self.assertIn("password:***REDACTED***", sanitized)

    def test_invalid_or_unsupported_input_fail_closed(self) -> None:
        """Requirement 13: Unsupported non-serializable objects raise RedactionError (fail-closed)."""
        class UnsupportedClass:
            pass

        unsupported_obj = {"valid": 1, "bad_handle": UnsupportedClass()}

        with self.assertRaises(RedactionError) as cm:
            CredentialRedactor.redact(unsupported_obj)
        self.assertIn("Unsupported payload type", str(cm.exception))

    def test_unicode_and_ordinary_diagnostic_text(self) -> None:
        """Requirement 14: Unicode characters, Cyrillic/Asian telemetry, and ordinary text are preserved."""
        unicode_data = {
            "device_name": "Маршрутизатор-Главный-01",
            "location": "東京データセンター",
            "description": "Temperature: 45°C ± 0.5°C; throughput ≈ 1.2 Gbps; latency ≤ 2ms.",
            "token": "secret_unicode_token_123",
        }
        sanitized, count = CredentialRedactor.redact(unicode_data)
        self.assertEqual(count, 1)
        self.assertEqual(sanitized["device_name"], "Маршрутизатор-Главный-01")
        self.assertEqual(sanitized["location"], "東京データセンター")
        self.assertIn("45°C", sanitized["description"])
        self.assertEqual(sanitized["token"], "***REDACTED***")

    def test_accurate_redaction_accounting(self) -> None:
        """Requirement 15: Redaction accounting strictly tallies unique redactions without double counting."""
        # 1. Zero secrets -> count 0
        _, c0 = CredentialRedactor.redact({"status": "OK", "code": 200})
        self.assertEqual(c0, 0)

        # 2. Already redacted string should not be double-counted (idempotence)
        pre_redacted = {
            "password": "***REDACTED***",
            "uri": "rtsp://admin:***REDACTED***@192.168.1.10/live",
        }
        sanitized_pre, c_pre = CredentialRedactor.redact(pre_redacted)
        self.assertEqual(c_pre, 0)
        self.assertEqual(sanitized_pre["password"], "***REDACTED***")
        self.assertEqual(sanitized_pre["uri"], "rtsp://admin:***REDACTED***@192.168.1.10/live")

        # 3. Convenience function test
        result = redact_sensitive_data({"api_key": "secret123"})
        self.assertIsInstance(result, RedactionResult)
        self.assertEqual(result.redacted_count, 1)
        self.assertEqual(result.data["api_key"], "***REDACTED***")

    def test_url_query_parameter_credential_redaction(self) -> None:
        """Check 2: Sensitive URL query parameters (token, access_token, api_key, password, secret, community)."""
        test_urls = {
            "token": "https://device.local/api?token=SECRET123",
            "access_token": "https://device.local/api?access_token=SECRET456",
            "api_key": "https://device.local/api?api_key=SECRET789",
            "password": "https://device.local/api?password=SECRET_PASS",
            "secret": "https://device.local/api?secret=SECRET_VAL",
            "community": "http://switch.local/snmp?community=private_comm",
        }
        for param, url in test_urls.items():
            sanitized, count = CredentialRedactor.redact_string(url)
            self.assertEqual(count, 1, f"Failed count for {param}: {url}")
            self.assertNotIn("SECRET", sanitized)
            self.assertNotIn("private_comm", sanitized)
            self.assertIn(f"{param}=***REDACTED***", sanitized)

    def test_url_query_preserves_non_sensitive_parameters(self) -> None:
        """Check 2: Preserves useful non-sensitive URL information (format, page, limit, other)."""
        url = "https://device.local/api?format=json&token=SECRET123&page=2&limit=50&target=switch01"
        sanitized, count = CredentialRedactor.redact_string(url)
        self.assertEqual(count, 1)
        self.assertNotIn("SECRET123", sanitized)
        self.assertIn("format=json", sanitized)
        self.assertIn("token=***REDACTED***", sanitized)
        self.assertIn("page=2", sanitized)
        self.assertIn("limit=50", sanitized)
        self.assertIn("target=switch01", sanitized)

    def test_url_query_encoded_names_and_values(self) -> None:
        """Check 2: Sanitizes URL-encoded parameter names and handles URL-encoded secret values."""
        # api%5Fkey is URL-encoded api_key
        url_encoded_name = "https://device.local/api?api%5Fkey=SECRET999&format=xml"
        sanitized_name, count_name = CredentialRedactor.redact_string(url_encoded_name)
        self.assertEqual(count_name, 1)
        self.assertNotIn("SECRET999", sanitized_name)
        self.assertIn("api%5Fkey=***REDACTED***", sanitized_name)
        self.assertIn("format=xml", sanitized_name)

        # URL-encoded secret value
        url_encoded_val = "https://device.local/api?password=foo%20bar%26baz&user=admin"
        sanitized_val, count_val = CredentialRedactor.redact_string(url_encoded_val)
        self.assertEqual(count_val, 1)
        self.assertNotIn("foo", sanitized_val)
        self.assertNotIn("bar", sanitized_val)
        self.assertIn("password=***REDACTED***", sanitized_val)
        self.assertIn("user=admin", sanitized_val)

    def test_url_query_repeated_parameters_and_fragments(self) -> None:
        """Check 2: Repeated query parameters, ordinary URL fragments, and sensitive fragment tokens."""
        # Repeated parameter
        repeated_url = "https://device.local/api?token=SECRET_ONE&token=SECRET_TWO&page=1"
        sanitized_rep, count_rep = CredentialRedactor.redact_string(repeated_url)
        self.assertEqual(count_rep, 2)
        self.assertNotIn("SECRET_ONE", sanitized_rep)
        self.assertNotIn("SECRET_TWO", sanitized_rep)
        self.assertEqual(
            sanitized_rep,
            "https://device.local/api?token=***REDACTED***&token=***REDACTED***&page=1",
        )

        # Non-sensitive fragment preserved
        frag_url = "https://device.local/api?token=SECRET123#telemetry_section"
        sanitized_frag, count_frag = CredentialRedactor.redact_string(frag_url)
        self.assertEqual(count_frag, 1)
        self.assertNotIn("SECRET123", sanitized_frag)
        self.assertIn("token=***REDACTED***", sanitized_frag)
        self.assertIn("#telemetry_section", sanitized_frag)

        # Sensitive OAuth2 fragment parameter sanitized
        oauth_url = "https://device.local/oauth/callback#access_token=SECRET_OAUTH&token_type=bearer"
        sanitized_oauth, count_oauth = CredentialRedactor.redact_string(oauth_url)
        self.assertEqual(count_oauth, 1)
        self.assertNotIn("SECRET_OAUTH", sanitized_oauth)
        self.assertIn("access_token=***REDACTED***", sanitized_oauth)
        self.assertIn("token_type=bearer", sanitized_oauth)

    def test_url_both_userinfo_and_query_credentials(self) -> None:
        """Check 2: Redacts both embedded userinfo AND query parameters in a single URL with accurate accounting."""
        url = "rtsp://camera_admin:CameraSecretPass@192.168.1.100:554/stream?api_key=SynthKey123&fps=30#main"
        sanitized, count = CredentialRedactor.redact_string(url)
        self.assertEqual(count, 2)
        self.assertNotIn("CameraSecretPass", sanitized)
        self.assertNotIn("SynthKey123", sanitized)
        self.assertEqual(
            sanitized,
            "rtsp://camera_admin:***REDACTED***@192.168.1.100:554/stream?api_key=***REDACTED***&fps=30#main",
        )

    def test_url_inside_sentence_with_trailing_punctuation(self) -> None:
        """Check 2: Correctly redacts URL inside sentence text without swallowing trailing punctuation."""
        text = "Diagnostic report at https://device.local/api?token=SECRET123, verified by monitor."
        sanitized, count = CredentialRedactor.redact_string(text)
        self.assertEqual(count, 1)
        self.assertNotIn("SECRET123", sanitized)
        self.assertIn("https://device.local/api?token=***REDACTED***,", sanitized)
        self.assertTrue(sanitized.endswith(", verified by monitor."))


if __name__ == "__main__":
    unittest.main()

