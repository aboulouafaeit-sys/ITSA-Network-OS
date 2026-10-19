"""Unit tests for Authorized Network Scope Enclosure and Runtime Scope Guard (TASK-008 / REQ-DISC-002)."""

from __future__ import annotations

import io
import ipaddress
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
import socket
from unittest.mock import patch

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.main import main
from itsa_network_os.network.scope import (
    ScopeEnclosure,
    ScopeGuard,
    ScopeViolationError,
)
from itsa_network_os.security.validator import SecurityValidationError


class TestScopeEnclosureConstruction(unittest.TestCase):
    """Test suite for ScopeEnclosure instantiation, parsing, and input validation."""

    def test_valid_single_ipv4_cidr(self) -> None:
        """Verify construction with a single IPv4 CIDR network."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertEqual(len(enclosure.cidrs), 1)
        self.assertEqual(str(enclosure.cidrs[0]), "192.168.1.0/24")
        self.assertEqual(enclosure.interfaces, ())
        self.assertTrue(enclosure.allow_loopback)
        self.assertFalse(enclosure.allow_global_internet)

    def test_valid_single_ipv6_cidr(self) -> None:
        """Verify construction with a single IPv6 CIDR network."""
        enclosure = ScopeEnclosure.from_strings(cidrs="fd00:abcd::/64")
        self.assertEqual(len(enclosure.cidrs), 1)
        self.assertEqual(str(enclosure.cidrs[0]), "fd00:abcd::/64")
        self.assertIsInstance(enclosure.cidrs[0], ipaddress.IPv6Network)

    def test_valid_mixed_dual_stack_cidrs(self) -> None:
        """Verify construction with multiple mixed IPv4 and IPv6 CIDRs."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.0/24", "10.0.0.0/16", "2001:db8:acad::/48"]
        )
        self.assertEqual(len(enclosure.cidrs), 3)
        self.assertEqual(str(enclosure.cidrs[0]), "192.168.1.0/24")
        self.assertEqual(str(enclosure.cidrs[1]), "10.0.0.0/16")
        self.assertEqual(str(enclosure.cidrs[2]), "2001:db8:acad::/48")

    def test_comma_separated_cidr_string(self) -> None:
        """Verify parsing comma-separated CIDR strings with surrounding whitespace."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs="  192.168.1.0/24 ,  10.0.0.0/8 , fd00::/64  "
        )
        self.assertEqual(len(enclosure.cidrs), 3)
        self.assertEqual(str(enclosure.cidrs[0]), "192.168.1.0/24")
        self.assertEqual(str(enclosure.cidrs[1]), "10.0.0.0/8")
        self.assertEqual(str(enclosure.cidrs[2]), "fd00::/64")

    def test_single_host_ipv4_and_ipv6(self) -> None:
        """Verify /32 and /128 single host CIDR boundaries."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.50/32", "2001:db8::1/128"]
        )
        self.assertEqual(len(enclosure.cidrs), 2)
        self.assertEqual(enclosure.cidrs[0].prefixlen, 32)
        self.assertEqual(enclosure.cidrs[1].prefixlen, 128)

    def test_interface_bindings(self) -> None:
        """Verify interface bindings parsing and sanitization."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs="192.168.1.0/24",
            interfaces="eth0, wlan0",
        )
        self.assertEqual(enclosure.interfaces, ("eth0", "wlan0"))

    def test_overly_broad_ipv4_prohibited_by_default(self) -> None:
        """Ensure 0.0.0.0/0 is rejected by default to prevent wide-area scans."""
        with self.assertRaises(SecurityValidationError) as ctx:
            ScopeEnclosure.from_strings(cidrs="0.0.0.0/0")
        self.assertIn("Overly broad network scope", str(ctx.exception))

    def test_overly_broad_ipv6_prohibited_by_default(self) -> None:
        """Ensure ::/0 is rejected by default to prevent wide-area scans."""
        with self.assertRaises(SecurityValidationError) as ctx:
            ScopeEnclosure.from_strings(cidrs="::/0")
        self.assertIn("Overly broad network scope", str(ctx.exception))

    def test_overly_broad_allowed_with_explicit_flag(self) -> None:
        """Ensure 0.0.0.0/0 and ::/0 are permitted only when allow_global_internet=True."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["0.0.0.0/0", "::/0"],
            allow_global_internet=True,
        )
        self.assertEqual(len(enclosure.cidrs), 2)
        self.assertTrue(enclosure.allow_global_internet)

    def test_malformed_cidr_rejected(self) -> None:
        """Ensure syntactically invalid CIDRs raise SecurityValidationError."""
        with self.assertRaises(SecurityValidationError):
            ScopeEnclosure.from_strings(cidrs="not-a-cidr")

        with self.assertRaises(SecurityValidationError):
            ScopeEnclosure.from_strings(cidrs="192.168.1.500/24")

        with self.assertRaises(SecurityValidationError):
            ScopeEnclosure.from_strings(cidrs="192.168.1.0/33")

    def test_invalid_interface_rejected(self) -> None:
        """Ensure shell-injection payloads in interface names are rejected."""
        with self.assertRaises(SecurityValidationError):
            ScopeEnclosure.from_strings(
                cidrs="192.168.1.0/24",
                interfaces="eth0; rm -rf /",
            )

    def test_invalid_types_raise_error(self) -> None:
        """Ensure invalid field types raise appropriate exceptions."""
        with self.assertRaises(SecurityValidationError):
            ScopeEnclosure(cidrs=("not_a_network",))  # type: ignore

        with self.assertRaises(TypeError):
            ScopeEnclosure(cidrs=(), allow_loopback="yes")  # type: ignore

        with self.assertRaises(TypeError):
            ScopeEnclosure(cidrs=(), allow_global_internet="no")  # type: ignore


class TestScopeEnclosureBoundaryAndInclusion(unittest.TestCase):
    """Test suite for CIDR boundary containment, usable IPs, and dual-stack matching."""

    def setUp(self) -> None:
        self.scope = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.0/24", "10.50.0.0/16", "fd00:abcd::/64"],
            allow_loopback=False,
        )

    def test_ipv4_boundary_containment(self) -> None:
        """Test exact first, middle, last usable, network, and broadcast addresses for /24."""
        # Network address
        self.assertTrue(self.scope.is_authorized("192.168.1.0"))
        # First usable host
        self.assertTrue(self.scope.is_authorized("192.168.1.1"))
        # Arbitrary middle host
        self.assertTrue(self.scope.is_authorized("192.168.1.128"))
        # Last usable host
        self.assertTrue(self.scope.is_authorized("192.168.1.254"))
        # Broadcast address
        self.assertTrue(self.scope.is_authorized("192.168.1.255"))

    def test_ipv4_adjacent_denial(self) -> None:
        """Test adjacent out-of-scope IPv4 addresses evaluate to unauthorized."""
        self.assertFalse(self.scope.is_authorized("192.168.0.255"))
        self.assertFalse(self.scope.is_authorized("192.168.2.0"))
        self.assertFalse(self.scope.is_authorized("192.168.2.1"))
        self.assertFalse(self.scope.is_authorized("8.8.8.8"))

    def test_ipv4_ipaddress_objects(self) -> None:
        """Verify ipaddress.IPv4Address object targets evaluate identically to strings."""
        ip_in = ipaddress.ip_address("192.168.1.42")
        ip_out = ipaddress.ip_address("172.16.0.1")
        self.assertTrue(self.scope.is_authorized(ip_in))
        self.assertFalse(self.scope.is_authorized(ip_out))

    def test_ipv6_boundary_containment(self) -> None:
        """Test IPv6 subnet containment and adjacent out-of-scope addresses."""
        self.assertTrue(self.scope.is_authorized("fd00:abcd::1"))
        self.assertTrue(self.scope.is_authorized("fd00:abcd::ffff:ffff"))
        self.assertFalse(self.scope.is_authorized("fd00:abce::1"))
        self.assertFalse(self.scope.is_authorized("2001:4860:4860::8888"))

    def test_single_host_boundary(self) -> None:
        """Test single host /32 and /128 enclosure boundaries."""
        host_scope = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.50/32", "2001:db8::1/128"],
            allow_loopback=False,
        )
        self.assertTrue(host_scope.is_authorized("192.168.1.50"))
        self.assertFalse(host_scope.is_authorized("192.168.1.49"))
        self.assertFalse(host_scope.is_authorized("192.168.1.51"))

        self.assertTrue(host_scope.is_authorized("2001:db8::1"))
        self.assertFalse(host_scope.is_authorized("2001:db8::2"))

    def test_empty_scope_default_deny(self) -> None:
        """Verify empty scope enclosure defaults to deny all targets."""
        empty_scope = ScopeEnclosure.from_strings(cidrs=(), allow_loopback=False)
        self.assertFalse(empty_scope.is_authorized("192.168.1.1"))
        self.assertFalse(empty_scope.is_authorized("127.0.0.1"))
        self.assertFalse(empty_scope.is_authorized("::1"))

    def test_assert_authorized_raises_scope_violation_error(self) -> None:
        """Verify assert_authorized raises ScopeViolationError on unauthorized target."""
        # Allowed target does not raise
        self.scope.assert_authorized("192.168.1.1")

        # Disallowed target raises ScopeViolationError
        with self.assertRaises(ScopeViolationError) as ctx:
            self.scope.assert_authorized("1.1.1.1")
        self.assertIn("outside user-authorized network scope", str(ctx.exception))


class TestScopeEnclosureLoopbackAndHostnames(unittest.TestCase):
    """Test suite for loopback authorization and DNS resolution safety."""

    def test_loopback_allowed_by_default(self) -> None:
        """Verify loopback addresses 127.0.0.1 and ::1 are permitted by default."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertTrue(scope.is_authorized("127.0.0.1"))
        self.assertTrue(scope.is_authorized("127.0.0.2"))
        self.assertTrue(scope.is_authorized("::1"))
        self.assertTrue(scope.is_authorized("localhost"))
        self.assertTrue(scope.is_authorized("localhost.localdomain"))

    def test_loopback_prohibited_when_disabled(self) -> None:
        """Verify loopback addresses are denied when allow_loopback=False."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", allow_loopback=False)
        self.assertFalse(scope.is_authorized("127.0.0.1"))
        self.assertFalse(scope.is_authorized("::1"))
        self.assertFalse(scope.is_authorized("localhost"))

    def test_hostname_resolution_authorized(self) -> None:
        """Verify hostname resolving to in-scope IP evaluates to authorized."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        mock_resolver = lambda host: ["192.168.1.100"]

        self.assertTrue(scope.is_authorized("router.local", resolver=mock_resolver))
        scope.assert_authorized("router.local", resolver=mock_resolver)

    def test_hostname_resolution_out_of_scope(self) -> None:
        """Verify hostname resolving to out-of-scope IP evaluates to unauthorized."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        mock_resolver = lambda host: ["93.184.216.34"]

        self.assertFalse(scope.is_authorized("example.com", resolver=mock_resolver))
        with self.assertRaises(ScopeViolationError):
            scope.assert_authorized("example.com", resolver=mock_resolver)

    def test_hostname_dns_rebinding_mixed_ips(self) -> None:
        """Verify hostname resolving to multiple IPs where one is out-of-scope fails closed."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        # One IP inside scope, one outside scope
        mock_resolver = lambda host: ["192.168.1.10", "8.8.8.8"]

        self.assertFalse(scope.is_authorized("dual.local", resolver=mock_resolver))
        with self.assertRaises(ScopeViolationError):
            scope.assert_authorized("dual.local", resolver=mock_resolver)

    def test_hostname_resolution_empty_or_failed(self) -> None:
        """Verify hostname resolution failure or empty response fails closed."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertFalse(scope.is_authorized("nonexistent.invalid", resolver=lambda h: []))
        self.assertFalse(scope.is_authorized(""))

    @patch("socket.getaddrinfo")
    def test_hostname_default_socket_resolution_success(self, mock_getaddrinfo) -> None:
        """Verify default socket.getaddrinfo fallback resolves and authorizes target."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.55", 0))
        ]
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertTrue(scope.is_authorized("router.lan"))
        mock_getaddrinfo.assert_called_once_with("router.lan", None)

    @patch("socket.getaddrinfo")
    def test_hostname_default_socket_resolution_gaierror(self, mock_getaddrinfo) -> None:
        """Verify default socket.getaddrinfo socket.gaierror fails closed gracefully."""
        mock_getaddrinfo.side_effect = socket.gaierror(-2, "Name or service not known")
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertFalse(scope.is_authorized("unknown-node.lan"))


class TestScopeEnclosureInterfaces(unittest.TestCase):
    """Test suite for interface binding restrictions."""

    def test_interface_matching(self) -> None:
        """Verify target passes when interface is in authorized interfaces."""
        scope = ScopeEnclosure.from_strings(
            cidrs="192.168.1.0/24",
            interfaces=["eth0", "wlan0"],
        )
        self.assertTrue(scope.is_authorized("192.168.1.10", interface="eth0"))
        self.assertTrue(scope.is_authorized("192.168.1.10", interface="wlan0"))

    def test_interface_mismatch(self) -> None:
        """Verify target fails when interface is not in authorized interfaces."""
        scope = ScopeEnclosure.from_strings(
            cidrs="192.168.1.0/24",
            interfaces=["eth0"],
        )
        self.assertFalse(scope.is_authorized("192.168.1.10", interface="wlan0"))
        with self.assertRaises(ScopeViolationError) as ctx:
            scope.assert_authorized("192.168.1.10", interface="wlan0")
        self.assertIn("not in authorized interfaces", str(ctx.exception))


class TestScopeSerializationAndImmutability(unittest.TestCase):
    """Test suite for dictionary/JSON serialization and dataclass immutability."""

    def test_serialization_round_trip(self) -> None:
        """Verify to_dict and from_dict produce identical configurations."""
        original = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.0/24", "fd00:abcd::/64"],
            interfaces=["eth0", "wlan0"],
            allow_loopback=False,
            allow_global_internet=False,
        )
        serialized = original.to_dict()
        json_str = json.dumps(serialized)
        deserialized = ScopeEnclosure.from_dict(json.loads(json_str))

        self.assertEqual(original.cidrs, deserialized.cidrs)
        self.assertEqual(original.interfaces, deserialized.interfaces)
        self.assertEqual(original.allow_loopback, deserialized.allow_loopback)
        self.assertEqual(original.allow_global_internet, deserialized.allow_global_internet)

    def test_immutability(self) -> None:
        """Verify ScopeEnclosure is frozen against attribute modification."""
        scope = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        with self.assertRaises(FrozenInstanceError):
            scope.allow_loopback = False  # type: ignore


class TestScopeGuard(unittest.TestCase):
    """Test suite for runtime ScopeGuard lifecycle, assertion, and state changes."""

    def test_guard_inactive_by_default(self) -> None:
        """Verify uninitialized ScopeGuard permits all targets and is inactive."""
        guard = ScopeGuard()
        self.assertFalse(guard.is_active)
        self.assertIsNone(guard.enclosure)

        # Inactive guard does not raise
        self.assertTrue(guard.is_authorized("8.8.8.8"))
        guard.assert_authorized("8.8.8.8")

    def test_guard_activation_and_enforcement(self) -> None:
        """Verify activating guard enforces boundary assertions."""
        guard = ScopeGuard()
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", allow_loopback=False)
        guard.set_enclosure(enclosure)

        self.assertTrue(guard.is_active)
        self.assertEqual(guard.enclosure, enclosure)

        # Target in scope
        self.assertTrue(guard.is_authorized("192.168.1.10"))
        guard.assert_authorized("192.168.1.10")

        # Target out of scope
        self.assertFalse(guard.is_authorized("10.0.0.1"))
        with self.assertRaises(ScopeViolationError):
            guard.assert_authorized("10.0.0.1")

    def test_guard_clear_resets_to_inactive(self) -> None:
        """Verify clear resets guard to unconstrained inactive state."""
        guard = ScopeGuard()
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        guard.set_enclosure(enclosure)
        self.assertTrue(guard.is_active)

        guard.clear()
        self.assertFalse(guard.is_active)
        self.assertIsNone(guard.enclosure)
        self.assertTrue(guard.is_authorized("10.0.0.1"))

    def test_guard_invalid_enclosure_type(self) -> None:
        """Verify set_enclosure rejects objects that are not ScopeEnclosure instances."""
        guard = ScopeGuard()
        with self.assertRaises(TypeError):
            guard.set_enclosure("192.168.1.0/24")  # type: ignore


class TestApplicationScopeIntegration(unittest.TestCase):
    """Integration test suite for ScopeGuard integration inside Application controller."""

    def setUp(self) -> None:
        config = AppConfig(use_mock_network=True, database_file=":memory:")
        self.app = Application(config=config)

    def test_app_unconstrained_by_default(self) -> None:
        """Verify Application active operations succeed when scope is unconfigured."""
        self.assertIsNone(self.app.get_authorized_scope())
        res_lat = self.app.benchmark_latency("1.1.1.1", port=443, count=1)
        self.assertEqual(res_lat.target_host, "1.1.1.1")

        res_tls = self.app.inspect_tls("example.com", port=443)
        self.assertEqual(res_tls.target_host, "example.com")

    def test_app_scope_enforcement_latency(self) -> None:
        """Verify benchmark_latency adheres to authorized scope enclosure."""
        self.app.set_authorized_scope("192.168.1.0/24")
        self.assertIsNotNone(self.app.get_authorized_scope())

        # In-scope latency probe succeeds
        res_ok = self.app.benchmark_latency("192.168.1.25", port=443, count=1)
        self.assertEqual(res_ok.target_host, "192.168.1.25")

        # Out-of-scope latency probe raises ScopeViolationError
        with self.assertRaises(ScopeViolationError) as ctx:
            self.app.benchmark_latency("10.0.0.1", port=443, count=1)
        self.assertIn("outside user-authorized network scope", str(ctx.exception))

    def test_app_scope_enforcement_tls(self) -> None:
        """Verify inspect_tls adheres to authorized scope enclosure."""
        self.app.set_authorized_scope("192.168.1.0/24")

        # In-scope TLS probe succeeds
        res_ok = self.app.inspect_tls("192.168.1.50", port=443)
        self.assertEqual(res_ok.target_host, "192.168.1.50")

        # Out-of-scope TLS probe raises ScopeViolationError
        with self.assertRaises(ScopeViolationError) as ctx:
            self.app.inspect_tls("8.8.8.8", port=443)
        self.assertIn("outside user-authorized network scope", str(ctx.exception))

    def test_app_clear_authorized_scope(self) -> None:
        """Verify clearing scope re-enables unconstrained diagnostic queries."""
        self.app.set_authorized_scope("192.168.1.0/24")
        self.app.clear_authorized_scope()

        res = self.app.benchmark_latency("8.8.8.8", port=443, count=1)
        self.assertEqual(res.target_host, "8.8.8.8")


class TestCLIScopeIntegration(unittest.TestCase):
    """Integration test suite for CLI --scope and --scope-interface options."""

    def test_cli_scoped_latency_authorized(self) -> None:
        """Verify CLI latency benchmark succeeds when target is within --scope."""
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main([
                "--latency", "192.168.1.10",
                "--scope", "192.168.1.0/24",
                "--count", "1",
            ])
        self.assertEqual(code, 0)
        self.assertIn("192.168.1.10", stdout_buf.getvalue())

    def test_cli_scoped_latency_unauthorized_blocked(self) -> None:
        """Verify CLI latency benchmark is blocked with exit code 1 when outside --scope."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = main([
                "--latency", "10.0.0.1",
                "--scope", "192.168.1.0/24",
                "--count", "1",
            ])
        self.assertEqual(code, 1)
        self.assertIn("outside user-authorized network scope", stderr_buf.getvalue())

    def test_cli_invalid_scope_syntax(self) -> None:
        """Verify CLI exits with code 1 when --scope syntax is malformed."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = main([
                "--latency", "192.168.1.10",
                "--scope", "bad-cidr-format",
            ])
        self.assertEqual(code, 1)
        self.assertIn("Error:", stderr_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
