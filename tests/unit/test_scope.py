"""Unit tests for Authorized Network Scope Enclosure and Runtime Scope Guard (TASK-008 / REQ-DISC-002)."""

from __future__ import annotations

import io
import ipaddress
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import FrozenInstanceError
import socket
from unittest.mock import MagicMock, mock_open, patch

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.main import main
from itsa_network_os.network.dns import DNSDiagnostics
from itsa_network_os.network.latency import LatencyTester
from itsa_network_os.network.models import DNSServerInfo
from itsa_network_os.network.routes import RouteEntry
from itsa_network_os.network.scope import (
    ScopeEnclosure,
    ScopeGuard,
    ScopeViolationError,
    check_interface_route,
    get_interface_source_ip,
)
from itsa_network_os.security.tls import TLSInspectorEngine
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
        """Verify uninitialized ScopeGuard rejects active operations and fails closed."""
        guard = ScopeGuard()
        self.assertFalse(guard.is_active)
        self.assertFalse(guard.is_configured)
        self.assertIsNone(guard.enclosure)

        # Unconfigured guard fails closed
        self.assertFalse(guard.is_authorized("8.8.8.8"))
        with self.assertRaises(ScopeViolationError) as ctx:
            guard.assert_authorized("8.8.8.8")
        self.assertIn("No authorized network scope has been configured", str(ctx.exception))

    def test_guard_activation_and_enforcement(self) -> None:
        """Verify activating guard enforces boundary assertions."""
        guard = ScopeGuard()
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", allow_loopback=False)
        guard.set_enclosure(enclosure)

        self.assertTrue(guard.is_active)
        self.assertTrue(guard.is_configured)
        self.assertEqual(guard.enclosure, enclosure)

        # Target in scope
        self.assertTrue(guard.is_authorized("192.168.1.10"))
        guard.assert_authorized("192.168.1.10")

        # Target out of scope
        self.assertFalse(guard.is_authorized("10.0.0.1"))
        with self.assertRaises(ScopeViolationError):
            guard.assert_authorized("10.0.0.1")

    def test_guard_clear_resets_to_inactive(self) -> None:
        """Verify clear resets guard to default-deny empty enclosure."""
        guard = ScopeGuard()
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        guard.set_enclosure(enclosure)
        self.assertTrue(guard.is_active)

        guard.clear()
        self.assertFalse(guard.is_active)
        self.assertIsNotNone(guard.enclosure)
        self.assertEqual(guard.enclosure.cidrs, ())
        self.assertFalse(guard.is_authorized("10.0.0.1"))
        self.assertFalse(guard.is_authorized("192.168.1.10"))
        with self.assertRaises(ScopeViolationError):
            guard.assert_authorized("10.0.0.1")
        with self.assertRaises(ScopeViolationError):
            guard.assert_authorized("192.168.1.10")

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
        """Verify clearing scope resets enclosure to default-deny empty enclosure."""
        self.app.set_authorized_scope("192.168.1.0/24")
        self.assertIsNotNone(self.app.get_authorized_scope())
        self.assertEqual(len(self.app.get_authorized_scope().cidrs), 1)

        self.app.clear_authorized_scope()

        cleared_scope = self.app.get_authorized_scope()
        self.assertIsNotNone(cleared_scope)
        self.assertEqual(cleared_scope.cidrs, ())
        self.assertFalse(self.app.scope_guard.is_authorized("8.8.8.8"))
        with self.assertRaises(ScopeViolationError):
            self.app.scope_guard.assert_authorized("8.8.8.8")


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

    def test_cli_scope_interface_without_scope_rejected(self) -> None:
        """Verify CLI exits with code 1 if --scope-interface is specified without --scope."""
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            code = main([
                "--scope-interface", "eth0",
                "--latency", "127.0.0.1",
            ])
        self.assertEqual(code, 1)
        self.assertIn("Error: --scope-interface requires --scope to be specified", stderr_buf.getvalue())

    def test_cli_scoped_interface_authorized(self) -> None:
        """Verify CLI latency benchmark succeeds when scope and interface match."""
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            code = main([
                "--latency", "192.168.1.10",
                "--scope", "192.168.1.0/24",
                "--scope-interface", "eth0",
                "--count", "1",
            ])
        self.assertEqual(code, 0)
        self.assertIn("192.168.1.10", stdout_buf.getvalue())


class TestSupernetAndUnicastPolicy(unittest.TestCase):
    """Test suite for supernet restrictions and unicast target eligibility."""

    def test_ipv4_supernets_prohibited(self) -> None:
        """Verify IPv4 prefixes broader than RFC 1918 /8 (< 8) are rejected by default."""
        for cidr in ["0.0.0.0/0", "0.0.0.0/1", "10.0.0.0/7"]:
            with self.assertRaises(SecurityValidationError) as ctx:
                ScopeEnclosure.from_strings(cidrs=cidr)
            self.assertIn("Overly broad", str(ctx.exception))

    def test_ipv4_rfc1918_class_a_permitted(self) -> None:
        """Verify /8 (RFC 1918 Class A 10.0.0.0/8) is permitted."""
        enclosure = ScopeEnclosure.from_strings(cidrs="10.0.0.0/8")
        self.assertEqual(len(enclosure.cidrs), 1)
        self.assertEqual(enclosure.cidrs[0].prefixlen, 8)

    def test_ipv6_supernets_prohibited(self) -> None:
        """Verify IPv6 prefixes broader than ULA /7 (< 7) are rejected by default."""
        for cidr in ["::/0", "2000::/3", "fc00::/6"]:
            with self.assertRaises(SecurityValidationError) as ctx:
                ScopeEnclosure.from_strings(cidrs=cidr)
            self.assertIn("Overly broad", str(ctx.exception))

    def test_ipv6_ula_slash_7_permitted(self) -> None:
        """Verify IPv6 /7 (Unique Local Address fc00::/7) is permitted."""
        enclosure = ScopeEnclosure.from_strings(cidrs="fc00::/7")
        self.assertEqual(len(enclosure.cidrs), 1)
        self.assertEqual(enclosure.cidrs[0].prefixlen, 7)

    def test_supernets_allowed_with_global_flag(self) -> None:
        """Verify supernets are allowed when allow_global_internet=True."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["0.0.0.0/0", "::/0", "10.0.0.0/7", "2000::/3"],
            allow_global_internet=True,
        )
        self.assertEqual(len(enclosure.cidrs), 4)

    def test_unicast_eligibility_standard_subnet(self) -> None:
        """Verify network (.0) and broadcast (.255) addresses are ineligible for active unicast in /24."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertFalse(enclosure.is_active_unicast_target("192.168.1.0"))
        self.assertFalse(enclosure.is_active_unicast_target("192.168.1.255"))
        self.assertTrue(enclosure.is_active_unicast_target("192.168.1.1"))
        self.assertTrue(enclosure.is_active_unicast_target("192.168.1.254"))

        guard = ScopeGuard(enclosure)
        with self.assertRaises(ScopeViolationError) as ctx_net:
            guard.resolve_and_verify_target("192.168.1.0", check_unicast=True)
        self.assertIn("ineligible network/broadcast IP", str(ctx_net.exception))

        with self.assertRaises(ScopeViolationError) as ctx_bcast:
            guard.resolve_and_verify_target("192.168.1.255", check_unicast=True)
        self.assertIn("ineligible network/broadcast IP", str(ctx_bcast.exception))

        ip = guard.resolve_and_verify_target("192.168.1.1", check_unicast=True)
        self.assertEqual(ip, "192.168.1.1")

    def test_unicast_eligibility_rfc3021_slash31(self) -> None:
        """Verify RFC 3021 /31 point-to-point subnets permit both .0 and .1 as unicast targets."""
        enclosure = ScopeEnclosure.from_strings(cidrs="10.0.0.0/31")
        self.assertTrue(enclosure.is_active_unicast_target("10.0.0.0"))
        self.assertTrue(enclosure.is_active_unicast_target("10.0.0.1"))

        guard = ScopeGuard(enclosure)
        self.assertEqual(guard.resolve_and_verify_target("10.0.0.0", check_unicast=True), "10.0.0.0")
        self.assertEqual(guard.resolve_and_verify_target("10.0.0.1", check_unicast=True), "10.0.0.1")

    def test_unicast_eligibility_slash32(self) -> None:
        """Verify /32 host subnets permit the host address as unicast target."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.50/32")
        self.assertTrue(enclosure.is_active_unicast_target("192.168.1.50"))

        guard = ScopeGuard(enclosure)
        self.assertEqual(guard.resolve_and_verify_target("192.168.1.50", check_unicast=True), "192.168.1.50")


class TestIPv4MappedIPv6ScopeEnforcement(unittest.TestCase):
    """Test suite for IPv4-mapped IPv6 address unwrapping and policy evaluation."""

    def test_ipv4_mapped_ipv6_authorized(self) -> None:
        """Verify ::ffff:192.168.1.10 is evaluated against IPv4 CIDRs."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertTrue(enclosure.is_authorized("::ffff:192.168.1.10"))
        guard = ScopeGuard(enclosure)
        self.assertEqual(
            guard.resolve_and_verify_target("::ffff:192.168.1.10"),
            "::ffff:192.168.1.10",
        )

    def test_ipv4_mapped_ipv6_unauthorized(self) -> None:
        """Verify ::ffff:8.8.8.8 fails closed when outside IPv4 CIDR scope."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        self.assertFalse(enclosure.is_authorized("::ffff:8.8.8.8"))
        with self.assertRaises(ScopeViolationError):
            enclosure.assert_authorized("::ffff:8.8.8.8")


class TestInterfaceMandatoryEnforcementAndSourceBinding(unittest.TestCase):
    """Test suite for interface binding attribution, enforcement, and source IP resolution."""

    def test_missing_interface_when_restricted_fails_closed(self) -> None:
        """Verify omitting interface when scope specifies interfaces raises ScopeViolationError."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0", "wlan0"])
        self.assertFalse(enclosure.is_authorized("192.168.1.10", interface=None))
        with self.assertRaises(ScopeViolationError) as ctx:
            enclosure.assert_authorized("192.168.1.10", interface=None)
        self.assertIn("requested without interface attribution", str(ctx.exception))

    def test_mismatched_interface_fails_closed(self) -> None:
        """Verify requesting unauthorized interface fails closed."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0"])
        self.assertFalse(enclosure.is_authorized("192.168.1.10", interface="wlan0"))
        with self.assertRaises(ScopeViolationError) as ctx:
            enclosure.assert_authorized("192.168.1.10", interface="wlan0")
        self.assertIn("not in authorized interfaces", str(ctx.exception))

    def test_authorized_interface_succeeds(self) -> None:
        """Verify matching interface passes authorization."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0"])
        self.assertTrue(enclosure.is_authorized("192.168.1.10", interface="eth0"))
        enclosure.assert_authorized("192.168.1.10", interface="eth0")

    @patch("itsa_network_os.network.inspector.HostNetworkProvider.get_interfaces")
    def test_get_interface_source_ip_resolution(self, mock_get_ifaces) -> None:
        """Verify get_interface_source_ip resolves local IP matching target address family."""
        from itsa_network_os.network.models import (
            IPAddressInfo,
            InterfaceState,
            InterfaceType,
            NetworkInterface,
        )

        mock_get_ifaces.return_value = [
            NetworkInterface(
                name="eth0",
                mac_address="00:11:22:33:44:55",
                state=InterfaceState.UP,
                interface_type=InterfaceType.ETHERNET,
                addresses=[
                    IPAddressInfo(address="192.168.1.42", prefix_length=24, family="IPv4"),
                    IPAddressInfo(address="fd00::42", prefix_length=64, family="IPv6"),
                ],
            ),
            NetworkInterface(
                name="wlan0",
                mac_address="00:11:22:33:44:66",
                state=InterfaceState.UP,
                interface_type=InterfaceType.WIRELESS,
                addresses=[],
            ),
        ]

        # Matching IPv4
        ip = get_interface_source_ip("eth0", "192.168.1.1")
        self.assertEqual(ip, "192.168.1.42")

        # Matching IPv6
        ip6 = get_interface_source_ip("eth0", "fd00::1")
        self.assertEqual(ip6, "fd00::42")

        # Nonexistent interface
        self.assertIsNone(get_interface_source_ip("eth99", "192.168.1.1"))

        # Interface without IP of requested family
        self.assertIsNone(get_interface_source_ip("wlan0", "192.168.1.1"))


class TestEngineLevelBypassPrevention(unittest.TestCase):
    """Test suite verifying active engines fail closed if invoked directly without ScopeGuard."""

    def test_latency_tester_direct_live_fails_closed_without_scope(self) -> None:
        """Direct invocation of LatencyTester in live mode without scope raises ScopeViolationError."""
        with self.assertRaises(ScopeViolationError):
            LatencyTester.benchmark("192.168.1.1", use_mock=False)

    def test_tls_inspector_direct_live_fails_closed_without_scope(self) -> None:
        """Direct invocation of TLSInspectorEngine in live mode without scope raises ScopeViolationError."""
        with self.assertRaises(ScopeViolationError):
            TLSInspectorEngine.inspect("192.168.1.1", use_mock=False)

    def test_dns_diagnostics_direct_live_fails_closed_without_scope(self) -> None:
        """Direct invocation of DNSDiagnostics in live mode without scope raises ScopeViolationError."""
        with self.assertRaises(ScopeViolationError):
            DNSDiagnostics.query("192.168.1.1", use_mock=False)

    @patch("socket.create_connection")
    def test_latency_tester_blocks_socket_creation_for_unauthorized_target(self, mock_connect) -> None:
        """Verify socket.create_connection is never called when target is out of scope."""
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError):
            LatencyTester.benchmark("10.0.0.1", use_mock=False, scope_guard=guard)
        mock_connect.assert_not_called()

    @patch("socket.socket")
    def test_tls_inspector_blocks_socket_creation_for_unauthorized_target(self, mock_sock_cls) -> None:
        """Verify raw socket connection is never attempted when target is out of scope."""
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError):
            TLSInspectorEngine.inspect("10.0.0.1", use_mock=False, scope_guard=guard)
        mock_sock_cls.assert_not_called()

    @patch("socket.create_connection")
    @patch("itsa_network_os.network.latency.get_interface_source_ip")
    @patch("itsa_network_os.network.routes.RouteParser.get_routes")
    def test_latency_tester_interface_binding_source_address(self, mock_routes, mock_source_ip, mock_connect) -> None:
        """Verify LatencyTester binds to interface source address in live mode."""
        from itsa_network_os.network.routes import RouteEntry
        mock_routes.return_value = [
            RouteEntry(destination="192.168.1.0", gateway="on-link", netmask="255.255.255.0", interface="eth0", metric=100, flags="U", family="IPv4")
        ]
        mock_source_ip.return_value = "192.168.1.100"
        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock

        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0"])
        guard = ScopeGuard(enclosure)

        result = LatencyTester.benchmark(
            "192.168.1.50",
            port=443,
            count=1,
            use_mock=False,
            interface="eth0",
            scope_guard=guard,
        )
        self.assertEqual(result.target_host, "192.168.1.50")
        mock_connect.assert_called_once_with(
            ("192.168.1.50", 443),
            timeout=2.0,
            source_address=("192.168.1.100", 0),
        )

    @patch("itsa_network_os.network.latency.get_interface_source_ip")
    @patch("itsa_network_os.network.routes.RouteParser.get_routes")
    def test_latency_tester_fails_closed_when_interface_unbound(self, mock_routes, mock_source_ip) -> None:
        """Verify LatencyTester raises ScopeViolationError if interface IP cannot be resolved."""
        from itsa_network_os.network.routes import RouteEntry
        mock_routes.return_value = [
            RouteEntry(destination="192.168.1.0", gateway="on-link", netmask="255.255.255.0", interface="eth0", metric=100, flags="U", family="IPv4")
        ]
        mock_source_ip.return_value = None
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0"])
        guard = ScopeGuard(enclosure)

        with self.assertRaises(ScopeViolationError) as ctx:
            LatencyTester.benchmark(
                "192.168.1.50",
                port=443,
                count=1,
                use_mock=False,
                interface="eth0",
                scope_guard=guard,
            )
        self.assertIn("Cannot guarantee binding to authorized interface", str(ctx.exception))

    @patch("itsa_network_os.network.routes.RouteParser.get_routes")
    def test_latency_tester_fails_closed_when_route_mismatches_interface(self, mock_routes) -> None:
        """Verify LatencyTester fails closed when kernel route directs to a different interface."""
        from itsa_network_os.network.routes import RouteEntry
        mock_routes.return_value = [
            RouteEntry(destination="192.168.1.0", gateway="on-link", netmask="255.255.255.0", interface="wlan0", metric=100, flags="U", family="IPv4")
        ]
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24", interfaces=["eth0"])
        guard = ScopeGuard(enclosure)
        with self.assertRaises(ScopeViolationError) as ctx:
            LatencyTester.benchmark(
                "192.168.1.50",
                port=443,
                count=1,
                use_mock=False,
                interface="eth0",
                scope_guard=guard,
            )
        self.assertIn("which does not match requested interface constraint 'eth0'", str(ctx.exception))


class TestLiveDNSDiagnosticsAuthorization(unittest.TestCase):
    """Test suite verifying live DNS diagnostics enforce scope on resolvers and targets."""

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_live_dns_rejects_out_of_scope_resolver(self, mock_resolvers) -> None:
        """Live DNS query fails closed if system resolver in /etc/resolv.conf is out of scope."""
        from itsa_network_os.network.dns import DNSServerInfo
        mock_resolvers.return_value = [DNSServerInfo(address="1.1.1.1", scope="system")]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard)
        self.assertIn("DNS resolver '1.1.1.1' is outside authorized network scope", str(ctx.exception))

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_live_dns_rejects_out_of_scope_target_ip(self, mock_resolvers) -> None:
        """Live DNS query fails closed if target IP is out of scope."""
        from itsa_network_os.network.dns import DNSServerInfo
        mock_resolvers.return_value = [DNSServerInfo(address="192.168.1.1", scope="system")]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("8.8.8.8", use_mock=False, scope_guard=guard)
        self.assertIn("outside user-authorized network scope", str(ctx.exception))


class TestResolutionToConnectionIntegrity(unittest.TestCase):
    """Test suite for single-resolution and DNS-rebinding prevention."""

    def test_multiple_dns_records_fail_closed_if_any_out_of_scope(self) -> None:
        """Hostname resolving to multiple addresses where at least one is unauthorized raises ScopeViolationError."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        mock_resolver = lambda host: ["192.168.1.10", "8.8.8.8"]
        with self.assertRaises(ScopeViolationError) as ctx:
            enclosure.resolve_and_verify("dual.domain.local", resolver=mock_resolver)
        self.assertIn("8.8.8.8", str(ctx.exception))
        self.assertIn("outside user-authorized network scope", str(ctx.exception))

    def test_resolve_and_verify_returns_first_validated_ip(self) -> None:
        """Hostname resolving to valid in-scope IPs returns the validated IP string."""
        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        mock_resolver = lambda host: ["192.168.1.10", "192.168.1.20"]
        ip = enclosure.resolve_and_verify("internal.lan", resolver=mock_resolver)
        self.assertEqual(ip, "192.168.1.10")

    @patch("socket.create_connection")
    def test_latency_tester_connects_strictly_to_validated_ip(self, mock_connect) -> None:
        """Verify LatencyTester socket connects directly to validated IP, not hostname string."""
        mock_sock = MagicMock()
        mock_connect.return_value = mock_sock

        enclosure = ScopeEnclosure.from_strings(cidrs="192.168.1.0/24")
        guard = ScopeGuard(enclosure)

        with patch("socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.77", 0))
            ]
            result = LatencyTester.benchmark(
                "myrouter.local",
                port=443,
                count=1,
                use_mock=False,
                scope_guard=guard,
            )
            self.assertEqual(result.target_host, "myrouter.local")
            mock_connect.assert_called_once_with(
                ("192.168.1.77", 443),
                timeout=2.0,
                source_address=None,
            )


class TestPassiveAndOfflineUnconstrainedOperations(unittest.TestCase):
    """Test suite verifying passive and offline local operations remain unhindered without scope."""

    def setUp(self) -> None:
        config = AppConfig(use_mock_network=True, database_file=":memory:")
        self.app = Application(config=config)

    def test_passive_interfaces_unhindered(self) -> None:
        """get_network_interfaces runs without requiring configured scope."""
        ifaces = self.app.get_network_interfaces()
        self.assertGreaterEqual(len(ifaces), 1)

    def test_passive_subnet_calculation_unhindered(self) -> None:
        """calculate_subnet runs without requiring configured scope."""
        res = self.app.calculate_subnet("192.168.1.0/24")
        self.assertEqual(res.usable_hosts, 254)

    def test_passive_health_check_unhindered(self) -> None:
        """check_health runs without requiring configured scope."""
        report = self.app.check_health()
        self.assertIsNotNone(report.status)

    def test_passive_routing_table_unhindered(self) -> None:
        """get_routing_table runs without requiring configured scope."""
        routes = self.app.get_routing_table()
        self.assertGreaterEqual(len(routes), 1)

    def test_passive_packet_lab_unhindered(self) -> None:
        """get_packet_lab_trace runs without requiring configured scope."""
        packets = self.app.get_packet_lab_trace()
        self.assertGreaterEqual(len(packets), 1)


class TestTASK008FinalSecurityCorrections(unittest.TestCase):
    """Regression test suite for TASK-008 Final Security Corrections.

    Covers:
    1. Direct live invocation with a hostname and no scope guard.
    2. Direct live invocation with a configured guard and an unauthorized hostname.
    3. A hostname whose resolution includes both authorized and unauthorized addresses.
    4. Proof that unauthorized requests trigger no forbidden DNS/socket operation before rejection.
    5. A permitted hostname in a controlled, mocked environment.
    6. Existing IP-target authorization behavior.
    7. Mock-mode compatibility without live network access.
    8. Deterministic preflight route check for interface egress.
    9. Local loopback stub resolvers and upstream resolver validation.
    """

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_live_hostname_no_scope_guard_fails_closed(self, mock_resolvers) -> None:
        """Requirement 2.1: Direct live invocation with a hostname and no scope guard fails closed."""
        mock_resolvers.return_value = ["127.0.0.1"]
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("example.com", use_mock=False, scope_guard=None)
        self.assertIn("No authorized network scope has been configured", str(ctx.exception))

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_live_hostname_unauthorized_fails_closed(self, mock_resolvers) -> None:
        """Requirement 2.2: Direct live invocation with a configured guard and unauthorized hostname fails closed."""
        mock_resolvers.return_value = ["192.168.1.1"]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        mock_resolver = lambda h: ["93.184.216.34"]
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("example.com", use_mock=False, scope_guard=guard, resolver=mock_resolver)
        self.assertIn("outside user-authorized network scope", str(ctx.exception))

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_live_hostname_mixed_resolution_fails_closed(self, mock_resolvers) -> None:
        """Requirement 2.3: Hostname resolving to both authorized and unauthorized addresses fails closed."""
        mock_resolvers.return_value = ["192.168.1.1"]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        mock_resolver = lambda h: ["192.168.1.10", "8.8.8.8"]
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("dual.local", use_mock=False, scope_guard=guard, resolver=mock_resolver)
        self.assertIn("outside user-authorized network scope", str(ctx.exception))

    @patch("socket.getaddrinfo")
    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_unauthorized_requests_trigger_no_socket_operations(self, mock_resolvers, mock_gai) -> None:
        """Requirement 2.4: Proof that unauthorized requests trigger no forbidden DNS/socket operations before rejection."""
        mock_resolvers.return_value = ["192.168.1.1"]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))

        # Case A: Live query with unconfigured guard
        with self.assertRaises(ScopeViolationError):
            DNSDiagnostics.query("example.com", use_mock=False, scope_guard=ScopeGuard())
        mock_gai.assert_not_called()

        # Case B: Live query targeting unauthorized IP
        with self.assertRaises(ScopeViolationError):
            DNSDiagnostics.query("8.8.8.8", use_mock=False, scope_guard=guard)
        mock_gai.assert_not_called()

        # Case C: Live query with unauthorized resolver
        mock_resolvers.return_value = ["1.1.1.1"]
        with self.assertRaises(ScopeViolationError):
            DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard)
        mock_gai.assert_not_called()

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    def test_permitted_hostname_controlled_environment(self, mock_resolvers) -> None:
        """Requirement 2.5: Permitted hostname succeeds in controlled mock environment without network."""
        mock_resolvers.return_value = ["192.168.1.1"]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        mock_resolver = lambda h: ["192.168.1.50"]
        result = DNSDiagnostics.query("router.local", use_mock=False, scope_guard=guard, resolver=mock_resolver)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.target_host, "router.local")
        self.assertEqual(len(result.records), 1)
        self.assertEqual(result.records[0].value, "192.168.1.50")

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    @patch("socket.getaddrinfo")
    def test_existing_ip_target_authorization_behavior(self, mock_gai, mock_resolvers) -> None:
        """Requirement 2.6: Existing IP target authorization behavior is preserved."""
        mock_resolvers.return_value = ["192.168.1.1"]
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))
        ]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))

        # In-scope IP succeeds
        res = DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard)
        self.assertEqual(res.status, "SUCCESS")

        # Out-of-scope IP fails closed
        with self.assertRaises(ScopeViolationError):
            DNSDiagnostics.query("10.0.0.1", use_mock=False, scope_guard=guard)

    def test_mock_mode_compatibility_without_live_network(self) -> None:
        """Requirement 2.7: Mock mode compatibility without live network access or scope guard."""
        res = DNSDiagnostics.query("anyhost.example.com", use_mock=True)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.records), 0)

    def test_check_interface_route_matching_interface_succeeds(self) -> None:
        """Requirement 3.1: Preflight route check succeeds when kernel route points to requested interface."""
        routes = [
            RouteEntry(destination="192.168.1.0", gateway="on-link", netmask="255.255.255.0", interface="eth0", metric=100, flags="U", family="IPv4"),
            RouteEntry(destination="default", gateway="10.0.0.1", netmask="0.0.0.0", interface="wlan0", metric=600, flags="UG", family="IPv4"),
        ]
        # 192.168.1.50 matches eth0 subnet route
        check_interface_route("eth0", "192.168.1.50", routes=routes)

    def test_check_interface_route_mismatched_interface_fails_closed(self) -> None:
        """Requirement 3.2: Preflight route check fails closed when kernel route directs to different interface."""
        routes = [
            RouteEntry(destination="192.168.1.0", gateway="on-link", netmask="255.255.255.0", interface="eth0", metric=100, flags="U", family="IPv4"),
        ]
        with self.assertRaises(ScopeViolationError) as ctx:
            check_interface_route("wlan0", "192.168.1.50", routes=routes)
        self.assertIn("which does not match requested interface constraint 'wlan0'", str(ctx.exception))

    def test_check_interface_route_longest_prefix_match(self) -> None:
        """Requirement 3.3: Preflight route check honors longest prefix match over default route."""
        routes = [
            RouteEntry(destination="default", gateway="10.0.0.1", netmask="0.0.0.0", interface="eth0", metric=100, flags="UG", family="IPv4"),
            RouteEntry(destination="10.20.0.0", gateway="on-link", netmask="255.255.0.0", interface="eth1", metric=200, flags="U", family="IPv4"),
        ]
        # Target 10.20.1.5 matches /16 on eth1 (longer prefix than /0 default on eth0)
        check_interface_route("eth1", "10.20.1.5", routes=routes)
        # Requesting eth0 for 10.20.1.5 must fail closed
        with self.assertRaises(ScopeViolationError):
            check_interface_route("eth0", "10.20.1.5", routes=routes)

    def test_check_interface_route_metric_tie_breaking(self) -> None:
        """Requirement 3.4: Preflight route check honors lower metric when prefix lengths are identical."""
        routes = [
            RouteEntry(destination="default", gateway="192.168.1.1", netmask="0.0.0.0", interface="eth0", metric=100, flags="UG", family="IPv4"),
            RouteEntry(destination="default", gateway="192.168.2.1", netmask="0.0.0.0", interface="wlan0", metric=600, flags="UG", family="IPv4"),
        ]
        # eth0 has lower metric (100 < 600)
        check_interface_route("eth0", "8.8.8.8", routes=routes)
        with self.assertRaises(ScopeViolationError):
            check_interface_route("wlan0", "8.8.8.8", routes=routes)

    def test_check_interface_route_ipv6_support(self) -> None:
        """Requirement 3.5: Preflight route check supports IPv6 routes and prefix matching."""
        routes = [
            RouteEntry(destination="2001:db8::/32", gateway="on-link", netmask="::/32", interface="eth0", metric=256, flags="U", family="IPv6"),
            RouteEntry(destination="default", gateway="fe80::1", netmask="::/0", interface="wlan0", metric=1024, flags="UG", family="IPv6"),
        ]
        check_interface_route("eth0", "2001:db8::1", routes=routes)
        with self.assertRaises(ScopeViolationError):
            check_interface_route("wlan0", "2001:db8::1", routes=routes)

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_interface_dns_servers")
    def test_loopback_stub_with_unauthorized_upstream_fails_closed(self, mock_iface_dns, mock_resolvers) -> None:
        """Requirement 4.1: Loopback stub resolver (127.0.0.53) with unauthorized upstream fails closed."""
        mock_resolvers.return_value = ["127.0.0.53"]
        mock_iface_dns.return_value = {
            "eth0": [DNSServerInfo(address="8.8.8.8", scope="interface", interface="eth0")]
        }
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard)
        self.assertIn("Discovered upstream DNS resolver '8.8.8.8'", str(ctx.exception))

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_interface_dns_servers")
    @patch("socket.getaddrinfo")
    def test_loopback_stub_with_authorized_upstream_succeeds(self, mock_gai, mock_iface_dns, mock_resolvers) -> None:
        """Requirement 4.2: Loopback stub resolver with authorized upstream resolver succeeds."""
        mock_resolvers.return_value = ["127.0.0.53"]
        mock_iface_dns.return_value = {
            "eth0": [DNSServerInfo(address="192.168.1.1", scope="interface", interface="eth0")]
        }
        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))
        ]
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        result = DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard)
        self.assertEqual(result.status, "SUCCESS")

    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_system_resolvers")
    @patch("itsa_network_os.network.dns.DNSDiagnostics.get_interface_dns_servers")
    def test_loopback_stub_strict_egress_fails_closed_when_upstream_unknown(self, mock_iface_dns, mock_resolvers) -> None:
        """Requirement 4.3: Strict DNS egress mode fails closed if local stub is used but upstream cannot be discovered."""
        mock_resolvers.return_value = ["127.0.0.53"]
        mock_iface_dns.return_value = {}  # No upstream servers found
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs="192.168.1.0/24"))
        with self.assertRaises(ScopeViolationError) as ctx:
            DNSDiagnostics.query("192.168.1.50", use_mock=False, scope_guard=guard, strict_dns_egress=True)
        self.assertIn("Strict DNS egress confinement cannot be guaranteed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

