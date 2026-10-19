"""Integration tests for HostNetworkProvider and NetworkInspector against real Linux host environment.

Safety constraints:
- Strictly read-only execution under unprivileged user permissions (non-root).
- Never assumes specific hardware interface names (e.g. eth0, wlo1).
- Never assumes external Internet access, physical Wi-Fi hardware, or specific IP assignments.
- Validates model invariants, dataclass types, and JSON serialization.
"""

from __future__ import annotations

import json
import unittest

from itsa_network_os.network.inspector import HostNetworkProvider, NetworkInspector
from itsa_network_os.network.models import (
    DNSServerInfo,
    GatewayInfo,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)


class TestHostProviderLiveIntegration(unittest.TestCase):
    """Live host integration tests executed against actual Linux kernel APIs."""

    def test_live_host_provider_structural_integrity(self) -> None:
        """Verify HostNetworkProvider.get_interfaces() executes unprivileged and returns valid models."""
        provider = HostNetworkProvider()
        interfaces = provider.get_interfaces()

        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0, "Host discovery must return at least one interface.")

        # On any Linux host, loopback 'lo' is guaranteed to exist
        lo = next((i for i in interfaces if i.name == "lo"), None)
        self.assertIsNotNone(lo, "Loopback interface 'lo' must be discovered on Linux host.")
        assert lo is not None

        self.assertEqual(lo.interface_type, InterfaceType.LOOPBACK)
        self.assertEqual(lo.name, "lo")

        # Verify all discovered interfaces conform to strict schema invariants
        for iface in interfaces:
            self.assertIsInstance(iface, NetworkInterface)
            self.assertIsInstance(iface.name, str)
            self.assertTrue(len(iface.name) > 0)
            self.assertIsInstance(iface.mac_address, str)
            self.assertIsInstance(iface.state, InterfaceState)
            self.assertIsInstance(iface.interface_type, InterfaceType)
            self.assertIsInstance(iface.mtu, int)
            self.assertGreater(iface.mtu, 0)

            # Addresses invariants
            self.assertIsInstance(iface.addresses, list)
            for addr in iface.addresses:
                self.assertIsInstance(addr, IPAddressInfo)
                self.assertIn(addr.family, ("IPv4", "IPv6"))
                self.assertGreater(addr.prefix_length, 0)
                self.assertLessEqual(addr.prefix_length, 128)
                self.assertIsInstance(addr.address, str)
                self.assertIsNotNone(addr.classification)
                self.assertIn(
                    addr.classification,
                    ("loopback", "private", "link-local", "unique-local", "global-unicast", "site-local", "multicast", "reserved", "unspecified"),
                )
                self.assertIsNotNone(addr.scope)
                self.assertIn(addr.scope, ("global", "link", "host", "site", "unknown"))

            # Gateways invariants
            self.assertIsInstance(iface.gateways, list)
            for gw in iface.gateways:
                self.assertIsInstance(gw, GatewayInfo)
                self.assertIn(gw.family, ("IPv4", "IPv6"))
                self.assertIsInstance(gw.gateway, str)
                self.assertEqual(gw.interface, iface.name)
                if gw.metric is not None:
                    self.assertIsInstance(gw.metric, int)
                    self.assertGreaterEqual(gw.metric, 0)

            # DNS servers invariants
            self.assertIsInstance(iface.dns_servers, list)
            for dns in iface.dns_servers:
                self.assertIsInstance(dns, DNSServerInfo)
                self.assertIsInstance(dns.address, str)
                self.assertIn(dns.scope, ("interface", "system"))
                if dns.scope == "interface":
                    self.assertEqual(dns.interface, iface.name)
                else:
                    self.assertIsNone(dns.interface)

    def test_live_interface_serialization_roundtrip(self) -> None:
        """Verify that every discovered interface converts to dictionary and serializes to JSON cleanly."""
        provider = HostNetworkProvider()
        interfaces = provider.get_interfaces()

        for iface in interfaces:
            d = iface.to_dict()
            self.assertIsInstance(d, dict)
            self.assertEqual(d["name"], iface.name)
            self.assertEqual(d["state"], iface.state.value)
            self.assertEqual(d["interface_type"], iface.interface_type.value)
            self.assertIsInstance(d["gateways"], list)
            self.assertIsInstance(d["dns_servers"], list)

            # Ensure JSON serializable without circular references or non-primitive types
            json_str = json.dumps(d)
            self.assertIsInstance(json_str, str)
            deserialized = json.loads(json_str)
            self.assertEqual(deserialized["name"], iface.name)

    def test_live_network_inspector_orchestration(self) -> None:
        """Verify high-level NetworkInspector operates cleanly in live mode."""
        inspector = NetworkInspector(use_mock=False)
        self.assertIsInstance(inspector.provider, HostNetworkProvider)

        # list_interfaces
        interfaces = inspector.list_interfaces()
        self.assertGreater(len(interfaces), 0)

        # get_system_dns
        system_dns = inspector.get_system_dns()
        self.assertIsInstance(system_dns, list)
        for s in system_dns:
            self.assertIsInstance(s, DNSServerInfo)
            self.assertEqual(s.scope, "system")
            self.assertIsNone(s.interface)

        # get_default_gateways
        gateways = inspector.get_default_gateways()
        self.assertIsInstance(gateways, list)
        for g in gateways:
            self.assertIsInstance(g, GatewayInfo)
            self.assertIn(g.family, ("IPv4", "IPv6"))


if __name__ == "__main__":
    unittest.main()
