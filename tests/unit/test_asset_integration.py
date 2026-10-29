"""Unit tests for Phase 2 integration of vendor-neutral asset domain with network models.

Validates:
1. Conversion of interface data with and without MAC addresses.
2. Multiple IP addresses and dual-stack IPv4/IPv6 handling.
3. Repeated observations without duplicate asset creation.
4. Changing IP bindings while preserving stable asset identity.
5. Gateway configuration versus verified reachability.
6. DNS configuration versus verified reachability.
7. Evidence provenance preservation through adapters.
8. Verified facts versus inferred observations.
9. Conflicting observations and history retention.
10. Topology mapping without unsupported physical-link inference.
11. Compatibility with existing model constructors and provider return contracts.
12. Missing, malformed, or partial input handling.
13. Serialization and credential redaction at output boundaries.
14. Circular-import and package-import regression checks.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from typing import List

import pytest

from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    AssetIdentity,
    AttributeHistory,
    AttributeObservation,
    EntityStatus,
    IPBindingRecord,
    LogicalLink,
    NetworkAsset,
    PhysicalPort,
    RelationshipType,
    TelemetryCategory,
    build_discovery_asset_graph,
    from_host_interfaces,
    from_network_topology,
    to_network_topology,
)
from itsa_network_os.network.inspector import (
    HostNetworkProvider,
    MockNetworkProvider,
    NetworkInspector,
)
from itsa_network_os.network.models import (
    DNSServerInfo,
    EvidenceProtocol,
    EvidenceRecord,
    GatewayInfo,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)
from itsa_network_os.network.topology import (
    NetworkTopology,
    NodeStatus,
    TopologyDiscoveryEngine,
    TopologyLink,
    TopologyNode,
    TopologyNodeType,
)


# =============================================================================
# 1. Interface Conversion with and without MAC Addresses
# =============================================================================

def test_interface_conversion_with_mac_identifies_primary_mac():
    """Verify non-loopback interface MAC becomes primary MAC and assigns stable host identity."""
    lo = NetworkInterface(
        name="lo",
        mac_address="00:00:00:00:00:00",
        state=InterfaceState.UP,
        interface_type=InterfaceType.LOOPBACK,
        addresses=[IPAddressInfo("127.0.0.1", 8, "IPv4")],
    )
    eth0 = NetworkInterface(
        name="eth0",
        mac_address="00:11:22:33:44:55",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("192.168.1.10", 24, "IPv4")],
    )

    asset = from_host_interfaces([lo, eth0], host_system_name="station-1")

    assert asset.identity.primary_mac == "00:11:22:33:44:55"
    assert asset.identity.system_name == "station-1"
    assert "eth0" in asset.interfaces
    assert "lo" in asset.interfaces
    assert "port.eth0" in asset.ports
    assert asset.ports["port.eth0"].mac_address == "00:11:22:33:44:55"
    assert asset.ports["port.lo"].mac_address is None


def test_interface_conversion_without_mac_or_loopback_only():
    """Verify loopback or missing MAC records do not invent identity or vendor guesses."""
    lo = NetworkInterface(
        name="lo",
        mac_address="00:00:00:00:00:00",
        state=InterfaceState.UP,
        interface_type=InterfaceType.LOOPBACK,
        addresses=[IPAddressInfo("127.0.0.1", 8, "IPv4")],
    )
    tun0 = NetworkInterface(
        name="tun0",
        mac_address="",
        state=InterfaceState.UP,
        interface_type=InterfaceType.VIRTUAL,
        addresses=[IPAddressInfo("10.8.0.2", 24, "IPv4")],
    )

    asset = from_host_interfaces([lo, tun0], host_system_name="vpn-client")

    assert asset.identity.primary_mac is None
    assert asset.identity.vendor_guess is None
    assert asset.identity.model_guess is None
    # Stable UUID derived deterministically from hostname when no physical MAC is present
    expected_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, "host.vpn-client"))
    assert asset.id == expected_uuid


# =============================================================================
# 2. Multiple IP Addresses and IPv4/IPv6 Dual-Stack Handling
# =============================================================================

def test_multiple_ip_addresses_dual_stack_preservation():
    """Verify multiple IPv4 and IPv6 addresses across interfaces are bound without data loss."""
    eth0 = NetworkInterface(
        name="eth0",
        mac_address="52:54:00:12:34:56",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[
            IPAddressInfo(address="192.168.10.15", prefix_length=24, family="IPv4", scope="global"),
            IPAddressInfo(address="192.168.10.16", prefix_length=24, family="IPv4", scope="global"),
            IPAddressInfo(address="2001:db8::1015", prefix_length=64, family="IPv6", scope="global"),
            IPAddressInfo(address="fe80::5054:ff:fe12:3456", prefix_length=64, family="IPv6", scope="link"),
        ],
    )

    asset = from_host_interfaces([eth0], host_system_name="dual-stack-node")

    assert "192.168.10.15" in asset.management_ips
    assert "192.168.10.16" in asset.management_ips
    assert "2001:db8::1015" in asset.management_ips
    assert "fe80::5054:ff:fe12:3456" in asset.management_ips
    assert len(asset.ip_history) == 4

    # Verify IPv6 scope is preserved
    v6_link = next(b for b in asset.ip_history if b.ip_address == "fe80::5054:ff:fe12:3456")
    assert v6_link.scope == "link"
    assert v6_link.is_current is True


# =============================================================================
# 3. Repeated Observations Without Duplicate Asset Creation
# =============================================================================

def test_repeated_observations_no_duplicate_assets():
    """Verify sequential observations of the same host update the asset rather than duplicating."""
    eth0_initial = NetworkInterface(
        name="eth0",
        mac_address="aa:bb:cc:dd:ee:01",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("10.0.0.5", 24, "IPv4")],
    )

    asset1 = from_host_interfaces([eth0_initial], host_system_name="srv-db1")

    graph = AssetGraph()
    graph.add_asset(asset1)
    assert len(graph.assets) == 1

    # Second observation with an additional address
    eth0_updated = NetworkInterface(
        name="eth0",
        mac_address="aa:bb:cc:dd:ee:01",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[
            IPAddressInfo("10.0.0.5", 24, "IPv4"),
            IPAddressInfo("10.0.0.6", 24, "IPv4"),
        ],
    )
    asset2 = from_host_interfaces([eth0_updated], host_system_name="srv-db1")

    assert asset1.id == asset2.id
    graph.add_asset(asset2)
    # Still exactly one asset in graph
    assert len(graph.assets) == 1
    assert "10.0.0.6" in graph.get_asset(asset1.id).management_ips


# =============================================================================
# 4. Changing IP Bindings While Preserving Stable Asset Identity
# =============================================================================

def test_changing_ip_bindings_preserves_stable_identity():
    """Verify IP address migration (e.g. DHCP renewal) updates history while keeping asset identity."""
    eth0 = NetworkInterface(
        name="eth0",
        mac_address="aa:bb:cc:dd:ee:99",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("192.168.1.50", 24, "IPv4")],
    )
    asset = from_host_interfaces([eth0], host_system_name="workstation-dhcp")
    orig_uuid = asset.id

    assert "192.168.1.50" in asset.management_ips

    # IP reallocated: unbind old, bind new
    asset.unbind_ip("192.168.1.50")
    asset.bind_ip("192.168.1.75", interface_name="eth0")

    # Asset ID remains identical
    assert asset.id == orig_uuid
    assert "192.168.1.50" not in asset.management_ips
    assert "192.168.1.75" in asset.management_ips

    # Both bindings exist in timeline
    old_binding = next(b for b in asset.ip_history if b.ip_address == "192.168.1.50")
    new_binding = next(b for b in asset.ip_history if b.ip_address == "192.168.1.75")
    assert old_binding.is_current is False
    assert new_binding.is_current is True


# =============================================================================
# 5. Gateway Configuration versus Verified Reachability
# =============================================================================

def test_gateway_configuration_vs_reachability():
    """Verify configured gateways are captured as routing entries without claiming reachability."""
    gw_v4 = GatewayInfo(gateway="192.168.1.1", family="IPv4", metric=100, interface="eth0")
    gw_v6 = GatewayInfo(gateway="2001:db8::1", family="IPv6", metric=1024, interface="eth0")

    eth0 = NetworkInterface(
        name="eth0",
        mac_address="aa:bb:cc:00:11:22",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("192.168.1.100", 24, "IPv4")],
        gateways=[gw_v4, gw_v6],
    )

    asset = from_host_interfaces([eth0], host_system_name="gw-tester")

    # Recorded in attribute history under ROUTING_ENTRY
    v4_history = asset.attribute_histories.get("configured_gateway.ipv4.192.168.1.1")
    assert v4_history is not None
    obs = v4_history.observations[-1]
    assert obs.category == TelemetryCategory.ROUTING_ENTRY
    assert obs.evidence.is_verified_fact is True  # Verified kernel routing table entry
    v4_details = json.loads(obs.evidence.details)
    assert v4_details["verified_reachability"] is False  # Reachability NOT claimed
    assert v4_details["relationship"] == "CONFIGURED_GATEWAY"

    # Verify graph mapping does not assert physical wire link
    graph = build_discovery_asset_graph([eth0], gateways=[gw_v4, gw_v6])
    gw_links = [l for l in graph.links.values() if l.relationship_type == RelationshipType.CONFIGURED_GATEWAY]
    assert len(gw_links) == 2
    for link in gw_links:
        assert link.status == "CONFIGURED"
        link_details = json.loads(link.evidence.details)
        assert link_details["verified_reachability"] is False
        assert link_details["is_physical_link"] is False


# =============================================================================
# 6. DNS Configuration versus Verified Reachability
# =============================================================================

def test_dns_configuration_vs_reachability():
    """Verify DNS resolvers are recorded with provenance without claiming remote reachability."""
    dns1 = DNSServerInfo(address="1.1.1.1", scope="system", provenance="resolv.conf")
    dns2 = DNSServerInfo(address="192.168.1.1", scope="interface", interface="eth0", provenance="systemd-resolved")

    eth0 = NetworkInterface(
        name="eth0",
        mac_address="aa:bb:cc:00:11:33",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("192.168.1.100", 24, "IPv4")],
        dns_servers=[dns2],
    )

    asset = from_host_interfaces([eth0], host_system_name="dns-tester", dns_servers=[dns1])

    history1 = asset.attribute_histories.get("configured_dns.1.1.1.1")
    history2 = asset.attribute_histories.get("configured_dns.192.168.1.1")
    assert history1 is not None
    assert history2 is not None

    obs1 = history1.observations[-1]
    assert obs1.evidence.is_verified_fact is True
    dns1_details = json.loads(obs1.evidence.details)
    assert dns1_details["verified_reachability"] is False
    assert dns1_details["provenance"] == "resolv.conf"

    # Verify in discovery asset graph
    graph = build_discovery_asset_graph([eth0], dns_servers=[dns1, dns2])
    dns_links = [l for l in graph.links.values() if l.relationship_type == RelationshipType.CONFIGURED_DNS]
    assert len(dns_links) == 2
    for link in dns_links:
        assert link.status == "CONFIGURED"
        link_details = json.loads(link.evidence.details)
        assert link_details["verified_reachability"] is False
        assert link_details["is_physical_link"] is False


# =============================================================================
# 7. Evidence Provenance Preservation Through Adapters
# =============================================================================

def test_evidence_provenance_preservation():
    """Verify evidence attributes, protocol origin, and timestamps survive adapter transformations."""
    iface = NetworkInterface(
        name="eth0",
        mac_address="02:42:0a:00:00:01",
        state=InterfaceState.UP,
        interface_type=InterfaceType.ETHERNET,
        addresses=[IPAddressInfo("10.10.10.1", 24, "IPv4", scope="global", classification="unicast")],
    )

    asset = from_host_interfaces([iface], host_system_name="node-provenance")

    binding = asset.ip_history[0]
    assert binding.evidence is not None
    assert binding.evidence.source_protocol == EvidenceProtocol.KERNEL_RTNETLINK
    assert binding.evidence.confidence == 1.0
    assert binding.evidence.is_verified_fact is True
    details = json.loads(binding.evidence.details)
    assert details["interface"] == "eth0"
    assert details["prefix_length"] == 24


# =============================================================================
# 8. Verified Facts versus Inferred Observations
# =============================================================================

def test_verified_facts_vs_inferred_observations_conflict_precedence():
    """Verify verified factual evidence takes strict precedence over inferences in attribute resolution."""
    asset = NetworkAsset(
        identity=AssetIdentity(id=str(uuid.uuid4()), system_name="test-box"),
        category=AssetCategory.ROUTER,
    )

    # Inferred observation with high numeric confidence
    inferred_ev = EvidenceRecord(
        source_protocol=EvidenceProtocol.MNDP,
        timestamp="2026-10-28T12:00:00Z",
        confidence=0.95,
        is_verified_fact=False,
    )
    asset.record_observation(
        attribute="vendor",
        value="MikroTik-Inferred",
        evidence=inferred_ev,
    )

    # Verified fact with lower numeric confidence or earlier timestamp
    verified_ev = EvidenceRecord(
        source_protocol=EvidenceProtocol.TLS,
        timestamp="2026-10-28T11:00:00Z",
        confidence=0.80,
        is_verified_fact=True,
    )
    asset.record_observation(
        attribute="vendor",
        value="MikroTik-Verified",
        evidence=verified_ev,
    )

    # Resolved value MUST prioritize verified fact over inference
    assert asset.get_attribute("vendor") == "MikroTik-Verified"
    assert asset.has_attribute_conflict("vendor") is True


# =============================================================================
# 9. Conflicting Observations and History Retention with Complex Types
# =============================================================================

def test_conflicting_observations_with_dictionaries():
    """Verify conflict detection handles unhashable values (dictionaries/lists) without raising TypeError."""
    hist = AttributeHistory(attribute_name="gateway_config")

    ev1 = EvidenceRecord(source_protocol=EvidenceProtocol.KERNEL_RTNETLINK, timestamp="2026-10-28T12:00:00Z", confidence=1.0, is_verified_fact=True)
    obs1 = AttributeObservation(attribute="gateway_config", value={"gw": "192.168.1.1", "metric": 100}, evidence=ev1)

    ev2 = EvidenceRecord(source_protocol=EvidenceProtocol.KERNEL_RTNETLINK, timestamp="2026-10-28T12:05:00Z", confidence=1.0, is_verified_fact=True)
    obs2 = AttributeObservation(attribute="gateway_config", value={"gw": "192.168.1.254", "metric": 200}, evidence=ev2)

    hist.add_observation(obs1)
    assert hist.has_conflict is False
    assert hist.current_value == {"gw": "192.168.1.1", "metric": 100}

    hist.add_observation(obs2)
    assert hist.has_conflict is True
    assert len(hist.observations) == 2
    assert hist.current_value == {"gw": "192.168.1.254", "metric": 200}


# =============================================================================
# 10. Topology Mapping Without Unsupported Physical-Link Inference
# =============================================================================

def test_topology_mapping_bidirectional_and_no_unsupported_physical_links():
    """Verify NetworkTopology conversion preserves uncertainty, metrics, and round-trips cleanly."""
    default_topo = TopologyDiscoveryEngine.get_default_topology()

    graph = from_network_topology(default_topo)
    assert len(graph.assets) == len(default_topo.nodes)
    assert len(graph.links) == len(default_topo.links)

    # Verify links are marked as INFERRED, not verified physical
    for link in graph.links.values():
        assert "INFERRED" in link.relationship_type.value or link.relationship_type == RelationshipType.INFERRED_PORT_MAPPING
        assert link.bandwidth_mbps is not None

    # Verify bidirectional round-trip back to NetworkTopology
    recovered_topo = to_network_topology(graph)
    assert len(recovered_topo.nodes) == len(default_topo.nodes)
    assert len(recovered_topo.links) == len(default_topo.links)

    # Verify node IDs and link IDs remain aligned
    orig_node_ids = {n.id for n in default_topo.nodes}
    recovered_node_ids = {n.id for n in recovered_topo.nodes}
    assert orig_node_ids == recovered_node_ids

    orig_link_ids = {l.id for l in default_topo.links}
    recovered_link_ids = {l.id for l in recovered_topo.links}
    assert orig_link_ids == recovered_link_ids


def test_topology_discovery_engine_asset_graph():
    """Verify TopologyDiscoveryEngine.get_default_asset_graph() convenience method."""
    graph = TopologyDiscoveryEngine.get_default_asset_graph()
    assert isinstance(graph, AssetGraph)
    assert len(graph.assets) > 0
    assert len(graph.links) > 0


# =============================================================================
# 11. Compatibility With Existing Constructors and Provider Return Contracts
# =============================================================================

def test_inspector_backward_compatibility_and_asset_methods():
    """Verify NetworkInspector preserves all existing signatures, return types, and adds asset methods."""
    inspector = NetworkInspector(use_mock=True)

    # Existing methods preserve exact return types
    interfaces = inspector.list_interfaces()
    assert isinstance(interfaces, list)
    assert all(isinstance(i, NetworkInterface) for i in interfaces)

    gateways = inspector.get_default_gateways()
    assert isinstance(gateways, list)
    assert all(isinstance(g, GatewayInfo) for g in gateways)

    dns_servers = inspector.get_system_dns()
    assert isinstance(dns_servers, list)
    assert all(isinstance(d, DNSServerInfo) for d in dns_servers)

    # New Phase 2 asset integration methods
    host_asset = inspector.get_host_asset(host_system_name="mock-host")
    assert isinstance(host_asset, NetworkAsset)
    assert host_asset.identity.system_name == "mock-host"
    assert "eth0" in host_asset.interfaces

    graph = inspector.get_asset_graph(host_system_name="mock-host")
    assert isinstance(graph, AssetGraph)
    assert host_asset.id in graph.assets


# =============================================================================
# 12. Missing, Malformed, or Partial Input Handling
# =============================================================================

def test_empty_and_partial_interface_inputs():
    """Verify safe degradation when interface records are empty or missing fields."""
    # Empty interface list
    empty_asset = from_host_interfaces([], host_system_name="empty-box")
    assert empty_asset.status == EntityStatus.UNKNOWN
    assert len(empty_asset.interfaces) == 0
    assert len(empty_asset.ports) == 0

    # Interface with invalid/corrupt MAC and invalid IP
    malformed_iface = NetworkInterface(
        name="eth_bad",
        mac_address="NOT-A-VALID-MAC",
        state=InterfaceState.UNKNOWN,
        interface_type=InterfaceType.UNKNOWN,
        addresses=[
            IPAddressInfo(address="not-an-ip", prefix_length=24, family="IPv4"),
            IPAddressInfo(address="192.168.1.1", prefix_length=24, family="IPv4"),
        ],
    )

    asset = from_host_interfaces([malformed_iface], host_system_name="bad-iface-host")
    assert asset.identity.primary_mac is None  # Invalid MAC not used as primary
    assert "eth_bad" in asset.interfaces
    # Only valid IP was bound
    assert "192.168.1.1" in asset.management_ips
    assert len(asset.ip_history) == 1


# =============================================================================
# 13. Serialization and Credential Redaction at Output Boundaries
# =============================================================================

def test_asset_and_graph_serialization_with_redaction():
    """Verify JSON serialization and CredentialRedactor secret scrubbing at boundary."""
    asset = NetworkAsset(
        identity=AssetIdentity(id=str(uuid.uuid4()), system_name="secure-router"),
        category=AssetCategory.ROUTER,
        metadata={
            "admin_password": "supersecretpassword123",
            "api_key": "eyJhbGciOi...",
            "location": "Rack 4",
        },
    )

    data = asset.to_dict()

    # Secret keys must be scrubbed by CredentialRedactor
    assert data["metadata"]["admin_password"] == "***REDACTED***"
    assert data["metadata"]["api_key"] == "***REDACTED***"
    assert data["metadata"]["location"] == "Rack 4"

    # Must be valid, round-trip JSON serializable
    json_str = json.dumps(data)
    assert "supersecretpassword123" not in json_str

    # Graph serialization
    graph = AssetGraph()
    graph.add_asset(asset)
    graph_data = graph.to_dict()
    assert graph_data["assets"][asset.id]["metadata"]["admin_password"] == "***REDACTED***"


# =============================================================================
# 14. Circular Import and Package Import Regression Check
# =============================================================================

def test_isolated_clean_package_imports():
    """Verify that importing core and network subsystems does not trigger circular import errors."""
    code = (
        "import itsa_network_os.core;"
        "import itsa_network_os.core.assets;"
        "import itsa_network_os.network;"
        "import itsa_network_os.network.assets;"
        "import itsa_network_os.network.inspector;"
        "import itsa_network_os.network.topology;"
        "print('IMPORTS_SUCCESSFUL')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "IMPORTS_SUCCESSFUL" in result.stdout
