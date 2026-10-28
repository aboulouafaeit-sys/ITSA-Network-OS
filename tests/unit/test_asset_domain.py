"""Unit tests for the unified asset domain model, property graph, and compatibility adapters."""

import datetime
import math
import uuid
from typing import Any, Dict

import pytest

from itsa_network_os.core.assets import (
    AssetCategory,
    AssetGraph,
    AssetIdentity,
    AttributeHistory,
    AttributeObservation,
    DEFAULT_CATEGORY_TTLS,
    EntityStatus,
    IPBindingRecord,
    LogicalLink,
    NetworkAsset,
    PhysicalPort,
    RelationshipType,
    TelemetryCategory,
    from_managed_device,
    from_network_interface,
    from_topology_node,
    normalize_ip_address,
    normalize_mac_address,
    now_utc,
    parse_utc_timestamp,
    to_managed_device,
    to_topology_link,
    to_topology_node,
)
from itsa_network_os.network.models import (
    EvidenceProtocol,
    EvidenceRecord,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)
from itsa_network_os.network.topology import NodeStatus, TopologyLink, TopologyNode, TopologyNodeType
from itsa_network_os.network.vendor_manager import (
    DeviceCategory,
    DeviceSecurityStatus,
    ManagedDevice,
)


# =============================================================================
# Normalization & Timestamp Tests
# =============================================================================

class TestNormalizationAndTimestamps:
    """Tests for MAC, IP, and UTC timestamp normalization helpers."""

    def test_normalize_mac_valid(self) -> None:
        assert normalize_mac_address("00:11:22:33:44:55") == "00:11:22:33:44:55"
        assert normalize_mac_address("00-11-22-33-44-55") == "00:11:22:33:44:55"
        assert normalize_mac_address("001122334455") == "00:11:22:33:44:55"
        assert normalize_mac_address("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac_address(None) is None
        assert normalize_mac_address("") is None

    def test_normalize_mac_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            normalize_mac_address("00:11:22:33:44")  # too short
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            normalize_mac_address("00:11:22:33:44:55:66")  # too long
        with pytest.raises(ValueError, match="Invalid MAC address format"):
            normalize_mac_address("not-a-mac-addr!!")

    def test_normalize_ip_valid(self) -> None:
        assert normalize_ip_address("192.168.1.1") == "192.168.1.1"
        assert normalize_ip_address(" 10.0.0.1 ") == "10.0.0.1"
        assert normalize_ip_address("2001:0db8::0001") == "2001:db8::1"
        assert normalize_ip_address("::1") == "::1"
        assert normalize_ip_address(None) is None
        assert normalize_ip_address("") is None

    def test_normalize_ip_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid IP address format"):
            normalize_ip_address("999.999.999.999")
        with pytest.raises(ValueError, match="Invalid IP address format"):
            normalize_ip_address("invalid-ip")

    def test_parse_utc_timestamp(self) -> None:
        dt = parse_utc_timestamp("2026-10-28T12:00:00Z")
        assert dt.tzinfo == datetime.timezone.utc
        assert dt.year == 2026

        now_str = now_utc()
        dt_now = parse_utc_timestamp(now_str)
        assert dt_now.tzinfo == datetime.timezone.utc

        naive_dt = datetime.datetime(2026, 1, 1, 0, 0, 0)
        aware_dt = parse_utc_timestamp(naive_dt)
        assert aware_dt.tzinfo == datetime.timezone.utc


# =============================================================================
# AssetIdentity Tests
# =============================================================================

class TestAssetIdentity:
    """Tests for stable asset identity creation and validation."""

    def test_create_default_identity(self) -> None:
        ident = AssetIdentity(system_name="Gateway-01")
        assert ident.system_name == "Gateway-01"
        assert ident.confidence == 1.0
        # Should generate a valid UUID4
        uuid.UUID(ident.id)
        assert ident.primary_mac is None
        assert ident.serial_number is None
        assert ident.external_ids == {}

    def test_custom_valid_uuid(self) -> None:
        custom_id = str(uuid.uuid4())
        ident = AssetIdentity(id=custom_id, system_name="Switch-Core")
        assert ident.id == custom_id

    def test_invalid_uuid_raises(self) -> None:
        with pytest.raises(ValueError, match="Must be a valid UUID string"):
            AssetIdentity(id="not-a-uuid", system_name="BadAsset")

    def test_confidence_validation(self) -> None:
        with pytest.raises(ValueError, match="confidence must be a finite number between 0.0 and 1.0"):
            AssetIdentity(confidence=-0.1)
        with pytest.raises(ValueError, match="confidence must be a finite number between 0.0 and 1.0"):
            AssetIdentity(confidence=1.1)
        with pytest.raises(ValueError, match="confidence must be a finite number between 0.0 and 1.0"):
            AssetIdentity(confidence=float("nan"))
        with pytest.raises(TypeError, match="confidence must be float"):
            AssetIdentity(confidence=True)  # bool is subclass of int

    def test_external_identifiers(self) -> None:
        ident = AssetIdentity(
            system_name="Server-Prod-01",
            primary_mac="00:1A:2B:3C:4D:5E",
            serial_number="SN-987654321",
            external_ids={"asset_tag": "TAG-5521", "rack_unit": "U12"},
        )
        assert ident.primary_mac == "00:1a:2b:3c:4d:5e"
        assert ident.external_ids["asset_tag"] == "TAG-5521"
        assert ident.external_ids["rack_unit"] == "U12"

    def test_identity_serialization_round_trip(self) -> None:
        ident = AssetIdentity(
            system_name="EdgeRouter-X",
            primary_mac="F0:9F:C2:11:22:33",
            serial_number="ERX-12345",
            external_ids={"cloud_id": "c-991"},
            confidence=0.95,
            vendor_guess="Ubiquiti",
            model_guess="EdgeRouter X",
        )
        data = ident.to_dict()
        restored = AssetIdentity.from_dict(data)
        assert restored.id == ident.id
        assert restored.system_name == "EdgeRouter-X"
        assert restored.primary_mac == "f0:9f:c2:11:22:33"
        assert restored.serial_number == "ERX-12345"
        assert restored.external_ids == {"cloud_id": "c-991"}
        assert restored.confidence == 0.95
        assert restored.vendor_guess == "Ubiquiti"
        assert restored.model_guess == "EdgeRouter X"


# =============================================================================
# Attribute Observation & History Tests
# =============================================================================

class TestAttributeObservationAndHistory:
    """Tests for evidence attribution, conflict resolution, and staleness."""

    def test_attribute_observation_creation_and_staleness(self) -> None:
        ev = EvidenceRecord(
            source_protocol=EvidenceProtocol.MNDP,
            timestamp=now_utc(),
            confidence=0.9,
            is_verified_fact=True,
            attribute="board_name",
        )
        obs = AttributeObservation(
            attribute="board_name",
            value="RB750Gr3",
            evidence=ev,
            category=TelemetryCategory.DYNAMIC_METRIC,
            ttl_seconds=10.0,
        )
        assert obs.attribute == "board_name"
        assert obs.value == "RB750Gr3"
        assert not obs.is_stale()

        # Simulate 15 seconds passing
        future_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=15)
        assert obs.is_stale(reference_time=future_time)

    def test_attribute_history_conflict_detection(self) -> None:
        history = AttributeHistory(attribute_name="model")

        # First observation: inferred from MAC OUI
        ev1 = EvidenceRecord(
            source_protocol="MAC_OUI",
            timestamp="2026-10-28T10:00:00Z",
            confidence=0.6,
            is_verified_fact=False,
            attribute="model",
        )
        obs1 = AttributeObservation(attribute="model", value="PowerBeam M5", evidence=ev1)
        history.add_observation(obs1)

        assert history.current_value == "PowerBeam M5"
        assert not history.has_conflict

        # Second observation: direct SNMP query reports different model with verified fact
        ev2 = EvidenceRecord(
            source_protocol=EvidenceProtocol.SNMP,
            timestamp="2026-10-28T10:05:00Z",
            confidence=0.95,
            is_verified_fact=True,
            attribute="model",
        )
        obs2 = AttributeObservation(attribute="model", value="PBE-M5-400", evidence=ev2)
        history.add_observation(obs2)

        # Conflict is detected and verified fact wins
        assert history.has_conflict
        assert history.current_value == "PBE-M5-400"
        assert len(history.observations) == 2

    def test_attribute_history_serialization_round_trip(self) -> None:
        history = AttributeHistory(attribute_name="firmware")
        ev = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp=now_utc(),
            confidence=0.99,
            is_verified_fact=True,
        )
        obs = AttributeObservation(attribute="firmware", value="v5.7.3", evidence=ev)
        history.add_observation(obs)

        data = history.to_dict()
        restored = AttributeHistory.from_dict(data)
        assert restored.attribute_name == "firmware"
        assert restored.current_value == "v5.7.3"
        assert len(restored.observations) == 1
        assert restored.observations[0].evidence.source_protocol == "ONVIF"


# =============================================================================
# LogicalLink & Topology Invariant Tests
# =============================================================================

class TestLogicalLinkAndInvariants:
    """Tests for logical link validation, self-link restrictions, and serialization."""

    def test_valid_link_creation(self) -> None:
        src_id = str(uuid.uuid4())
        dst_id = str(uuid.uuid4())
        ev = EvidenceRecord(
            source_protocol=EvidenceProtocol.LLDP,
            timestamp=now_utc(),
            confidence=1.0,
            is_verified_fact=True,
        )
        link = LogicalLink(
            link_id="link-01",
            source_asset_id=src_id,
            target_asset_id=dst_id,
            relationship_type=RelationshipType.VERIFIED_L2_NEIGHBOR,
            source_port_or_interface="eth0",
            target_port_or_interface="ge-0/0/1",
            evidence=ev,
        )
        assert link.link_id == "link-01"
        assert link.relationship_type == RelationshipType.VERIFIED_L2_NEIGHBOR

    def test_self_link_prohibited_by_default(self) -> None:
        asset_id = str(uuid.uuid4())
        with pytest.raises(ValueError, match="Self-links are prohibited"):
            LogicalLink(
                link_id="self-link",
                source_asset_id=asset_id,
                target_asset_id=asset_id,
                relationship_type=RelationshipType.VERIFIED_L2_NEIGHBOR,
                allow_self_link=False,
            )

    def test_self_link_allowed_when_flagged(self) -> None:
        asset_id = str(uuid.uuid4())
        link = LogicalLink(
            link_id="loopback-link",
            source_asset_id=asset_id,
            target_asset_id=asset_id,
            relationship_type=RelationshipType.VERIFIED_LOCAL_ATTACHED,
            allow_self_link=True,
        )
        assert link.source_asset_id == link.target_asset_id

    def test_invalid_uuid_references_raise(self) -> None:
        with pytest.raises(ValueError, match="Source and target asset IDs must be valid UUIDs"):
            LogicalLink(
                link_id="bad-link",
                source_asset_id="invalid-uuid",
                target_asset_id=str(uuid.uuid4()),
                relationship_type=RelationshipType.INFERRED_SAME_SUBNET,
            )

    def test_link_serialization_round_trip(self) -> None:
        src_id = str(uuid.uuid4())
        dst_id = str(uuid.uuid4())
        link = LogicalLink(
            link_id="link-rt",
            source_asset_id=src_id,
            target_asset_id=dst_id,
            relationship_type=RelationshipType.INFERRED_ROUTED_HOP,
            latency_ms=1.2,
            bandwidth_mbps=1000.0,
        )
        data = link.to_dict()
        restored = LogicalLink.from_dict(data)
        assert restored.link_id == "link-rt"
        assert restored.source_asset_id == src_id
        assert restored.target_asset_id == dst_id
        assert restored.relationship_type == RelationshipType.INFERRED_ROUTED_HOP
        assert restored.latency_ms == 1.2
        assert restored.bandwidth_mbps == 1000.0


# =============================================================================
# NetworkAsset & IP Mutation Tests
# =============================================================================

class TestNetworkAsset:
    """Tests for unified NetworkAsset operations, IP mutation tracking, and secret scrubbing."""

    def test_asset_creation_and_ip_binding(self) -> None:
        ident = AssetIdentity(system_name="Core-Switch")
        asset = NetworkAsset(identity=ident, category=AssetCategory.SWITCH)

        # Bind an IP
        asset.bind_ip("192.168.1.1", interface_name="vlan1", scope="global", classification="private")
        assert "192.168.1.1" in asset.management_ips
        assert len(asset.ip_history) == 1
        assert asset.ip_history[0].ip_address == "192.168.1.1"

        # Bind a second IP (dual-homed or management IP added)
        asset.bind_ip("10.0.0.1", interface_name="mgmt0")
        assert len(asset.management_ips) == 2
        assert len(asset.ip_history) == 2

    def test_secret_scrubbing_during_serialization(self) -> None:
        ident = AssetIdentity(system_name="Camera-Axis")
        asset = NetworkAsset(
            identity=ident,
            category=AssetCategory.IP_CAMERA,
            metadata={
                "location": "Front Gate",
                "password": "SuperSecretPassword123!",
                "api_token": "Bearer abc123def456",
            },
        )
        data = asset.to_dict()

        # Metadata must be scrubbed
        assert data["metadata"]["location"] == "Front Gate"
        assert data["metadata"]["password"] == "***REDACTED***"
        assert data["metadata"]["api_token"] == "***REDACTED***"

    def test_network_asset_serialization_round_trip(self) -> None:
        ident = AssetIdentity(system_name="Router-MikroTik", primary_mac="48:8F:5A:11:22:33")
        asset = NetworkAsset(
            identity=ident,
            category=AssetCategory.ROUTER,
            vendor="MikroTik",
            model="CCR1009",
            firmware_version="7.12",
            status=EntityStatus.ONLINE,
        )
        asset.ports["sfp1"] = PhysicalPort(port_id="sfp1", name="SFP Plus 1", speed_mbps=10000, is_up=True)
        asset.bind_ip("172.16.0.1")

        ev = EvidenceRecord(
            source_protocol=EvidenceProtocol.MNDP,
            timestamp=now_utc(),
            confidence=1.0,
            is_verified_fact=True,
            attribute="model",
        )
        asset.record_observation("model", "CCR1009", ev)

        data = asset.to_dict()
        restored = NetworkAsset.from_dict(data)

        assert restored.id == asset.id
        assert restored.name == "Router-MikroTik"
        assert restored.category == AssetCategory.ROUTER
        assert restored.vendor == "MikroTik"
        assert restored.model == "CCR1009"
        assert restored.ports["sfp1"].speed_mbps == 10000
        assert "172.16.0.1" in restored.management_ips
        assert restored.get_attribute("model") == "CCR1009"


# =============================================================================
# AssetGraph & Cyclic Traversal Tests
# =============================================================================

class TestAssetGraphAndCycles:
    """Tests for in-memory graph indexing, safe traversal in cyclic networks, and cycle detection."""

    def test_add_and_lookup_assets_and_links(self) -> None:
        graph = AssetGraph()
        a1 = NetworkAsset(identity=AssetIdentity(system_name="Node-A"))
        a2 = NetworkAsset(identity=AssetIdentity(system_name="Node-B"))

        graph.add_asset(a1)
        graph.add_asset(a2)

        link = LogicalLink(
            link_id="link-ab",
            source_asset_id=a1.id,
            target_asset_id=a2.id,
            relationship_type=RelationshipType.VERIFIED_L2_NEIGHBOR,
        )
        graph.add_link(link)

        assert graph.get_asset(a1.id) is a1
        assert graph.get_link("link-ab") is link
        assert graph.neighbors(a1.id) == [a2]

    def test_cycle_safe_bfs_pathfinding(self) -> None:
        """Construct a cyclic ring topology: A -> B -> C -> A. Verify BFS finds path without loop."""
        graph = AssetGraph()
        a = NetworkAsset(identity=AssetIdentity(system_name="A"))
        b = NetworkAsset(identity=AssetIdentity(system_name="B"))
        c = NetworkAsset(identity=AssetIdentity(system_name="C"))
        d = NetworkAsset(identity=AssetIdentity(system_name="D"))

        for node in (a, b, c, d):
            graph.add_asset(node)

        # Ring: A -> B -> C -> A
        graph.add_link(LogicalLink("l-ab", a.id, b.id, RelationshipType.VERIFIED_L2_NEIGHBOR))
        graph.add_link(LogicalLink("l-bc", b.id, c.id, RelationshipType.VERIFIED_L2_NEIGHBOR))
        graph.add_link(LogicalLink("l-ca", c.id, a.id, RelationshipType.VERIFIED_L2_NEIGHBOR))
        # Branch: C -> D
        graph.add_link(LogicalLink("l-cd", c.id, d.id, RelationshipType.VERIFIED_L2_NEIGHBOR))

        # BFS should find path from A to D safely without infinite recursion
        path = graph.find_path(a.id, d.id)
        assert path == [a.id, b.id, c.id, d.id]

        # Path to non-existent or unreachable
        assert graph.find_path(d.id, a.id) is None  # directed graph, no D -> A link

    def test_cycle_detection(self) -> None:
        graph = AssetGraph()
        a = NetworkAsset(identity=AssetIdentity(system_name="A"))
        b = NetworkAsset(identity=AssetIdentity(system_name="B"))
        c = NetworkAsset(identity=AssetIdentity(system_name="C"))

        for node in (a, b, c):
            graph.add_asset(node)

        graph.add_link(LogicalLink("l-ab", a.id, b.id, RelationshipType.VERIFIED_L2_NEIGHBOR))
        graph.add_link(LogicalLink("l-bc", b.id, c.id, RelationshipType.VERIFIED_L2_NEIGHBOR))
        graph.add_link(LogicalLink("l-ca", c.id, a.id, RelationshipType.VERIFIED_L2_NEIGHBOR))

        cycles = graph.detect_cycles()
        assert len(cycles) >= 1
        # The cycle must involve A, B, C
        cycle_nodes = set(cycles[0])
        assert a.id in cycle_nodes
        assert b.id in cycle_nodes
        assert c.id in cycle_nodes

    def test_graph_serialization_round_trip(self) -> None:
        graph = AssetGraph()
        a = NetworkAsset(identity=AssetIdentity(system_name="Switch-01"))
        b = NetworkAsset(identity=AssetIdentity(system_name="Switch-02"))
        graph.add_asset(a)
        graph.add_asset(b)
        graph.add_link(LogicalLink("l-12", a.id, b.id, RelationshipType.VERIFIED_L2_NEIGHBOR))

        data = graph.to_dict()
        restored = AssetGraph.from_dict(data)

        assert len(restored.assets) == 2
        assert len(restored.links) == 1
        assert restored.get_asset(a.id) is not None
        assert restored.get_link("l-12") is not None


# =============================================================================
# Compatibility Adapter Tests
# =============================================================================

class TestCompatibilityAdapters:
    """Tests for bidirectional adapters converting between legacy models and NetworkAsset."""

    def test_topology_node_adapter(self) -> None:
        legacy_node = TopologyNode(
            id="node-r1",
            label="Router R1",
            node_type=TopologyNodeType.ROUTER,
            ip_address="10.0.0.1",
            mac_address="00:11:22:33:44:55",
            status=NodeStatus.ONLINE,
            x=100.0,
            y=200.0,
            details={"vendor": "Cisco"},
        )
        asset = from_topology_node(legacy_node)
        assert asset.name == "Router R1"
        assert asset.category == AssetCategory.ROUTER
        assert asset.identity.primary_mac == "00:11:22:33:44:55"
        assert "10.0.0.1" in asset.management_ips

        # Convert back
        converted = to_topology_node(asset)
        assert converted.id == "node-r1"
        assert converted.label == "Router R1"
        assert converted.node_type == TopologyNodeType.ROUTER
        assert converted.ip_address == "10.0.0.1"
        assert converted.mac_address == "00:11:22:33:44:55"
        assert converted.x == 100.0
        assert converted.y == 200.0

    def test_managed_device_adapter(self) -> None:
        ev = EvidenceRecord(
            source_protocol=EvidenceProtocol.ONVIF,
            timestamp=now_utc(),
            confidence=0.99,
            is_verified_fact=True,
        )
        legacy_dev = ManagedDevice(
            device_id="cam-01",
            name="Front Gate Camera",
            category=DeviceCategory.IP_CAMERA,
            vendor="Hikvision",
            model="DS-2CD2042WD-I",
            ip_address="192.168.1.64",
            mac_address="c0:56:e3:11:22:33",
            firmware_version="V5.5.82",
            discovery_protocol="ONVIF",
            security_status=DeviceSecurityStatus.SECURE,
            security_notes=["Default password changed"],
            evidence=[ev],
        )
        asset = from_managed_device(legacy_dev)
        assert asset.name == "Front Gate Camera"
        assert asset.category == AssetCategory.IP_CAMERA
        assert asset.vendor == "Hikvision"
        assert asset.model == "DS-2CD2042WD-I"
        assert asset.identity.primary_mac == "c0:56:e3:11:22:33"
        assert "192.168.1.64" in asset.management_ips

        # Convert back
        converted = to_managed_device(asset)
        assert converted.device_id == "cam-01"
        assert converted.name == "Front Gate Camera"
        assert converted.category == DeviceCategory.IP_CAMERA
        assert converted.vendor == "Hikvision"
        assert converted.model == "DS-2CD2042WD-I"

    def test_network_interface_adapter(self) -> None:
        addr = IPAddressInfo(
            address="192.168.1.50",
            prefix_length=24,
            family="IPv4",
            scope="global",
            classification="private",
        )
        iface = NetworkInterface(
            name="eth0",
            mac_address="52:54:00:12:34:56",
            state=InterfaceState.UP,
            interface_type=InterfaceType.ETHERNET,
            mtu=1500,
            addresses=[addr],
        )
        asset = from_network_interface(iface, host_system_name="srv-deb13")
        assert "srv-deb13 (eth0)" in asset.name
        assert asset.category == AssetCategory.SERVER
        assert asset.status == EntityStatus.ONLINE
        assert asset.identity.primary_mac == "52:54:00:12:34:56"
        assert "192.168.1.50" in asset.management_ips

    def test_topology_link_adapter(self) -> None:
        src_id = str(uuid.uuid4())
        dst_id = str(uuid.uuid4())
        link = LogicalLink(
            link_id="link-101",
            source_asset_id=src_id,
            target_asset_id=dst_id,
            relationship_type=RelationshipType.VERIFIED_L2_NEIGHBOR,
            latency_ms=0.8,
            bandwidth_mbps=10000.0,
        )
        top_link = to_topology_link(link)
        assert top_link.id == "link-101"
        assert top_link.source_id == src_id
        assert top_link.target_id == dst_id
        assert top_link.link_type == "VERIFIED_L2_NEIGHBOR"
        assert top_link.speed_mbps == 10000
        assert top_link.latency_ms == 0.8
