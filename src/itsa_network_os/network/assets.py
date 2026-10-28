"""Unified, vendor-neutral asset domain model and property graph for ITSA Network OS.

Provides high-integrity representations for network infrastructure assets, physical
ports, logical links, mutable IP bindings, observation histories with conflict detection,
evidentiary provenance attribution, and safe cyclic graph traversal.
"""

from __future__ import annotations

import copy
import ipaddress
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Union

from itsa_network_os.network.models import (
    EvidenceProtocol,
    EvidenceRecord,
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
)
from itsa_network_os.storage.redaction import CredentialRedactor

if TYPE_CHECKING:
    from itsa_network_os.network.topology import TopologyLink, TopologyNode
    from itsa_network_os.network.vendor_manager import ManagedDevice


# =============================================================================
# Domain Enums
# =============================================================================

class AssetCategory(str, Enum):
    """Categorization for all infrastructure, compute, and physical assets."""

    ROUTER = "ROUTER"
    SWITCH = "SWITCH"
    ACCESS_POINT = "ACCESS_POINT"
    CPE = "CPE"
    IP_CAMERA = "IP_CAMERA"
    NVR_VMS = "NVR_VMS"
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    STORAGE = "STORAGE"
    GATEWAY = "GATEWAY"
    SUBNET = "SUBNET"
    UNKNOWN = "UNKNOWN"


class EntityStatus(str, Enum):
    """Operational status of a network asset or node."""

    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


class RelationshipType(str, Enum):
    """Epistemic classification of topological interconnections between assets.

    Distinguishes verified technical protocol observations from inferred associations.
    """

    # VERIFIED: Backed by direct protocol or kernel proof
    VERIFIED_L2_NEIGHBOR = "VERIFIED_L2_NEIGHBOR"         # e.g., LLDP / CDP neighbor frames
    VERIFIED_LOCAL_ATTACHED = "VERIFIED_LOCAL_ATTACHED"   # e.g., host sysfs/netlink binding
    VERIFIED_MANAGEMENT_OVERLAY = "VERIFIED_MANAGEMENT_OVERLAY" # e.g., ONVIF SOAP XAddr or API endpoint

    # INFERRED: Deductions based on heuristics or correlation
    INFERRED_SAME_SUBNET = "INFERRED_SAME_SUBNET"         # e.g., IPs share a common CIDR block
    INFERRED_PORT_MAPPING = "INFERRED_PORT_MAPPING"       # e.g., learned MAC in bridge forwarding table
    INFERRED_ROUTED_HOP = "INFERRED_ROUTED_HOP"           # e.g., traceroute TTL decrement
    INFERRED_WIRELESS_LINK = "INFERRED_WIRELESS_LINK"     # e.g., matching SSID/frequency/BSSID
    INFERRED_DEVICE_TYPE = "INFERRED_DEVICE_TYPE"         # e.g., MAC OUI prefix lookup


class TelemetryCategory(str, Enum):
    """Classification of telemetry observations for category-specific TTLs."""

    DYNAMIC_METRIC = "DYNAMIC_METRIC"     # Rapidly fluctuating values (e.g., CPU, RAM, bandwidth)
    INTERFACE_STATE = "INTERFACE_STATE"   # Link carrier status, operational state
    ROUTING_ENTRY = "ROUTING_ENTRY"       # Forwarding routes, gateway associations
    STATIC_HARDWARE = "STATIC_HARDWARE"   # Serial numbers, board names, MAC addresses


# Explicit, configurable default TTLs (seconds) per telemetry category
DEFAULT_CATEGORY_TTLS: Dict[TelemetryCategory, float] = {
    TelemetryCategory.DYNAMIC_METRIC: 60.0,
    TelemetryCategory.INTERFACE_STATE: 300.0,
    TelemetryCategory.ROUTING_ENTRY: 600.0,
    TelemetryCategory.STATIC_HARDWARE: 86400.0,
}


# =============================================================================
# Normalization & Timestamp Utilities
# =============================================================================

_MAC_CLEAN_REGEX = re.compile(r"[^0-9a-fA-F]")


def normalize_mac_address(mac: Optional[str]) -> Optional[str]:
    """Normalize MAC address to lowercase EUI-48 format (xx:xx:xx:xx:xx:xx).

    Raises:
        ValueError: If mac is non-empty and not a valid 12-hex-digit EUI-48 address.
    """
    if mac is None:
        return None
    cleaned = _MAC_CLEAN_REGEX.sub("", mac).lower()
    if not cleaned:
        return None
    if len(cleaned) != 12:
        raise ValueError(
            f"Invalid MAC address format: '{mac}'. Must contain exactly 12 hexadecimal digits."
        )
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def normalize_ip_address(ip: Optional[str]) -> Optional[str]:
    """Normalize IPv4 or IPv6 address using standard library ipaddress.

    Raises:
        ValueError: If ip is non-empty and not a valid IP address.
    """
    if ip is None:
        return None
    cleaned = ip.strip()
    if not cleaned:
        return None
    try:
        obj = ipaddress.ip_address(cleaned)
        return str(obj)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address format: '{ip}'") from exc


def now_utc() -> str:
    """Return the current instant as a timezone-aware UTC ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def parse_utc_timestamp(ts: Union[str, datetime]) -> datetime:
    """Parse a timestamp into a timezone-aware UTC datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if isinstance(ts, str):
        cleaned = ts.strip()
        if not cleaned:
            raise ValueError("Timestamp string cannot be empty")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise TypeError(f"Timestamp must be string or datetime, got {type(ts).__name__}")


# =============================================================================
# Core Domain Contracts
# =============================================================================

@dataclass(frozen=True)
class AssetIdentity:
    """Immutable asset identity anchoring stable identifiers across observation sessions.

    Attributes:
        id: Stable UUID string uniquely identifying the asset entity.
        system_name: Primary human-readable name or hostname.
        primary_mac: Optional normalized EUI-48 physical address.
        serial_number: Optional hardware chassis serial number.
        external_ids: Dictionary of external foreign keys (e.g. asset tags, cloud IDs).
        confidence: Normalized confidence metric bounded between 0.0 and 1.0.
        vendor_guess: Inferred or unverified vendor string.
        model_guess: Inferred or unverified model string.
        created_at: ISO 8601 UTC timestamp of asset creation.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    system_name: str = "Unknown"
    primary_mac: Optional[str] = None
    serial_number: Optional[str] = None
    external_ids: Dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0
    vendor_guess: Optional[str] = None
    model_guess: Optional[str] = None
    created_at: str = field(default_factory=now_utc)

    def __post_init__(self) -> None:
        # Validate UUID
        try:
            uuid_obj = uuid.UUID(str(self.id))
            object.__setattr__(self, "id", str(uuid_obj))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid AssetIdentity id: '{self.id}'. Must be a valid UUID string.") from exc

        # Validate confidence
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(f"confidence must be float, got {type(self.confidence).__name__}")
        if math.isnan(self.confidence) or math.isinf(self.confidence) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be a finite number between 0.0 and 1.0, got {self.confidence}")
        object.__setattr__(self, "confidence", float(self.confidence))

        # Normalize MAC
        if self.primary_mac:
            norm_mac = normalize_mac_address(self.primary_mac)
            object.__setattr__(self, "primary_mac", norm_mac)

        # Normalize timestamp
        norm_ts = parse_utc_timestamp(self.created_at).isoformat()
        object.__setattr__(self, "created_at", norm_ts)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AssetIdentity to JSON-compatible dictionary."""
        return {
            "id": self.id,
            "system_name": self.system_name,
            "primary_mac": self.primary_mac,
            "serial_number": self.serial_number,
            "external_ids": dict(self.external_ids),
            "confidence": self.confidence,
            "vendor_guess": self.vendor_guess,
            "model_guess": self.model_guess,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetIdentity:
        """Deserialize AssetIdentity from a dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            system_name=data.get("system_name", "Unknown"),
            primary_mac=data.get("primary_mac"),
            serial_number=data.get("serial_number"),
            external_ids=dict(data.get("external_ids", {})),
            confidence=float(data.get("confidence", 1.0)),
            vendor_guess=data.get("vendor_guess"),
            model_guess=data.get("model_guess"),
            created_at=data.get("created_at", now_utc()),
        )


@dataclass(frozen=True)
class AttributeObservation:
    """A discrete observation of an asset attribute backed by evidentiary provenance."""

    attribute: str
    value: Any
    evidence: EvidenceRecord
    is_inferred: bool = False
    category: TelemetryCategory = TelemetryCategory.DYNAMIC_METRIC
    ttl_seconds: Optional[float] = None
    observed_at: str = field(default_factory=now_utc)

    def __post_init__(self) -> None:
        if not self.attribute or not isinstance(self.attribute, str):
            raise ValueError("attribute name cannot be empty")
        if not isinstance(self.evidence, EvidenceRecord):
            raise TypeError(f"evidence must be an EvidenceRecord, got {type(self.evidence).__name__}")
        norm_ts = parse_utc_timestamp(self.observed_at).isoformat()
        object.__setattr__(self, "observed_at", norm_ts)

        # Apply default category TTL if not explicitly set
        if self.ttl_seconds is None:
            cat_ttl = DEFAULT_CATEGORY_TTLS.get(self.category)
            object.__setattr__(self, "ttl_seconds", cat_ttl)

    def is_stale(self, reference_time: Optional[datetime] = None) -> bool:
        """Return True if this observation has exceeded its category TTL."""
        if self.ttl_seconds is None or self.ttl_seconds <= 0:
            return False
        ref_dt = reference_time or datetime.now(timezone.utc)
        obs_dt = parse_utc_timestamp(self.observed_at)
        delta_seconds = (ref_dt - obs_dt).total_seconds()
        return delta_seconds > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AttributeObservation to JSON-compatible dictionary."""
        return {
            "attribute": self.attribute,
            "value": self.value,
            "evidence": self.evidence.to_dict(),
            "is_inferred": self.is_inferred,
            "category": self.category.value,
            "ttl_seconds": self.ttl_seconds,
            "observed_at": self.observed_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttributeObservation:
        """Deserialize AttributeObservation from a dictionary."""
        ev_data = data["evidence"]
        evidence = EvidenceRecord(
            source_protocol=ev_data["source_protocol"],
            timestamp=ev_data["timestamp"],
            confidence=float(ev_data["confidence"]),
            is_verified_fact=bool(ev_data["is_verified_fact"]),
            attribute=ev_data.get("attribute"),
            details=ev_data.get("details"),
        )
        return cls(
            attribute=data["attribute"],
            value=data["value"],
            evidence=evidence,
            is_inferred=bool(data.get("is_inferred", False)),
            category=TelemetryCategory(data.get("category", TelemetryCategory.DYNAMIC_METRIC.value)),
            ttl_seconds=data.get("ttl_seconds"),
            observed_at=data.get("observed_at", now_utc()),
        )


@dataclass
class AttributeHistory:
    """Historical timeline of observations for an attribute, preserving conflicting data."""

    attribute_name: str
    observations: List[AttributeObservation] = field(default_factory=list)
    current_value: Optional[Any] = None
    has_conflict: bool = False

    def add_observation(self, obs: AttributeObservation) -> None:
        """Append an observation, detect conflicts, and update current_value without clobbering history."""
        if obs.attribute != self.attribute_name:
            raise ValueError(
                f"Cannot add observation for '{obs.attribute}' to AttributeHistory for '{self.attribute_name}'"
            )
        self.observations.append(obs)

        # Detect conflict if distinct values have been observed recently
        distinct_values = {o.value for o in self.observations}
        self.has_conflict = len(distinct_values) > 1

        # Resolve current value: prioritize verified facts over inferences, then higher confidence, then newest
        def sort_key(o: AttributeObservation) -> Tuple[int, float, str]:
            return (
                1 if o.evidence.is_verified_fact else 0,
                o.evidence.confidence,
                o.observed_at,
            )

        best_obs = max(self.observations, key=sort_key)
        self.current_value = best_obs.value

    def get_active_observation(self) -> Optional[AttributeObservation]:
        """Return the observation currently dictating current_value."""
        if not self.observations:
            return None
        for obs in reversed(self.observations):
            if obs.value == self.current_value:
                return obs
        return self.observations[-1]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AttributeHistory to JSON-compatible dictionary."""
        return {
            "attribute_name": self.attribute_name,
            "observations": [o.to_dict() for o in self.observations],
            "current_value": self.current_value,
            "has_conflict": self.has_conflict,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttributeHistory:
        """Deserialize AttributeHistory from a dictionary."""
        history = cls(
            attribute_name=data["attribute_name"],
            current_value=data.get("current_value"),
            has_conflict=bool(data.get("has_conflict", False)),
        )
        for obs_data in data.get("observations", []):
            history.observations.append(AttributeObservation.from_dict(obs_data))
        return history


@dataclass(frozen=True)
class IPBindingRecord:
    """Tracked association between an IP address and an asset, recognizing IPs as mutable bindings."""

    ip_address: str
    interface_name: Optional[str] = None
    first_seen: str = field(default_factory=now_utc)
    last_seen: str = field(default_factory=now_utc)
    is_current: bool = True
    scope: Optional[str] = None
    classification: Optional[str] = None
    evidence: Optional[EvidenceRecord] = None

    def __post_init__(self) -> None:
        norm_ip = normalize_ip_address(self.ip_address)
        if norm_ip is None:
            raise ValueError("ip_address cannot be empty")
        object.__setattr__(self, "ip_address", norm_ip)
        norm_first = parse_utc_timestamp(self.first_seen).isoformat()
        norm_last = parse_utc_timestamp(self.last_seen).isoformat()
        object.__setattr__(self, "first_seen", norm_first)
        object.__setattr__(self, "last_seen", norm_last)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize IPBindingRecord to JSON-compatible dictionary."""
        return {
            "ip_address": self.ip_address,
            "interface_name": self.interface_name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "is_current": self.is_current,
            "scope": self.scope,
            "classification": self.classification,
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IPBindingRecord:
        """Deserialize IPBindingRecord from a dictionary."""
        evidence = None
        if data.get("evidence"):
            ev_data = data["evidence"]
            evidence = EvidenceRecord(
                source_protocol=ev_data["source_protocol"],
                timestamp=ev_data["timestamp"],
                confidence=float(ev_data["confidence"]),
                is_verified_fact=bool(ev_data["is_verified_fact"]),
                attribute=ev_data.get("attribute"),
                details=ev_data.get("details"),
            )
        return cls(
            ip_address=data["ip_address"],
            interface_name=data.get("interface_name"),
            first_seen=data.get("first_seen", now_utc()),
            last_seen=data.get("last_seen", now_utc()),
            is_current=bool(data.get("is_current", True)),
            scope=data.get("scope"),
            classification=data.get("classification"),
            evidence=evidence,
        )


@dataclass(frozen=True)
class PhysicalPort:
    """Representation of a physical switch, router, or server port."""

    port_id: str
    name: str
    mac_address: Optional[str] = None
    medium: str = "Copper"
    speed_mbps: Optional[int] = None
    duplex: Optional[str] = None
    poe_status: Optional[str] = None
    poe_power_watts: Optional[float] = None
    untagged_vlan: Optional[int] = None
    tagged_vlans: List[int] = field(default_factory=list)
    is_up: bool = True

    def __post_init__(self) -> None:
        if self.mac_address:
            norm_mac = normalize_mac_address(self.mac_address)
            object.__setattr__(self, "mac_address", norm_mac)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize PhysicalPort to JSON-compatible dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PhysicalPort:
        """Deserialize PhysicalPort from a dictionary."""
        return cls(
            port_id=data["port_id"],
            name=data["name"],
            mac_address=data.get("mac_address"),
            medium=data.get("medium", "Copper"),
            speed_mbps=data.get("speed_mbps"),
            duplex=data.get("duplex"),
            poe_status=data.get("poe_status"),
            poe_power_watts=data.get("poe_power_watts"),
            untagged_vlan=data.get("untagged_vlan"),
            tagged_vlans=list(data.get("tagged_vlans", [])),
            is_up=bool(data.get("is_up", True)),
        )


@dataclass(frozen=True)
class LogicalLink:
    """Interconnection edge between assets with explicit relationship semantics.

    Supports cyclic network topologies (e.g. redundant ring or mesh networks) while
    optionally rejecting invalid self-links where point-to-point semantics require it.
    """

    link_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: RelationshipType
    source_port_or_interface: Optional[str] = None
    target_port_or_interface: Optional[str] = None
    confidence: float = 1.0
    evidence: Optional[EvidenceRecord] = None
    status: str = "ACTIVE"
    latency_ms: Optional[float] = None
    bandwidth_mbps: Optional[float] = None
    allow_self_link: bool = False
    created_at: str = field(default_factory=now_utc)
    updated_at: str = field(default_factory=now_utc)

    def __post_init__(self) -> None:
        # Validate UUIDs
        try:
            uuid.UUID(str(self.source_asset_id))
            uuid.UUID(str(self.target_asset_id))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Source and target asset IDs must be valid UUIDs: source='{self.source_asset_id}', target='{self.target_asset_id}'"
            ) from exc

        # Self-link validation
        if self.source_asset_id == self.target_asset_id and not self.allow_self_link:
            raise ValueError(
                f"Self-links are prohibited for relationship '{self.relationship_type.value}' unless allow_self_link=True"
            )

        # Validate confidence
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError(f"confidence must be float, got {type(self.confidence).__name__}")
        if not (0.0 <= self.confidence <= 1.0) or math.isnan(self.confidence):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        object.__setattr__(self, "confidence", float(self.confidence))

        # Normalize timestamps
        norm_created = parse_utc_timestamp(self.created_at).isoformat()
        norm_updated = parse_utc_timestamp(self.updated_at).isoformat()
        object.__setattr__(self, "created_at", norm_created)
        object.__setattr__(self, "updated_at", norm_updated)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize LogicalLink to JSON-compatible dictionary."""
        return {
            "link_id": self.link_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "relationship_type": self.relationship_type.value,
            "source_port_or_interface": self.source_port_or_interface,
            "target_port_or_interface": self.target_port_or_interface,
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "bandwidth_mbps": self.bandwidth_mbps,
            "allow_self_link": self.allow_self_link,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogicalLink:
        """Deserialize LogicalLink from a dictionary."""
        evidence = None
        if data.get("evidence"):
            ev_data = data["evidence"]
            evidence = EvidenceRecord(
                source_protocol=ev_data["source_protocol"],
                timestamp=ev_data["timestamp"],
                confidence=float(ev_data["confidence"]),
                is_verified_fact=bool(ev_data["is_verified_fact"]),
                attribute=ev_data.get("attribute"),
                details=ev_data.get("details"),
            )
        return cls(
            link_id=data["link_id"],
            source_asset_id=data["source_asset_id"],
            target_asset_id=data["target_asset_id"],
            relationship_type=RelationshipType(data["relationship_type"]),
            source_port_or_interface=data.get("source_port_or_interface"),
            target_port_or_interface=data.get("target_port_or_interface"),
            confidence=float(data.get("confidence", 1.0)),
            evidence=evidence,
            status=data.get("status", "ACTIVE"),
            latency_ms=data.get("latency_ms"),
            bandwidth_mbps=data.get("bandwidth_mbps"),
            allow_self_link=bool(data.get("allow_self_link", False)),
            created_at=data.get("created_at", now_utc()),
            updated_at=data.get("updated_at", now_utc()),
        )


@dataclass
class NetworkAsset:
    """Canonical representation of any managed, observed, or discovered infrastructure entity."""

    identity: AssetIdentity
    category: AssetCategory = AssetCategory.UNKNOWN
    vendor: str = "Unknown"
    model: str = "Unknown"
    firmware_version: str = "Unknown"
    status: EntityStatus = EntityStatus.UNKNOWN
    management_ips: List[str] = field(default_factory=list)
    interfaces: Dict[str, NetworkInterface] = field(default_factory=dict)
    ports: Dict[str, PhysicalPort] = field(default_factory=dict)
    ip_history: List[IPBindingRecord] = field(default_factory=list)
    attribute_histories: Dict[str, AttributeHistory] = field(default_factory=dict)
    evidence_records: List[EvidenceRecord] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Convenience accessor for primary asset UUID string."""
        return self.identity.id

    @property
    def name(self) -> str:
        """Convenience accessor for primary system name."""
        return self.identity.system_name

    def record_observation(
        self,
        attribute: str,
        value: Any,
        evidence: EvidenceRecord,
        category: TelemetryCategory = TelemetryCategory.DYNAMIC_METRIC,
        ttl_seconds: Optional[float] = None,
    ) -> None:
        """Record an evidentiary observation for an attribute with conflict tracking."""
        obs = AttributeObservation(
            attribute=attribute,
            value=value,
            evidence=evidence,
            is_inferred=not evidence.is_verified_fact,
            category=category,
            ttl_seconds=ttl_seconds,
            observed_at=evidence.timestamp,
        )
        if attribute not in self.attribute_histories:
            self.attribute_histories[attribute] = AttributeHistory(attribute_name=attribute)
        self.attribute_histories[attribute].add_observation(obs)

        # Update root attribute fields if relevant
        if attribute == "vendor" and evidence.is_verified_fact:
            self.vendor = str(value)
        elif attribute == "model" and evidence.is_verified_fact:
            self.model = str(value)
        elif attribute == "firmware_version" and evidence.is_verified_fact:
            self.firmware_version = str(value)

        # Append to overall evidence trail
        self.evidence_records.append(evidence)

    def get_attribute(self, attribute: str) -> Optional[Any]:
        """Retrieve current value for an observed attribute."""
        history = self.attribute_histories.get(attribute)
        if history:
            return history.current_value
        return None

    def has_attribute_conflict(self, attribute: str) -> bool:
        """Return True if conflicting observations exist for this attribute."""
        history = self.attribute_histories.get(attribute)
        if history:
            return history.has_conflict
        return False

    def bind_ip(
        self,
        ip_address: str,
        interface_name: Optional[str] = None,
        scope: Optional[str] = None,
        classification: Optional[str] = None,
        evidence: Optional[EvidenceRecord] = None,
    ) -> None:
        """Associate an IP address with this asset while maintaining IP mutation history."""
        norm_ip = normalize_ip_address(ip_address)
        if not norm_ip:
            return
        if norm_ip not in self.management_ips:
            self.management_ips.append(norm_ip)

        # Update or append IP binding record
        existing = [b for b in self.ip_history if b.ip_address == norm_ip]
        if existing:
            rec = existing[-1]
            updated = IPBindingRecord(
                ip_address=norm_ip,
                interface_name=interface_name or rec.interface_name,
                first_seen=rec.first_seen,
                last_seen=now_utc(),
                is_current=True,
                scope=scope or rec.scope,
                classification=classification or rec.classification,
                evidence=evidence or rec.evidence,
            )
            self.ip_history.remove(rec)
            self.ip_history.append(updated)
        else:
            self.ip_history.append(
                IPBindingRecord(
                    ip_address=norm_ip,
                    interface_name=interface_name,
                    first_seen=now_utc(),
                    last_seen=now_utc(),
                    is_current=True,
                    scope=scope,
                    classification=classification,
                    evidence=evidence,
                )
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize NetworkAsset to JSON-compatible dictionary with secret scrubbing."""
        # Sanitize metadata using CredentialRedactor before serialization
        sanitized_metadata, _ = CredentialRedactor.redact(self.metadata)

        return {
            "identity": self.identity.to_dict(),
            "category": self.category.value,
            "vendor": self.vendor,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "status": self.status.value,
            "management_ips": list(self.management_ips),
            "interfaces": {k: v.to_dict() for k, v in self.interfaces.items()},
            "ports": {k: v.to_dict() for k, v in self.ports.items()},
            "ip_history": [b.to_dict() for b in self.ip_history],
            "attribute_histories": {k: v.to_dict() for k, v in self.attribute_histories.items()},
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "metadata": sanitized_metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NetworkAsset:
        """Deserialize NetworkAsset from a dictionary."""
        identity = AssetIdentity.from_dict(data["identity"])
        asset = cls(
            identity=identity,
            category=AssetCategory(data.get("category", AssetCategory.UNKNOWN.value)),
            vendor=data.get("vendor", "Unknown"),
            model=data.get("model", "Unknown"),
            firmware_version=data.get("firmware_version", "Unknown"),
            status=EntityStatus(data.get("status", EntityStatus.UNKNOWN.value)),
            management_ips=list(data.get("management_ips", [])),
            metadata=dict(data.get("metadata", {})),
        )

        # Deserialize ports
        for port_id, port_data in data.get("ports", {}).items():
            asset.ports[port_id] = PhysicalPort.from_dict(port_data)

        # Deserialize IP history
        for ip_data in data.get("ip_history", []):
            asset.ip_history.append(IPBindingRecord.from_dict(ip_data))

        # Deserialize attribute histories
        for attr_name, hist_data in data.get("attribute_histories", {}).items():
            asset.attribute_histories[attr_name] = AttributeHistory.from_dict(hist_data)

        # Deserialize evidence records
        for ev_data in data.get("evidence_records", []):
            asset.evidence_records.append(
                EvidenceRecord(
                    source_protocol=ev_data["source_protocol"],
                    timestamp=ev_data["timestamp"],
                    confidence=float(ev_data["confidence"]),
                    is_verified_fact=bool(ev_data["is_verified_fact"]),
                    attribute=ev_data.get("attribute"),
                    details=ev_data.get("details"),
                )
            )

        return asset


# =============================================================================
# In-Memory Property Graph with Safe Cyclic Traversal
# =============================================================================

class AssetGraph:
    """In-memory directed property graph of network assets and topological links.

    Maintains adjacency indices and provides cycle-safe graph traversal algorithms.
    """

    def __init__(self) -> None:
        self.assets: Dict[str, NetworkAsset] = {}
        self.links: Dict[str, LogicalLink] = {}
        self._adjacency: Dict[str, Set[str]] = {}
        self._reverse_adjacency: Dict[str, Set[str]] = {}
        self._link_lookup: Dict[Tuple[str, str], List[str]] = {}

    def add_asset(self, asset: NetworkAsset) -> None:
        """Add or update an asset in the graph."""
        if not isinstance(asset, NetworkAsset):
            raise TypeError(f"asset must be NetworkAsset, got {type(asset).__name__}")
        self.assets[asset.id] = asset
        if asset.id not in self._adjacency:
            self._adjacency[asset.id] = set()
        if asset.id not in self._reverse_adjacency:
            self._reverse_adjacency[asset.id] = set()

    def get_asset(self, asset_id: str) -> Optional[NetworkAsset]:
        """Retrieve an asset by its UUID string."""
        return self.assets.get(asset_id)

    def add_link(self, link: LogicalLink) -> None:
        """Add a directed or peer topological link between assets."""
        if not isinstance(link, LogicalLink):
            raise TypeError(f"link must be LogicalLink, got {type(link).__name__}")

        if link.source_asset_id not in self.assets:
            raise KeyError(f"Source asset '{link.source_asset_id}' does not exist in graph")
        if link.target_asset_id not in self.assets:
            raise KeyError(f"Target asset '{link.target_asset_id}' does not exist in graph")

        self.links[link.link_id] = link
        self._adjacency[link.source_asset_id].add(link.target_asset_id)
        self._reverse_adjacency[link.target_asset_id].add(link.source_asset_id)

        pair = (link.source_asset_id, link.target_asset_id)
        if pair not in self._link_lookup:
            self._link_lookup[pair] = []
        self._link_lookup[pair].append(link.link_id)

    def get_link(self, link_id: str) -> Optional[LogicalLink]:
        """Retrieve a link by its identifier."""
        return self.links.get(link_id)

    def neighbors(self, asset_id: str) -> List[NetworkAsset]:
        """Return list of outward neighbor assets reachable from asset_id."""
        if asset_id not in self._adjacency:
            return []
        return [self.assets[target_id] for target_id in self._adjacency[asset_id] if target_id in self.assets]

    def find_by_mac(self, mac: str) -> Optional[NetworkAsset]:
        """Lookup an asset by normalized primary MAC or interface MAC."""
        norm_mac = normalize_mac_address(mac)
        if not norm_mac:
            return None
        for asset in self.assets.values():
            if asset.identity.primary_mac == norm_mac:
                return asset
            for iface in asset.interfaces.values():
                if normalize_mac_address(iface.mac_address) == norm_mac:
                    return asset
            for port in asset.ports.values():
                if port.mac_address == norm_mac:
                    return asset
        return None

    def find_by_ip(self, ip: str) -> List[NetworkAsset]:
        """Return all assets associated with an IP address (supporting multi-asset bindings)."""
        norm_ip = normalize_ip_address(ip)
        if not norm_ip:
            return []
        matches: List[NetworkAsset] = []
        for asset in self.assets.values():
            if norm_ip in asset.management_ips:
                matches.append(asset)
            elif any(b.ip_address == norm_ip for b in asset.ip_history if b.is_current):
                matches.append(asset)
        return matches

    def find_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find the shortest hop path between two assets using Breadth-First Search.

        Employs an explicit visited set to handle cyclic graphs safely without infinite loops.
        """
        if source_id not in self.assets or target_id not in self.assets:
            return None
        if source_id == target_id:
            return [source_id]

        queue: List[Tuple[str, List[str]]] = [(source_id, [source_id])]
        visited: Set[str] = {source_id}

        while queue:
            current_id, path = queue.pop(0)
            for neighbor_id in self._adjacency.get(current_id, set()):
                if neighbor_id == target_id:
                    return path + [neighbor_id]
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return None

    def detect_cycles(self) -> List[List[str]]:
        """Identify elementary directed cycles in the graph without recursion overflow.

        Returns:
            List of cycle paths (e.g. [['A', 'B', 'C', 'A']]).
        """
        cycles: List[List[str]] = []
        # Vertex coloring: 0 = unvisited, 1 = visiting (in recursion stack), 2 = visited
        color: Dict[str, int] = {node_id: 0 for node_id in self.assets}
        parent: Dict[str, Optional[str]] = {node_id: None for node_id in self.assets}

        for start_node in self.assets:
            if color[start_node] != 0:
                continue

            # Iterative DFS stack: (node, neighbor_iterator)
            stack: List[str] = [start_node]
            color[start_node] = 1

            while stack:
                curr = stack[-1]
                neighbors = sorted(list(self._adjacency.get(curr, set())))
                advanced = False

                for nxt in neighbors:
                    if color[nxt] == 1:
                        # Cycle detected: backtrack from curr up to nxt
                        cycle_path = [nxt, curr]
                        p = parent[curr]
                        while p is not None and p != nxt and p in parent:
                            cycle_path.append(p)
                            p = parent[p]
                        cycle_path.append(nxt)
                        cycle_path.reverse()
                        cycles.append(cycle_path)
                    elif color[nxt] == 0:
                        color[nxt] = 1
                        parent[nxt] = curr
                        stack.append(nxt)
                        advanced = True
                        break

                if not advanced:
                    stack.pop()
                    color[curr] = 2

        return cycles

    def to_dict(self) -> Dict[str, Any]:
        """Serialize AssetGraph to a JSON-compatible dictionary."""
        return {
            "assets": {aid: asset.to_dict() for aid, asset in self.assets.items()},
            "links": {lid: link.to_dict() for lid, link in self.links.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetGraph:
        """Deserialize AssetGraph from a dictionary."""
        graph = cls()
        for aid, asset_data in data.get("assets", {}).items():
            graph.add_asset(NetworkAsset.from_dict(asset_data))
        for lid, link_data in data.get("links", {}).items():
            graph.add_link(LogicalLink.from_dict(link_data))
        return graph


# =============================================================================
# Compatibility Adapters (Translators for Legacy Models)
# =============================================================================

def from_topology_node(node: TopologyNode) -> NetworkAsset:
    """Convert legacy TopologyNode into a standardized NetworkAsset."""
    # Deterministic UUID generation from node.id
    node_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"topology.node.{node.id}"))
    identity = AssetIdentity(
        id=node_uuid,
        system_name=node.label or node.id,
        primary_mac=normalize_mac_address(node.mac_address) if node.mac_address else None,
        external_ids={"legacy_topology_id": node.id},
    )

    category_map: Dict[str, AssetCategory] = {
        "Router": AssetCategory.ROUTER,
        "Gateway": AssetCategory.GATEWAY,
        "Switch": AssetCategory.SWITCH,
        "Server": AssetCategory.SERVER,
        "Workstation": AssetCategory.WORKSTATION,
        "Subnet": AssetCategory.SUBNET,
    }
    cat = category_map.get(node.node_type.value, AssetCategory.UNKNOWN)

    status_map: Dict[str, EntityStatus] = {
        "ONLINE": EntityStatus.ONLINE,
        "OFFLINE": EntityStatus.OFFLINE,
        "DEGRADED": EntityStatus.DEGRADED,
    }
    stat = status_map.get(node.status.value, EntityStatus.UNKNOWN)

    asset = NetworkAsset(
        identity=identity,
        category=cat,
        status=stat,
        metadata={"x": node.x, "y": node.y, **copy.deepcopy(node.details)},
    )
    if node.ip_address:
        asset.bind_ip(node.ip_address)
    return asset


def to_topology_node(asset: NetworkAsset) -> TopologyNode:
    """Convert NetworkAsset into a legacy TopologyNode for GUI visualization."""
    from itsa_network_os.network.topology import NodeStatus, TopologyNode, TopologyNodeType

    type_map: Dict[AssetCategory, TopologyNodeType] = {
        AssetCategory.ROUTER: TopologyNodeType.ROUTER,
        AssetCategory.GATEWAY: TopologyNodeType.GATEWAY,
        AssetCategory.SWITCH: TopologyNodeType.SWITCH,
        AssetCategory.SERVER: TopologyNodeType.SERVER,
        AssetCategory.WORKSTATION: TopologyNodeType.WORKSTATION,
        AssetCategory.SUBNET: TopologyNodeType.SUBNET,
    }
    node_type = type_map.get(asset.category, TopologyNodeType.WORKSTATION)

    status_map: Dict[EntityStatus, NodeStatus] = {
        EntityStatus.ONLINE: NodeStatus.ONLINE,
        EntityStatus.OFFLINE: NodeStatus.OFFLINE,
        EntityStatus.DEGRADED: NodeStatus.DEGRADED,
        EntityStatus.STALE: NodeStatus.DEGRADED,
        EntityStatus.UNKNOWN: NodeStatus.ONLINE,
    }
    node_status = status_map.get(asset.status, NodeStatus.ONLINE)

    primary_ip = asset.management_ips[0] if asset.management_ips else ""
    x_pos = float(asset.metadata.get("x", 0.0))
    y_pos = float(asset.metadata.get("y", 0.0))

    return TopologyNode(
        id=asset.identity.external_ids.get("legacy_topology_id", asset.id),
        label=asset.name,
        node_type=node_type,
        ip_address=primary_ip,
        mac_address=asset.identity.primary_mac or "",
        status=node_status,
        x=x_pos,
        y=y_pos,
        details=copy.deepcopy(asset.metadata),
    )


def from_managed_device(device: ManagedDevice) -> NetworkAsset:
    """Convert legacy ManagedDevice into a standardized NetworkAsset."""
    device_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"managed.device.{device.device_id}"))
    identity = AssetIdentity(
        id=device_uuid,
        system_name=device.name,
        primary_mac=normalize_mac_address(device.mac_address),
        external_ids={"managed_device_id": device.device_id},
        vendor_guess=device.vendor,
        model_guess=device.model,
    )

    category_map: Dict[str, AssetCategory] = {
        "IP Camera / CCTV": AssetCategory.IP_CAMERA,
        "MikroTik RouterOS": AssetCategory.ROUTER,
        "Ubiquiti airMAX/UniFi": AssetCategory.CPE,
        "TP-Link Pharos CPE": AssetCategory.CPE,
        "Linux / Ubuntu Server": AssetCategory.SERVER,
    }
    cat = category_map.get(device.category.value, AssetCategory.UNKNOWN)

    asset = NetworkAsset(
        identity=identity,
        category=cat,
        vendor=device.vendor,
        model=device.model,
        firmware_version=device.firmware_version,
        status=EntityStatus.ONLINE,
        evidence_records=list(device.evidence),
        metadata={
            "discovery_protocol": device.discovery_protocol,
            "security_status": device.security_status.value,
            "security_notes": list(device.security_notes),
        },
    )
    if device.ip_address:
        asset.bind_ip(device.ip_address)
    return asset


def to_managed_device(asset: NetworkAsset) -> ManagedDevice:
    """Convert NetworkAsset into a legacy ManagedDevice representation."""
    from itsa_network_os.network.vendor_manager import (
        DeviceCategory,
        DeviceSecurityStatus,
        ManagedDevice,
    )

    category_map: Dict[AssetCategory, DeviceCategory] = {
        AssetCategory.IP_CAMERA: DeviceCategory.IP_CAMERA,
        AssetCategory.ROUTER: DeviceCategory.MIKROTIK,
        AssetCategory.CPE: DeviceCategory.UBIQUITI,
        AssetCategory.SERVER: DeviceCategory.LINUX_SERVER,
    }
    dev_cat = category_map.get(asset.category, DeviceCategory.LINUX_SERVER)

    sec_status_str = str(asset.metadata.get("security_status", DeviceSecurityStatus.SECURE.value))
    try:
        sec_status = DeviceSecurityStatus(sec_status_str)
    except ValueError:
        sec_status = DeviceSecurityStatus.SECURE

    primary_ip = asset.management_ips[0] if asset.management_ips else "0.0.0.0"

    return ManagedDevice(
        device_id=asset.identity.external_ids.get("managed_device_id", asset.id),
        name=asset.name,
        category=dev_cat,
        vendor=asset.vendor,
        model=asset.model,
        ip_address=primary_ip,
        mac_address=asset.identity.primary_mac or "00:00:00:00:00:00",
        firmware_version=asset.firmware_version,
        discovery_protocol=str(asset.metadata.get("discovery_protocol", "MANUAL")),
        security_status=sec_status,
        security_notes=list(asset.metadata.get("security_notes", [])),
        evidence=list(asset.evidence_records),
    )


def from_network_interface(interface: NetworkInterface, host_system_name: str = "localhost") -> NetworkAsset:
    """Wrap a local host NetworkInterface into a standardized NetworkAsset."""
    iface_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"host.interface.{host_system_name}.{interface.name}"))
    identity = AssetIdentity(
        id=iface_uuid,
        system_name=f"{host_system_name} ({interface.name})",
        primary_mac=normalize_mac_address(interface.mac_address),
        external_ids={"interface_name": interface.name, "host": host_system_name},
    )

    cat = AssetCategory.SERVER if interface.interface_type == InterfaceType.ETHERNET else AssetCategory.UNKNOWN
    stat = EntityStatus.ONLINE if interface.state == InterfaceState.UP else EntityStatus.OFFLINE

    asset = NetworkAsset(
        identity=identity,
        category=cat,
        status=stat,
        interfaces={interface.name: interface},
        metadata={"mtu": interface.mtu, "interface_type": interface.interface_type.value},
    )

    for addr in interface.addresses:
        asset.bind_ip(
            ip_address=addr.address,
            interface_name=interface.name,
            scope=addr.scope,
            classification=addr.classification,
        )

    return asset


def to_topology_link(link: LogicalLink) -> TopologyLink:
    """Convert LogicalLink into a legacy TopologyLink for visualization."""
    from itsa_network_os.network.topology import TopologyLink

    return TopologyLink(
        id=link.link_id,
        source_id=link.source_asset_id,
        target_id=link.target_asset_id,
        link_type=link.relationship_type.value,
        speed_mbps=int(link.bandwidth_mbps) if link.bandwidth_mbps else 1000,
        latency_ms=link.latency_ms if link.latency_ms is not None else 0.5,
        status=link.status,
    )
