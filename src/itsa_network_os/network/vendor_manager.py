"""Multi-Vendor Hardware & IP Surveillance Camera management, ONVIF/RTSP discovery, and CPE telemetry."""

from __future__ import annotations

import logging
import socket
import threading
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from itsa_network_os.network.mndp import MNDPObservation, MNDPPassiveListener
from itsa_network_os.network.models import EvidenceProtocol, EvidenceRecord
from itsa_network_os.network.onvif import ONVIFObservation, ONVIFPassiveListener

if TYPE_CHECKING:
    from itsa_network_os.network.scope import ScopeGuard


class DeviceCategory(str, Enum):
    """Categorization for discovered network hardware and surveillance units."""

    IP_CAMERA = "IP Camera / CCTV"
    MIKROTIK = "MikroTik RouterOS"
    UBIQUITI = "Ubiquiti airMAX/UniFi"
    TPLINK_CPE = "TP-Link Pharos CPE"
    LINUX_SERVER = "Linux / Ubuntu Server"


class DeviceSecurityStatus(str, Enum):
    """Cybersecurity posture evaluation of managed hardware."""

    SECURE = "Secure"
    WARNING = "Warning (Default Credentials / Port Exposed)"
    CRITICAL = "Critical (Unencrypted Stream / Deprecated OS)"


@dataclass(frozen=True)
class CameraTelemetry:
    """Specialized surveillance video telemetry, RTSP stream URIs, and ONVIF specifications."""

    rtsp_uri: str
    onvif_port: int
    resolution: str
    codec: str
    fps: int
    has_default_credentials: bool
    ptz_supported: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WirelessLinkTelemetry:
    """High-frequency wireless microwave, PtP / PtMP link telemetry for outdoor CPEs."""

    signal_rssi_dbm: int
    noise_floor_dbm: int
    snr_db: int
    ccq_percent: float
    tx_rate_mbps: float
    rx_rate_mbps: float
    distance_km: float
    frequency_mhz: int
    channel_width_mhz: int
    wireless_mode: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RouterOSTelemetry:
    """MikroTik RouterOS hardware telemetry and system health."""

    board_name: str
    architecture: str
    cpu_load_percent: int
    free_memory_mb: float
    uptime_str: str
    active_interfaces: int
    active_leases: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ManagedDevice:
    """Consolidated representation of discovered multi-vendor network and surveillance equipment."""

    device_id: str
    name: str
    category: DeviceCategory
    vendor: str
    model: str
    ip_address: str
    mac_address: str
    firmware_version: str
    discovery_protocol: str
    security_status: DeviceSecurityStatus
    security_notes: List[str] = field(default_factory=list)
    camera_info: Optional[CameraTelemetry] = None
    wireless_info: Optional[WirelessLinkTelemetry] = None
    router_info: Optional[RouterOSTelemetry] = None
    evidence: List[EvidenceRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["security_status"] = self.security_status.value
        if self.camera_info:
            data["camera_info"] = self.camera_info.to_dict()
        if self.wireless_info:
            data["wireless_info"] = self.wireless_info.to_dict()
        if self.router_info:
            data["router_info"] = self.router_info.to_dict()
        data["evidence"] = [e.to_dict() for e in self.evidence]
        return data


@dataclass(frozen=True)
class VendorDiscoveryReport:
    """Comprehensive discovery and inventory report of multi-vendor network hardware."""

    total_devices: int
    category_counts: Dict[str, int]
    devices: List[ManagedDevice]
    vulnerable_device_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_devices": self.total_devices,
            "category_counts": self.category_counts,
            "devices": [d.to_dict() for d in self.devices],
            "vulnerable_device_count": self.vulnerable_device_count,
        }


class VendorManagerEngine:
    """Discovery and telemetry inspection engine for MikroTik, Ubiquiti, TP-Link CPE, and ONVIF Cameras."""

    @classmethod
    def get_mock_devices(cls) -> List[ManagedDevice]:
        """Realistic enterprise field dataset representing common WISP, campus, and surveillance hardware."""
        return [
            ManagedDevice(
                device_id="CAM-01",
                name="Main Entrance 4K Dome",
                category=DeviceCategory.IP_CAMERA,
                vendor="Hikvision",
                model="DS-2CD2143G2-I",
                ip_address="192.168.1.120",
                mac_address="BC:54:36:11:A2:99",
                firmware_version="V5.7.12_build231018",
                discovery_protocol="ONVIF WS-Discovery (UDP 3702)",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["Strong admin password active", "Encrypted HTTPS onvif enabled", "Firmware up to date"],
                camera_info=CameraTelemetry(
                    rtsp_uri="rtsp://admin:*****@192.168.1.120:554/Streaming/Channels/101",
                    onvif_port=80,
                    resolution="3840x2160 (4K UHD)",
                    codec="H.265 / HEVC Main Profile",
                    fps=30,
                    has_default_credentials=False,
                    ptz_supported=False,
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ONVIF,
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="device_identity",
                        details="Verified via ONVIF WS-Discovery ProbeMatch (UDP 3702)",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.RTSP,
                        timestamp="2026-10-19T12:00:01+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="camera_info",
                        details="Verified RTSP DESCRIBE stream parameters on port 554",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.HTTP,
                        timestamp="2026-10-19T12:00:02+00:00",
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="model",
                        details="Inferred model DS-2CD2143G2-I from web interface title",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="CAM-02",
                name="Perimeter PTZ Speed Dome",
                category=DeviceCategory.IP_CAMERA,
                vendor="Dahua",
                model="SD49225XA-HNR",
                ip_address="192.168.1.121",
                mac_address="E0:50:8B:44:19:0C",
                firmware_version="V2.812.0000000.12.R",
                discovery_protocol="ONVIF WS-Discovery (UDP 3702)",
                security_status=DeviceSecurityStatus.WARNING,
                security_notes=[
                    "Default ONVIF credential detected (admin/admin)",
                    "Cleartext RTSP port 554 unencrypted",
                    "Immediate password change recommended",
                ],
                camera_info=CameraTelemetry(
                    rtsp_uri="rtsp://admin:admin@192.168.1.121:554/cam/realmonitor?channel=1&subtype=0",
                    onvif_port=80,
                    resolution="1920x1080 (1080p FHD)",
                    codec="H.264 High Profile",
                    fps=60,
                    has_default_credentials=True,
                    ptz_supported=True,
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ONVIF,
                        timestamp="2026-10-19T12:00:05+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="device_identity",
                        details="Verified Dahua PTZ responder on ONVIF port 80",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MOCK,
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=0.75,
                        is_verified_fact=False,
                        attribute="security_status",
                        details="Inferred default credentials based on factory port behavior",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="MIK-01",
                name="Core Gateway hEX S",
                category=DeviceCategory.MIKROTIK,
                vendor="MikroTik",
                model="RB760iGS (hEX S)",
                ip_address="192.168.1.1",
                mac_address="6C:3B:6B:88:99:A1",
                firmware_version="RouterOS v7.14.3 (Stable)",
                discovery_protocol="MNDP (MikroTik Discovery UDP 5678)",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["Winbox port restricted", "SSH key authentication enabled", "Default admin account renamed"],
                router_info=RouterOSTelemetry(
                    board_name="RB760iGS",
                    architecture="MMIPS",
                    cpu_load_percent=14,
                    free_memory_mb=218.4,
                    uptime_str="38 days, 14:22:10",
                    active_interfaces=5,
                    active_leases=24,
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp="2026-10-19T12:00:10+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="router_info",
                        details="Verified MikroTik Neighbor Discovery packet on UDP 5678",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ARP,
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=0.90,
                        is_verified_fact=False,
                        attribute="vendor",
                        details="Inferred vendor MikroTik from MAC OUI prefix 6C:3B:6B",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="MIK-02",
                name="Aggregation Switch CRS326",
                category=DeviceCategory.MIKROTIK,
                vendor="MikroTik",
                model="CRS326-24G-2S+RM",
                ip_address="192.168.1.2",
                mac_address="48:8F:5A:CC:12:44",
                firmware_version="RouterOS v7.13.5 (SwOS Compatible)",
                discovery_protocol="MNDP (MikroTik Discovery UDP 5678)",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["Hardware offload L3 active", "Spanning Tree Protocol (RSTP) enabled"],
                router_info=RouterOSTelemetry(
                    board_name="CRS326-24G-2S+",
                    architecture="ARM",
                    cpu_load_percent=6,
                    free_memory_mb=482.0,
                    uptime_str="120 days, 01:05:32",
                    active_interfaces=26,
                    active_leases=0,
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp="2026-10-19T12:00:12+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="router_info",
                        details="Verified MikroTik CRS326 switch telemetry via MNDP",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="UBNT-01",
                name="Tower PtP Link (HQ -> Branch)",
                category=DeviceCategory.UBIQUITI,
                vendor="Ubiquiti",
                model="LiteBeam 5AC Gen2",
                ip_address="192.168.1.20",
                mac_address="B4:FB:E4:77:88:99",
                firmware_version="AirOS WA.v8.7.1",
                discovery_protocol="UBNT Discovery (UDP 10001)",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["WPA2-Enterprise with airMAX AC active", "Management radio auto-disabled"],
                wireless_info=WirelessLinkTelemetry(
                    signal_rssi_dbm=-54,
                    noise_floor_dbm=-96,
                    snr_db=42,
                    ccq_percent=99.2,
                    tx_rate_mbps=320.0,
                    rx_rate_mbps=320.0,
                    distance_km=3.8,
                    frequency_mhz=5765,
                    channel_width_mhz=40,
                    wireless_mode="Access Point PtP (airMAX AC)",
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol="UBNT Discovery",
                        timestamp="2026-10-19T12:00:20+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="wireless_info",
                        details="Verified Ubiquiti airMAX discovery broadcast on UDP 10001",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.SNMP,
                        timestamp="2026-10-19T12:00:21+00:00",
                        confidence=0.80,
                        is_verified_fact=False,
                        attribute="firmware_version",
                        details="Estimated firmware version from standard sysDescr",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="UBNT-02",
                name="Office Wi-Fi 6 AP",
                category=DeviceCategory.UBIQUITI,
                vendor="Ubiquiti",
                model="UniFi U6-Pro",
                ip_address="192.168.1.21",
                mac_address="74:83:C2:55:66:77",
                firmware_version="UniFi 6.6.65",
                discovery_protocol="UBNT Discovery (UDP 10001)",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["Managed via UniFi Network Controller", "Band steering enabled", "WPA3 Transition active"],
                evidence=[
                    EvidenceRecord(
                        source_protocol="UBNT Discovery",
                        timestamp="2026-10-19T12:00:25+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="device_identity",
                        details="Verified UniFi AP beacon response",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="TPL-01",
                name="Warehouse Client CPE",
                category=DeviceCategory.TPLINK_CPE,
                vendor="TP-Link",
                model="Pharos CPE510 v3.20",
                ip_address="192.168.1.30",
                mac_address="50:C7:BF:11:22:33",
                firmware_version="PharOS 2.2.3 Build 20210714",
                discovery_protocol="TDDP / Pharos Discovery (UDP)",
                security_status=DeviceSecurityStatus.WARNING,
                security_notes=[
                    "Old PharOS firmware detected (Vulnerability advisory published)",
                    "Signal quality optimal but update recommended",
                ],
                wireless_info=WirelessLinkTelemetry(
                    signal_rssi_dbm=-62,
                    noise_floor_dbm=-94,
                    snr_db=32,
                    ccq_percent=94.5,
                    tx_rate_mbps=150.0,
                    rx_rate_mbps=150.0,
                    distance_km=1.6,
                    frequency_mhz=5200,
                    channel_width_mhz=20,
                    wireless_mode="Station Client (WDS)",
                ),
                evidence=[
                    EvidenceRecord(
                        source_protocol="TDDP / Pharos Discovery",
                        timestamp="2026-10-19T12:00:30+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="wireless_info",
                        details="Verified TP-Link TDDP discovery broadcast",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MOCK,
                        timestamp="2026-10-19T12:00:00+00:00",
                        confidence=0.60,
                        is_verified_fact=False,
                        attribute="security_notes",
                        details="Heuristic CVE vulnerability correlation",
                    ),
                ],
            ),
            ManagedDevice(
                device_id="SRV-01",
                name="Main Datacenter Server",
                category=DeviceCategory.LINUX_SERVER,
                vendor="Canonical / Linux",
                model="Ubuntu 24.04.1 LTS (Noble Numbat)",
                ip_address="192.168.1.10",
                mac_address="00:15:5D:88:77:66",
                firmware_version="Linux Kernel 6.8.0-generic",
                discovery_protocol="mDNS / Avahi & SSH Protocol",
                security_status=DeviceSecurityStatus.SECURE,
                security_notes=["UFW firewall active", "Fail2ban monitoring SSH port", "Unattended upgrades enabled"],
                evidence=[
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MDNS,
                        timestamp="2026-10-19T12:00:35+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="device_identity",
                        details="Verified mDNS / Avahi service announcement on UDP 5353",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.TLS,
                        timestamp="2026-10-19T12:00:36+00:00",
                        confidence=1.0,
                        is_verified_fact=True,
                        attribute="security_notes",
                        details="Verified TLS X.509 server certificate on port 443",
                    ),
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.HTTP,
                        timestamp="2026-10-19T12:00:37+00:00",
                        confidence=0.70,
                        is_verified_fact=False,
                        attribute="firmware_version",
                        details="Inferred Linux kernel version from Server HTTP response banner",
                    ),
                ],
            ),
        ]

    @classmethod
    def discover_devices(
        cls,
        category_filter: Optional[DeviceCategory] = None,
        use_mock: bool = True,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        scope_guard: Optional[Any] = None,
        mndp_socket_factory: Optional[Any] = None,
        onvif_socket_factory: Optional[Any] = None,
    ) -> VendorDiscoveryReport:
        """Discover and query multi-vendor network hardware and IP surveillance devices.

        When use_mock=True, returns deterministic simulated hardware profiles.
        When use_mock=False, listens passively for broadcast/multicast announcements
        via MNDP and ONVIF WS-Discovery. Never returns simulated devices in live mode.
        """
        if use_mock:
            devices = cls.get_mock_devices()
        else:
            devices = cls._discover_live(
                timeout=timeout,
                interface=interface,
                scope_guard=scope_guard,
                mndp_socket_factory=mndp_socket_factory,
                onvif_socket_factory=onvif_socket_factory,
            )

        if category_filter:
            devices = [d for d in devices if d.category == category_filter]

        category_counts: Dict[str, int] = {}
        for d in devices:
            cat_name = d.category.value
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

        vulnerable_count = sum(
            1
            for d in devices
            if d.security_status
            in (DeviceSecurityStatus.WARNING, DeviceSecurityStatus.CRITICAL)
        )

        return VendorDiscoveryReport(
            total_devices=len(devices),
            category_counts=category_counts,
            devices=devices,
            vulnerable_device_count=vulnerable_count,
        )

    @classmethod
    def _discover_live(
        cls,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        scope_guard: Optional[Any] = None,
        mndp_socket_factory: Optional[Any] = None,
        onvif_socket_factory: Optional[Any] = None,
    ) -> List[ManagedDevice]:
        """Perform passive, read-only listening for MNDP and ONVIF broadcast announcements.

        Strict security invariants:
        - NEVER transmits application packets (no ONVIF Probes, no MNDP queries).
        - Strictly unprivileged execution.
        - Silent network produces an empty result collection (total_devices=0), NEVER fake devices.
        - Applies ScopeGuard authorization policy to sender addresses when configured.
        - Deduplicates MNDP by verified MAC and ONVIF by verified endpoint UUID.
        - Bounded inventory (max 256 devices).
        """
        logger = logging.getLogger("itsa_network_os.vendor_manager")

        # Check interface with scope_guard if configured
        if (
            scope_guard is not None
            and scope_guard.is_configured
            and scope_guard.enclosure
            and scope_guard.enclosure.interfaces
        ):
            if interface is not None and interface not in scope_guard.enclosure.interfaces:
                from itsa_network_os.network.scope import ScopeViolationError

                raise ScopeViolationError(
                    f"Requested interface '{interface}' is not in authorized interfaces: {list(scope_guard.enclosure.interfaces)}"
                )

        mndp_listener = MNDPPassiveListener()
        onvif_listener = ONVIFPassiveListener()

        mndp_observations: List[MNDPObservation] = []
        onvif_observations: List[ONVIFObservation] = []
        listener_errors: List[Exception] = []
        stop_event = threading.Event()

        def listen_mndp() -> None:
            try:
                obs = mndp_listener.listen(
                    timeout=timeout,
                    interface=interface,
                    stop_event=stop_event,
                    socket_factory=mndp_socket_factory,
                )
                mndp_observations.extend(obs)
            except Exception as exc:
                listener_errors.append(exc)

        def listen_onvif() -> None:
            try:
                obs = onvif_listener.listen(
                    timeout=timeout,
                    interface=interface,
                    stop_event=stop_event,
                    socket_factory=onvif_socket_factory,
                )
                onvif_observations.extend(obs)
            except Exception as exc:
                listener_errors.append(exc)

        t_mndp = threading.Thread(
            target=listen_mndp, name="MNDP-Passive-Worker", daemon=True
        )
        t_onvif = threading.Thread(
            target=listen_onvif, name="ONVIF-Passive-Worker", daemon=True
        )

        t_mndp.start()
        t_onvif.start()

        join_timeout = max(0.2, min(float(timeout) + 2.0, 65.0))
        t_mndp.join(timeout=join_timeout)
        t_onvif.join(timeout=join_timeout)

        # Check if mandatory interface filtering error occurred
        for err in listener_errors:
            if isinstance(err, RuntimeError) and "cannot be enforced" in str(err).lower():
                raise err

        discovered_devices: Dict[str, ManagedDevice] = {}
        max_inventory_size = 256

        # Process MNDP observations
        for m_obs in mndp_observations:
            if len(discovered_devices) >= max_inventory_size:
                break

            # Filter sender against authorized ScopeEnclosure if configured
            if scope_guard is not None and scope_guard.is_configured:
                if not scope_guard.is_authorized(
                    m_obs.sender_ip, interface=m_obs.interface
                ):
                    logger.info(
                        "Dropping MNDP observation from unauthorized sender %s",
                        m_obs.sender_ip,
                    )
                    continue

            pkt = m_obs.packet
            mac_clean = (
                (pkt.mac_address or "").replace(":", "").replace("-", "").upper()
            )
            dev_key = (
                f"MNDP:{mac_clean}" if mac_clean else f"MNDP:IP:{m_obs.sender_ip}"
            )

            now_iso = m_obs.timestamp
            rec_fact = EvidenceRecord(
                source_protocol=EvidenceProtocol.MNDP,
                timestamp=now_iso,
                confidence=1.0,
                is_verified_fact=True,
                attribute="packet_reception",
                details=f"Received passive MNDP broadcast on {m_obs.interface or 'default'} from {m_obs.sender_ip}:{m_obs.sender_port}",
            )

            claims: List[EvidenceRecord] = [rec_fact]
            if pkt.board_name:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="model",
                        details=f"Claimed RouterBOARD model: {pkt.board_name}",
                    )
                )
            if pkt.version:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="firmware_version",
                        details=f"Claimed RouterOS version: {pkt.version}",
                    )
                )
            if pkt.identity:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="name",
                        details=f"Claimed router identity: {pkt.identity}",
                    )
                )
            if pkt.mac_address:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.MNDP,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="mac_address",
                        details=f"Claimed hardware MAC: {pkt.mac_address}",
                    )
                )

            if dev_key in discovered_devices:
                existing = discovered_devices[dev_key]
                merged_ev = list(existing.evidence)
                if len(merged_ev) < 20:
                    merged_ev.extend(claims)
                notes = list(existing.security_notes)
                if pkt.identity and pkt.identity != existing.name:
                    notes.append(
                        f"Conflicting identity claim observed: '{pkt.identity}' vs '{existing.name}'"
                    )
                discovered_devices[dev_key] = ManagedDevice(
                    device_id=existing.device_id,
                    name=existing.name,
                    category=existing.category,
                    vendor=existing.vendor,
                    model=existing.model,
                    ip_address=existing.ip_address,
                    mac_address=existing.mac_address,
                    firmware_version=existing.firmware_version,
                    discovery_protocol=existing.discovery_protocol,
                    security_status=existing.security_status,
                    security_notes=notes,
                    router_info=existing.router_info,
                    evidence=merged_ev,
                )
            else:
                dev_id = (
                    f"MIK-{mac_clean[-6:]}"
                    if len(mac_clean) >= 6
                    else f"MIK-{m_obs.sender_ip.replace('.', '_')}"
                )
                dev_name = pkt.identity or f"MikroTik-{pkt.board_name or 'Router'}"
                r_info = RouterOSTelemetry(
                    board_name=pkt.board_name or "RouterBOARD",
                    architecture="Unknown",
                    cpu_load_percent=0,
                    free_memory_mb=0.0,
                    uptime_str=pkt.uptime_formatted,
                    active_interfaces=1,
                    active_leases=0,
                )
                discovered_devices[dev_key] = ManagedDevice(
                    device_id=dev_id,
                    name=dev_name,
                    category=DeviceCategory.MIKROTIK,
                    vendor=pkt.platform or "MikroTik",
                    model=pkt.board_name or "RouterBOARD",
                    ip_address=pkt.ipv4_address or m_obs.sender_ip,
                    mac_address=pkt.mac_address or "",
                    firmware_version=pkt.version or "RouterOS",
                    discovery_protocol="MNDP (MikroTik Discovery UDP 5678)",
                    security_status=DeviceSecurityStatus.SECURE,
                    security_notes=[
                        f"Observed on interface {m_obs.interface or 'default'} via passive MNDP broadcast"
                    ],
                    router_info=r_info,
                    evidence=claims,
                )

        # Process ONVIF observations
        for o_obs in onvif_observations:
            if len(discovered_devices) >= max_inventory_size:
                break

            if scope_guard is not None and scope_guard.is_configured:
                if not scope_guard.is_authorized(
                    o_obs.sender_ip, interface=o_obs.interface
                ):
                    logger.info(
                        "Dropping ONVIF observation from unauthorized sender %s",
                        o_obs.sender_ip,
                    )
                    continue

            msg = o_obs.message
            clean_uuid = (msg.endpoint_uuid or "").replace("urn:uuid:", "").strip()
            dev_key = (
                f"ONVIF:{clean_uuid}"
                if clean_uuid
                else f"ONVIF:IP:{msg.ip_address or o_obs.sender_ip}"
            )

            now_iso = o_obs.timestamp
            rec_fact = EvidenceRecord(
                source_protocol=EvidenceProtocol.ONVIF,
                timestamp=now_iso,
                confidence=1.0,
                is_verified_fact=True,
                attribute="packet_reception",
                details=f"Received passive ONVIF {msg.message_type} on {o_obs.interface or 'default'} from {o_obs.sender_ip}:{o_obs.sender_port}",
            )

            claims = [rec_fact]
            if msg.hardware_model:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ONVIF,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="model",
                        details=f"Claimed camera hardware model: {msg.hardware_model}",
                    )
                )
            if msg.device_name:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ONVIF,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="name",
                        details=f"Claimed camera name: {msg.device_name}",
                    )
                )
            if msg.xaddrs:
                claims.append(
                    EvidenceRecord(
                        source_protocol=EvidenceProtocol.ONVIF,
                        timestamp=now_iso,
                        confidence=0.85,
                        is_verified_fact=False,
                        attribute="xaddrs",
                        details=f"Claimed service endpoints: {', '.join(msg.xaddrs[:3])}",
                    )
                )

            if dev_key in discovered_devices:
                existing = discovered_devices[dev_key]
                merged_ev = list(existing.evidence)
                if len(merged_ev) < 20:
                    merged_ev.extend(claims)
                notes = list(existing.security_notes)
                if msg.message_type == "Bye":
                    notes.append("Device announced departure via WS-Discovery Bye")
                discovered_devices[dev_key] = ManagedDevice(
                    device_id=existing.device_id,
                    name=existing.name,
                    category=existing.category,
                    vendor=existing.vendor,
                    model=existing.model,
                    ip_address=existing.ip_address,
                    mac_address=existing.mac_address,
                    firmware_version=existing.firmware_version,
                    discovery_protocol=existing.discovery_protocol,
                    security_status=existing.security_status,
                    security_notes=notes,
                    camera_info=existing.camera_info,
                    evidence=merged_ev,
                )
            else:
                dev_id = (
                    f"CAM-{clean_uuid[-6:]}"
                    if len(clean_uuid) >= 6
                    else f"CAM-{o_obs.sender_ip.replace('.', '_')}"
                )
                dev_name = (
                    msg.device_name
                    or f"ONVIF Camera ({msg.hardware_model or 'Unknown'})"
                )
                vendor_name = "ONVIF"
                if msg.hardware_model:
                    parts = msg.hardware_model.split()
                    if parts:
                        vendor_name = parts[0]
                cam_info = CameraTelemetry(
                    rtsp_uri=f"rtsp://{msg.ip_address or o_obs.sender_ip}:554/live",
                    onvif_port=msg.port or 80,
                    resolution="1920x1080",
                    codec="H.264/H.265",
                    fps=30,
                    has_default_credentials=False,
                    ptz_supported=any("ptz" in s.lower() for s in msg.scopes),
                )
                notes = [
                    f"Observed on interface {o_obs.interface or 'default'} via passive ONVIF {msg.message_type}"
                ]
                if msg.message_type == "Bye":
                    notes.append("Device announced departure via WS-Discovery Bye")
                discovered_devices[dev_key] = ManagedDevice(
                    device_id=dev_id,
                    name=dev_name,
                    category=DeviceCategory.IP_CAMERA,
                    vendor=vendor_name,
                    model=msg.hardware_model or "Network Video Transmitter",
                    ip_address=msg.ip_address or o_obs.sender_ip,
                    mac_address="",
                    firmware_version=f"WS-Discovery (Metadata v{msg.metadata_version or 1})",
                    discovery_protocol="ONVIF WS-Discovery (UDP 3702)",
                    security_status=DeviceSecurityStatus.SECURE,
                    security_notes=notes,
                    camera_info=cam_info,
                    evidence=claims,
                )

        return list(discovered_devices.values())

