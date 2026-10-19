"""ONVIF WS-Discovery pure decoder and passive listener.

WS-Discovery operates over UDP multicast port 3702 (IPv4 239.255.255.250).
This module implements:
1. Pure, deterministic, safe XML parsing for WS-Discovery SOAP messages.
2. Robust rejection of XXE, DTD expansion, and oversized payloads.
3. Multi-namespace support for WS-Discovery 2005 and OASIS 2009 standards.
4. Passive extraction of surveillance camera hardware profiles, scopes, and XAddrs.
5. Zero transmission of WS-Discovery Probe requests.
"""

from __future__ import annotations

import re
import select
import socket
import struct
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

# Maximum safe XML payload size (64 KB)
WS_DISCOVERY_MAX_PAYLOAD_SIZE = 65536
WS_DISCOVERY_PORT = 3702
WS_DISCOVERY_IPV4_MULTICAST = "239.255.255.250"

# Documented WS-Discovery and Addressing Namespaces
NS_WSD_2005 = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
NS_WSD_2009 = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01"
NS_WSA_2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
NS_WSA_2005 = "http://www.w3.org/2005/08/addressing"
NS_SOAP_12 = "http://www.w3.org/2003/05/soap-envelope"
NS_SOAP_11 = "http://schemas.xmlsoap.org/soap/envelope/"

# Regex to detect dangerous DTD / Entity definitions before parsing
_DTD_ENTITY_PATTERN = re.compile(rb"<!(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)

# Regex to validate safe UUID URN format (e.g. urn:uuid:12345678-1234-1234-1234-123456789abc)
_UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Safe permitted URL schemes for XAddrs
_ALLOWED_XADDR_SCHEMES: Set[str] = {"http", "https"}


@dataclass(frozen=True)
class ONVIFDiscoveryMessage:
    """Structured representation of a parsed ONVIF WS-Discovery SOAP datagram.

    Attributes:
        message_type: "Hello", "Bye", "ProbeMatches", or "Unknown".
        endpoint_uuid: Endpoint Reference Address UUID or URN (e.g. "urn:uuid:...").
        types: List of WS-Discovery device type QNames (e.g. "dn:NetworkVideoTransmitter").
        scopes: List of RFC 3986 scope URIs (e.g. "onvif://www.onvif.org/hardware/ModelX").
        xaddrs: List of validated service endpoints (e.g. ["http://192.168.1.100:80/onvif/device_service"]).
        hardware_model: Model name extracted from scope URIs if present.
        device_name: Friendly name extracted from scope URIs if present.
        ip_address: IPv4 address extracted from XAddrs endpoint if present.
        port: TCP port extracted from XAddrs endpoint if present.
        metadata_version: Integer metadata version from message if present.
        warnings: List of parser warnings or validation anomalies.
        is_valid: True if message was successfully parsed without security rejection.
    """

    message_type: str
    endpoint_uuid: Optional[str] = None
    types: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    xaddrs: List[str] = field(default_factory=list)
    hardware_model: Optional[str] = None
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    metadata_version: Optional[int] = None
    warnings: List[str] = field(default_factory=list)
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize discovery message to a JSON-compatible dictionary."""
        return asdict(self)


def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from element tag name (e.g. '{...}Hello' -> 'Hello')."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_ws_discovery(data: bytes) -> Optional[ONVIFDiscoveryMessage]:
    """Parse raw WS-Discovery SOAP XML datagram into an ONVIFDiscoveryMessage.

    Applies strict, defense-in-depth XML sanitization:
    - Payload size cap: rejects datagrams > 64 KB before XML parsing.
    - XXE & Billion-Laughs Defense: rejects any payload containing '<!DOCTYPE' or '<!ENTITY'.
    - ElementTree parsing with zero external network or schema retrieval.
    - Safe extraction and validation of EndpointReference UUID, Types, Scopes, and XAddrs.
    - Bounded string lengths to prevent heap exhaustion.

    Args:
        data: Raw payload bytes received on UDP port 3702.

    Returns:
        ONVIFDiscoveryMessage if parsed, or None if data is completely empty.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None

    clean_bytes = bytes(data).strip()
    if not clean_bytes:
        return None

    # Defense 1: Reject oversized payloads
    if len(clean_bytes) > WS_DISCOVERY_MAX_PAYLOAD_SIZE:
        return ONVIFDiscoveryMessage(
            message_type="Unknown",
            is_valid=False,
            warnings=[f"Payload size {len(clean_bytes)} exceeds maximum safe limit ({WS_DISCOVERY_MAX_PAYLOAD_SIZE})"],
        )

    # Defense 2: XXE / DTD expansion rejection
    if _DTD_ENTITY_PATTERN.search(clean_bytes):
        return ONVIFDiscoveryMessage(
            message_type="Unknown",
            is_valid=False,
            warnings=["Security violation: XML DOCTYPE or ENTITY declaration detected. Payload rejected."],
        )

    # Defense 3: Safe ElementTree XML parsing
    try:
        root = ET.fromstring(clean_bytes)
    except (ET.ParseError, UnicodeDecodeError, ValueError) as exc:
        return ONVIFDiscoveryMessage(
            message_type="Unknown",
            is_valid=False,
            warnings=[f"Malformed XML syntax: {exc}"],
        )

    warnings: List[str] = []
    message_type = "Unknown"
    endpoint_uuid: Optional[str] = None
    types_list: List[str] = []
    scopes_list: List[str] = []
    xaddrs_list: List[str] = []
    metadata_version: Optional[int] = None

    # Locate SOAP Body
    body_elem: Optional[ET.Element] = None
    for child in root:
        if _strip_ns(child.tag).lower() == "body":
            body_elem = child
            break

    # If no Body tag found, inspect root directly
    search_root = body_elem if body_elem is not None else root

    # Identify WS-Discovery action elements
    # Common actions: Hello, Bye, ProbeMatches, Probe (probe should never be transmitted)
    disc_elem: Optional[ET.Element] = None
    for child in search_root:
        tag_name = _strip_ns(child.tag)
        if tag_name in ("Hello", "Bye", "ProbeMatches"):
            message_type = tag_name
            disc_elem = child
            break

    # If action is ProbeMatches, inspect inner ProbeMatch elements
    target_elems: List[ET.Element] = []
    if message_type == "ProbeMatches" and disc_elem is not None:
        for pm in disc_elem:
            if _strip_ns(pm.tag) == "ProbeMatch":
                target_elems.append(pm)
    elif disc_elem is not None:
        target_elems.append(disc_elem)

    for target_elem in target_elems:
        for elem in target_elem:
            local_tag = _strip_ns(elem.tag)

            if local_tag == "EndpointReference":
                # Look for Address inside EndpointReference
                for sub in elem:
                    if _strip_ns(sub.tag) == "Address" and sub.text:
                        raw_addr = sub.text.strip()
                        if len(raw_addr) <= 256:
                            endpoint_uuid = raw_addr
                        else:
                            warnings.append("EndpointReference Address exceeds safe length limit (256 chars)")

            elif local_tag == "Types" and elem.text:
                for t in elem.text.split():
                    t_clean = t.strip()
                    if t_clean and len(t_clean) <= 128:
                        types_list.append(t_clean)

            elif local_tag == "Scopes" and elem.text:
                for s in elem.text.split():
                    s_clean = s.strip()
                    if s_clean and len(s_clean) <= 512:
                        scopes_list.append(s_clean)

            elif local_tag == "XAddrs" and elem.text:
                for x in elem.text.split():
                    x_clean = x.strip()
                    if not x_clean or len(x_clean) > 512:
                        continue
                    try:
                        parsed_url = urllib.parse.urlparse(x_clean)
                        if parsed_url.scheme.lower() in _ALLOWED_XADDR_SCHEMES:
                            xaddrs_list.append(x_clean)
                        else:
                            warnings.append(f"Rejected XAddr with disallowed URI scheme: '{parsed_url.scheme}'")
                    except Exception as u_exc:
                        warnings.append(f"Invalid XAddr URL: {u_exc}")

            elif local_tag == "MetadataVersion" and elem.text:
                try:
                    metadata_version = int(elem.text.strip())
                except ValueError:
                    warnings.append(f"Invalid non-integer MetadataVersion: '{elem.text.strip()}'")

    # Extract hardware model and device name from scopes
    hardware_model: Optional[str] = None
    device_name: Optional[str] = None
    for scope in scopes_list:
        scope_lower = scope.lower()
        if "/hardware/" in scope_lower:
            parts = scope.split("/hardware/", 1)
            if len(parts) == 2 and parts[1]:
                hardware_model = urllib.parse.unquote(parts[1].split("/")[0]).strip()
        elif "/name/" in scope_lower:
            parts = scope.split("/name/", 1)
            if len(parts) == 2 and parts[1]:
                device_name = urllib.parse.unquote(parts[1].split("/")[0]).strip()

    # Extract primary IP and port from the first valid XAddr
    extracted_ip: Optional[str] = None
    extracted_port: Optional[int] = None
    if xaddrs_list:
        try:
            parsed = urllib.parse.urlparse(xaddrs_list[0])
            if parsed.hostname:
                extracted_ip = parsed.hostname
            if parsed.port:
                extracted_port = parsed.port
            elif parsed.scheme == "https":
                extracted_port = 443
            elif parsed.scheme == "http":
                extracted_port = 80
        except Exception:
            pass

    return ONVIFDiscoveryMessage(
        message_type=message_type,
        endpoint_uuid=endpoint_uuid,
        types=types_list,
        scopes=scopes_list,
        xaddrs=xaddrs_list,
        hardware_model=hardware_model,
        device_name=device_name,
        ip_address=extracted_ip,
        port=extracted_port,
        metadata_version=metadata_version,
        warnings=warnings,
        is_valid=True,
    )


def build_ws_discovery_test_xml(
    message_type: str = "Hello",
    endpoint_uuid: str = "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
    types: str = "dn:NetworkVideoTransmitter tds:Device",
    scopes: Optional[str] = None,
    xaddr: str = "http://192.168.1.108:80/onvif/device_service",
    metadata_version: int = 1,
    namespace_variant: str = "2005",
    hardware_model: Optional[str] = None,
    device_name: Optional[str] = None,
) -> bytes:
    """Synthesize a valid WS-Discovery SOAP XML payload for deterministic offline testing.

    NEVER transmits on network. Generates bytes in memory only.
    """
    wsd_ns = NS_WSD_2005 if namespace_variant == "2005" else NS_WSD_2009
    wsa_ns = NS_WSA_2004 if namespace_variant == "2005" else NS_WSA_2005

    if scopes is None:
        model = hardware_model or "DS-2CD2042WD-I"
        name = device_name or "FrontEntrance"
        scopes = f"onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/{model} onvif://www.onvif.org/name/{name}"

    if message_type == "ProbeMatches":
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{NS_SOAP_12}" xmlns:wsa="{wsa_ns}" xmlns:wsd="{wsd_ns}">
  <soap:Header>
    <wsa:Action>{wsd_ns}/ProbeMatches</wsa:Action>
  </soap:Header>
  <soap:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <wsa:EndpointReference>
          <wsa:Address>{endpoint_uuid}</wsa:Address>
        </wsa:EndpointReference>
        <wsd:Types>{types}</wsd:Types>
        <wsd:Scopes>{scopes}</wsd:Scopes>
        <wsd:XAddrs>{xaddr}</wsd:XAddrs>
        <wsd:MetadataVersion>{metadata_version}</wsd:MetadataVersion>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </soap:Body>
</soap:Envelope>"""
    else:
        # Hello or Bye
        xml = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{NS_SOAP_12}" xmlns:wsa="{wsa_ns}" xmlns:wsd="{wsd_ns}">
  <soap:Header>
    <wsa:Action>{wsd_ns}/{message_type}</wsa:Action>
  </soap:Header>
  <soap:Body>
    <wsd:{message_type}>
      <wsa:EndpointReference>
        <wsa:Address>{endpoint_uuid}</wsa:Address>
      </wsa:EndpointReference>
      <wsd:Types>{types}</wsd:Types>
      <wsd:Scopes>{scopes}</wsd:Scopes>
      <wsd:XAddrs>{xaddr}</wsd:XAddrs>
      <wsd:MetadataVersion>{metadata_version}</wsd:MetadataVersion>
    </wsd:{message_type}>
  </soap:Body>
</soap:Envelope>"""

    return xml.encode("utf-8")


@dataclass(frozen=True)
class ONVIFObservation:
    """An observation event of an ONVIF WS-Discovery SOAP datagram.

    Attributes:
        message: Decoded ONVIFDiscoveryMessage.
        sender_ip: IP address of the transmitting host.
        sender_port: Port of the transmitting host.
        interface: Receiving interface name if attributed via IP_PKTINFO.
        timestamp: ISO 8601 UTC observation timestamp.
    """

    message: ONVIFDiscoveryMessage
    sender_ip: str
    sender_port: int
    interface: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize observation event to dictionary."""
        return {
            "message": self.message.to_dict(),
            "sender_ip": self.sender_ip,
            "sender_port": self.sender_port,
            "interface": self.interface,
            "timestamp": self.timestamp,
        }


class ONVIFPassiveListener:
    """Passive unprivileged UDP multicast listener for ONVIF WS-Discovery on UDP 3702.

    Strict security invariants:
    - NEVER transmits application packets (no WS-Discovery Probe requests).
    - Operates in unprivileged mode without requiring root or CAP_NET_RAW.
    - Joins IPv4 multicast group 239.255.255.250 on interface or INADDR_ANY.
    - Uses bounded receive buffers (max 65536 bytes) and rate limits (max 500 datagrams).
    - Enforces timeout bounds (default 5.0s, range [0.1, 60.0]).
    - Filters by receiving interface via IP_PKTINFO when supported.
    - If interface filtering is requested but IP_PKTINFO/recvmsg is unsupported, fails safely.
    - Clean cancellation support via stop_event.
    - Deterministically drops multicast membership and closes socket in finally block.
    - Note: Userspace filtering via IP_PKTINFO restricts application processing but does
      not act as a physical kernel firewall.
    """

    def __init__(
        self,
        port: int = WS_DISCOVERY_PORT,
        multicast_group: str = WS_DISCOVERY_IPV4_MULTICAST,
    ) -> None:
        self.port = port
        self.multicast_group = multicast_group

    def listen(
        self,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        max_packets: int = 500,
        socket_factory: Optional[Any] = None,
    ) -> List[ONVIFObservation]:
        """Listen passively for incoming ONVIF WS-Discovery datagrams.

        Args:
            timeout: Maximum listening window in seconds (bounded between 0.1 and 60.0).
            interface: Optional local interface name to restrict observations to.
            stop_event: Optional threading event to interrupt listening early.
            max_packets: Upper bound on datagrams processed to prevent flood exhaustion.
            socket_factory: Optional factory callable for deterministic offline unit testing.

        Returns:
            List of valid ONVIFObservation records received during the window.
        """
        from itsa_network_os.security.validator import InputValidator

        bounded_timeout = max(0.1, min(float(timeout), 60.0))
        target_iface: Optional[str] = None
        target_ifindex: int = 0
        if interface:
            target_iface = InputValidator.validate_interface_name(interface)
            try:
                target_ifindex = socket.if_nametoindex(target_iface)
            except (OSError, ValueError) as exc:
                raise RuntimeError(
                    f"Interface '{target_iface}' does not exist on host: {exc}"
                ) from exc

        if socket_factory is not None:
            sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        pktinfo_supported = False
        mreq: Optional[bytes] = None
        observations: List[ONVIFObservation] = []

        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                if hasattr(socket, "SO_REUSEPORT"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

            # Enable IP_PKTINFO for interface attribution if supported
            if hasattr(socket, "IP_PKTINFO"):
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
                    pktinfo_supported = True
                except (AttributeError, OSError):
                    pktinfo_supported = False

            # If an interface filter was explicitly requested, verify support
            if target_iface and not pktinfo_supported:
                raise RuntimeError(
                    f"Interface filtering on '{target_iface}' cannot be enforced because "
                    "IP_PKTINFO is unavailable on this platform or socket."
                )

            sock.bind(("", self.port))
            sock.setblocking(False)

            # Join multicast group (ip_mreqn with ifindex if supported, fallback to ip_mreq)
            grp_bytes = socket.inet_aton(self.multicast_group)
            if target_ifindex > 0:
                mreq = struct.pack(
                    "=4s4si", grp_bytes, socket.inet_aton("0.0.0.0"), target_ifindex
                )
            else:
                mreq = struct.pack("=4s4si", grp_bytes, socket.inet_aton("0.0.0.0"), 0)

            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                mreq = struct.pack("4s4s", grp_bytes, socket.inet_aton("0.0.0.0"))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            start_time = time.monotonic()
            packet_count = 0

            while (time.monotonic() - start_time) < bounded_timeout:
                if stop_event is not None and stop_event.is_set():
                    break

                if packet_count >= max_packets:
                    break

                remaining = bounded_timeout - (time.monotonic() - start_time)
                poll_interval = min(0.25, max(0.01, remaining))

                try:
                    rlist, _, _ = select.select([sock], [], [], poll_interval)
                except (select.error, OSError):
                    break

                if not rlist:
                    continue

                recv_iface: Optional[str] = None
                sender_ip: str = ""
                sender_port: int = 0
                data: bytes = b""

                if pktinfo_supported and hasattr(sock, "recvmsg"):
                    try:
                        msg_data, ancdata, flags, addr = sock.recvmsg(
                            WS_DISCOVERY_MAX_PAYLOAD_SIZE, 1024
                        )
                        data = msg_data
                        if addr and len(addr) >= 2:
                            sender_ip = str(addr[0])
                            sender_port = int(addr[1])

                        for cmsg_level, cmsg_type, cmsg_data in ancdata:
                            if (
                                cmsg_level == socket.IPPROTO_IP
                                and cmsg_type == socket.IP_PKTINFO
                            ):
                                if len(cmsg_data) >= 4:
                                    ifindex = struct.unpack("i", cmsg_data[:4])[0]
                                    try:
                                        recv_iface = socket.if_indextoname(ifindex)
                                    except (OSError, ValueError):
                                        recv_iface = None
                    except (BlockingIOError, socket.timeout, InterruptedError):
                        continue
                    except Exception:
                        continue
                else:
                    try:
                        data, addr = sock.recvfrom(WS_DISCOVERY_MAX_PAYLOAD_SIZE)
                        if addr and len(addr) >= 2:
                            sender_ip = str(addr[0])
                            sender_port = int(addr[1])
                    except (BlockingIOError, socket.timeout, InterruptedError):
                        continue
                    except Exception:
                        continue

                packet_count += 1

                # If an interface filter was requested and attribution doesn't match, drop
                if target_iface and recv_iface != target_iface:
                    continue

                msg = parse_ws_discovery(data)
                if msg and msg.is_valid:
                    observations.append(
                        ONVIFObservation(
                            message=msg,
                            sender_ip=sender_ip,
                            sender_port=sender_port,
                            interface=recv_iface,
                        )
                    )

        finally:
            if mreq is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
                except Exception:
                    pass
            try:
                sock.close()
            except Exception:
                pass

        return observations

