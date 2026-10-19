"""MikroTik Neighbor Discovery Protocol (MNDP) pure decoder and passive listener.

MNDP operates over UDP port 5678 (broadcast to 255.255.255.255 or multicast).
This module implements:
1. Pure, deterministic, bounded TLV decoder independent of network sockets.
2. Safe string sanitization and bounds enforcement against malicious or truncated datagrams.
3. Unprivileged passive broadcast listener using standard sockets and IP_PKTINFO interface attribution.
"""

from __future__ import annotations

import ipaddress
import re
import select
import socket
import struct
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# Protocol Constants
MNDP_DEFAULT_PORT = 5678
MNDP_HEADER_SIZE = 4
MNDP_MAX_SAFE_DATAGRAM_SIZE = 65536
MNDP_MAX_SAFE_TLV_LENGTH = 1024
MNDP_MAX_SAFE_STRING_LENGTH = 256

# Documented MNDP TLV Type Identifiers
TLV_MAC_ADDRESS = 0x0001
TLV_IDENTITY = 0x0005
TLV_VERSION = 0x0007
TLV_PLATFORM = 0x0008
TLV_UPTIME = 0x000A
TLV_SOFTWARE_ID = 0x000B
TLV_BOARD_NAME = 0x000C
TLV_UNPACK = 0x000E
TLV_IPV6_ADDRESS = 0x000F
TLV_INTERFACE_NAME = 0x0010
TLV_IPV4_ADDRESS = 0x0011

# Regex to strip unprintable/control characters while preserving printable UTF-8
_CONTROL_CHAR_REGEX = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def sanitize_mndp_string(val: str, max_length: int = MNDP_MAX_SAFE_STRING_LENGTH) -> str:
    """Sanitize decoded strings by stripping control characters and enforcing length bounds."""
    cleaned = _CONTROL_CHAR_REGEX.sub("", val).strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length]
    return cleaned


@dataclass(frozen=True)
class MNDPPacket:
    """Structured representation of a parsed MikroTik MNDP broadcast datagram.

    Attributes:
        mac_address: Colon-separated uppercase 48-bit MAC address (e.g. "48:8F:5A:12:34:56").
        identity: Claimed system identity or router name (e.g. "Core-RB760iGS").
        version: Claimed RouterOS software version (e.g. "7.14.3 (stable)").
        platform: Claimed hardware/software platform (e.g. "MikroTik").
        uptime_seconds: Claimed system uptime in seconds.
        software_id: Claimed software license ID (e.g. "V5NE-8XYZ").
        board_name: Claimed RouterBOARD hardware model (e.g. "RB760iGS", "hEX S").
        interface_name: Claimed transmitting interface name (e.g. "ether1").
        ipv4_address: Claimed primary IPv4 address.
        ipv6_address: Claimed primary IPv6 address.
        unknown_tlvs: Mapping of unrecognized TLV type IDs to raw bytes.
        warnings: List of parser warnings or validation anomalies.
        is_valid: True if header and core fields were parsed successfully.
    """

    mac_address: Optional[str] = None
    identity: Optional[str] = None
    version: Optional[str] = None
    platform: Optional[str] = None
    uptime_seconds: Optional[int] = None
    software_id: Optional[str] = None
    board_name: Optional[str] = None
    interface_name: Optional[str] = None
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    unknown_tlvs: Dict[int, bytes] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    is_valid: bool = True

    @property
    def uptime_formatted(self) -> str:
        """Format uptime seconds into a human-readable duration string."""
        if self.uptime_seconds is None:
            return "Unknown"
        secs = self.uptime_seconds
        days, rem = divmod(secs, 86400)
        hours, rem = divmod(rem, 3600)
        mins, secs = divmod(rem, 60)
        if days > 0:
            return f"{days}d {hours:02d}:{mins:02d}:{secs:02d}"
        return f"{hours:02d}:{mins:02d}:{secs:02d}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize packet to a JSON-compatible dictionary."""
        d = asdict(self)
        d["uptime_formatted"] = self.uptime_formatted
        # Convert raw byte values in unknown_tlvs to hex strings for serialization
        d["unknown_tlvs"] = {f"0x{k:04x}": v.hex() for k, v in self.unknown_tlvs.items()}
        return d


def parse_mndp_packet(data: bytes) -> Optional[MNDPPacket]:
    """Parse raw MNDP datagram bytes into an MNDPPacket.

    Enforces strict buffer boundaries and validates all TLVs:
    - Minimum length: 4 bytes (header).
    - Maximum accepted length: 65536 bytes.
    - Validates TLV boundary against remaining buffer size.
    - Caps individual TLV length at 1024 bytes.
    - Validates MAC length (exactly 6 bytes).
    - Validates uptime length (exactly 4 bytes, uint32 little-endian).
    - Validates IPv4 (4 bytes) and IPv6 (16 bytes).
    - Sanitizes strings defensively and bounds length.
    - Collects unknown TLV types without failing.

    Args:
        data: Raw payload bytes received on UDP port 5678.

    Returns:
        MNDPPacket object if header is present, or None if data is completely invalid.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None

    if len(data) < MNDP_HEADER_SIZE:
        return MNDPPacket(
            is_valid=False,
            warnings=[f"Datagram too short: {len(data)} bytes (minimum {MNDP_HEADER_SIZE})"],
        )

    if len(data) > MNDP_MAX_SAFE_DATAGRAM_SIZE:
        return MNDPPacket(
            is_valid=False,
            warnings=[f"Datagram exceeds maximum safe limit ({len(data)} > {MNDP_MAX_SAFE_DATAGRAM_SIZE})"],
        )

    warnings: List[str] = []
    mac_address: Optional[str] = None
    identity: Optional[str] = None
    version: Optional[str] = None
    platform: Optional[str] = None
    uptime_seconds: Optional[int] = None
    software_id: Optional[str] = None
    board_name: Optional[str] = None
    interface_name: Optional[str] = None
    ipv4_address: Optional[str] = None
    ipv6_address: Optional[str] = None
    unknown_tlvs: Dict[int, bytes] = {}

    # Header is 4 bytes (typically 0x00 0x00 sequence/ttl)
    offset = MNDP_HEADER_SIZE
    payload_len = len(data)

    while offset + 4 <= payload_len:
        tlv_type, tlv_len = struct.unpack_from(">HH", data, offset)
        offset += 4

        # Validate TLV boundary
        if offset + tlv_len > payload_len:
            warnings.append(
                f"Truncated TLV 0x{tlv_type:04x}: declared {tlv_len} bytes, only {payload_len - offset} remaining"
            )
            break

        # Validate maximum TLV length
        if tlv_len > MNDP_MAX_SAFE_TLV_LENGTH:
            warnings.append(
                f"TLV 0x{tlv_type:04x} declared excessive length {tlv_len} > {MNDP_MAX_SAFE_TLV_LENGTH}, skipping"
            )
            offset += tlv_len
            continue

        val_bytes = bytes(data[offset : offset + tlv_len])
        offset += tlv_len

        # Parse known TLVs
        if tlv_type == TLV_MAC_ADDRESS:
            if len(val_bytes) == 6:
                mac_address = ":".join(f"{b:02X}" for b in val_bytes)
            else:
                warnings.append(f"Invalid MAC TLV length: {len(val_bytes)} bytes (expected 6)")

        elif tlv_type == TLV_IDENTITY:
            decoded = val_bytes.decode("utf-8", errors="replace")
            identity = sanitize_mndp_string(decoded)

        elif tlv_type == TLV_VERSION:
            decoded = val_bytes.decode("utf-8", errors="replace")
            version = sanitize_mndp_string(decoded)

        elif tlv_type == TLV_PLATFORM:
            decoded = val_bytes.decode("utf-8", errors="replace")
            platform = sanitize_mndp_string(decoded)

        elif tlv_type == TLV_UPTIME:
            if len(val_bytes) == 4:
                uptime_seconds = struct.unpack("<I", val_bytes)[0]
            else:
                warnings.append(f"Invalid uptime TLV length: {len(val_bytes)} bytes (expected 4)")

        elif tlv_type == TLV_SOFTWARE_ID:
            decoded = val_bytes.decode("utf-8", errors="replace")
            software_id = sanitize_mndp_string(decoded)

        elif tlv_type == TLV_BOARD_NAME:
            decoded = val_bytes.decode("utf-8", errors="replace")
            board_name = sanitize_mndp_string(decoded)

        elif tlv_type == TLV_INTERFACE_NAME:
            decoded = val_bytes.decode("utf-8", errors="replace")
            interface_name = sanitize_mndp_string(decoded, max_length=64)

        elif tlv_type == TLV_IPV4_ADDRESS:
            if len(val_bytes) == 4:
                try:
                    ipv4_address = str(ipaddress.IPv4Address(val_bytes))
                except ValueError as exc:
                    warnings.append(f"Malformed IPv4 address in TLV: {exc}")
            else:
                warnings.append(f"Invalid IPv4 TLV length: {len(val_bytes)} bytes (expected 4)")

        elif tlv_type == TLV_IPV6_ADDRESS:
            if len(val_bytes) == 16:
                try:
                    ipv6_address = str(ipaddress.IPv6Address(val_bytes))
                except ValueError as exc:
                    warnings.append(f"Malformed IPv6 address in TLV: {exc}")
            else:
                warnings.append(f"Invalid IPv6 TLV length: {len(val_bytes)} bytes (expected 16)")

        elif tlv_type == TLV_UNPACK:
            # Documented unpack field; store in unknown_tlvs
            unknown_tlvs[tlv_type] = val_bytes

        else:
            # Preserve unknown TLVs safely
            unknown_tlvs[tlv_type] = val_bytes

    # If buffer had leftover trailing bytes smaller than 4 bytes
    if offset < payload_len:
        warnings.append(f"Ignored {payload_len - offset} trailing malformed bytes at end of datagram")

    return MNDPPacket(
        mac_address=mac_address,
        identity=identity,
        version=version,
        platform=platform,
        uptime_seconds=uptime_seconds,
        software_id=software_id,
        board_name=board_name,
        interface_name=interface_name,
        ipv4_address=ipv4_address,
        ipv6_address=ipv6_address,
        unknown_tlvs=unknown_tlvs,
        warnings=warnings,
        is_valid=True,
    )


def build_mndp_test_packet(
    mac: str = "48:8F:5A:11:22:33",
    identity: str = "MikroTik-Lab-Router",
    version: str = "7.14.3 (stable)",
    platform: str = "MikroTik",
    uptime_seconds: int = 3600,
    software_id: str = "ABCD-1234",
    board_name: str = "RB760iGS",
    interface_name: str = "ether1",
    ipv4: str = "192.168.88.1",
    ipv6: Optional[str] = None,
    extra_tlvs: Optional[Dict[int, bytes]] = None,
) -> bytes:
    """Synthesize a valid MNDP binary payload for deterministic offline testing.

    NEVER transmits on network. Generates bytes in memory only.
    """
    buf = bytearray(b"\x00\x00\x00\x00")  # 4-byte header

    # MAC
    mac_clean = mac.replace(":", "").replace("-", "")
    mac_bytes = bytes.fromhex(mac_clean)
    buf.extend(struct.pack(">HH", TLV_MAC_ADDRESS, len(mac_bytes)))
    buf.extend(mac_bytes)

    # Identity
    ident_bytes = identity.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_IDENTITY, len(ident_bytes)))
    buf.extend(ident_bytes)

    # Version
    ver_bytes = version.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_VERSION, len(ver_bytes)))
    buf.extend(ver_bytes)

    # Platform
    plat_bytes = platform.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_PLATFORM, len(plat_bytes)))
    buf.extend(plat_bytes)

    # Uptime
    uptime_bytes = struct.pack("<I", uptime_seconds)
    buf.extend(struct.pack(">HH", TLV_UPTIME, len(uptime_bytes)))
    buf.extend(uptime_bytes)

    # Software ID
    sw_bytes = software_id.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_SOFTWARE_ID, len(sw_bytes)))
    buf.extend(sw_bytes)

    # Board Name
    board_bytes = board_name.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_BOARD_NAME, len(board_bytes)))
    buf.extend(board_bytes)

    # Interface Name
    iface_bytes = interface_name.encode("utf-8")
    buf.extend(struct.pack(">HH", TLV_INTERFACE_NAME, len(iface_bytes)))
    buf.extend(iface_bytes)

    # IPv4
    if ipv4:
        v4_bytes = ipaddress.IPv4Address(ipv4).packed
        buf.extend(struct.pack(">HH", TLV_IPV4_ADDRESS, len(v4_bytes)))
        buf.extend(v4_bytes)

    # IPv6
    if ipv6:
        v6_bytes = ipaddress.IPv6Address(ipv6).packed
        buf.extend(struct.pack(">HH", TLV_IPV6_ADDRESS, len(v6_bytes)))
        buf.extend(v6_bytes)

    # Extra/Unknown TLVs
    if extra_tlvs:
        for t_id, t_val in extra_tlvs.items():
            buf.extend(struct.pack(">HH", t_id, len(t_val)))
            buf.extend(t_val)

    return bytes(buf)


@dataclass(frozen=True)
class MNDPObservation:
    """An observation event of an MNDP broadcast datagram.

    Attributes:
        packet: Decoded MNDPPacket.
        sender_ip: IP address of the transmitting host.
        sender_port: Port of the transmitting host.
        interface: Receiving interface name if attributed via IP_PKTINFO.
        timestamp: ISO 8601 UTC observation timestamp.
    """

    packet: MNDPPacket
    sender_ip: str
    sender_port: int
    interface: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize observation event to dictionary."""
        return {
            "packet": self.packet.to_dict(),
            "sender_ip": self.sender_ip,
            "sender_port": self.sender_port,
            "interface": self.interface,
            "timestamp": self.timestamp,
        }


class MNDPPassiveListener:
    """Passive unprivileged UDP broadcast listener for MikroTik MNDP on UDP 5678.

    Strict security invariants:
    - NEVER transmits application packets (no send/sendto/sendmsg calls).
    - Operates in unprivileged mode without requiring root or CAP_NET_RAW.
    - Uses bounded receive buffers (max 65536 bytes) and rate limits (max 500 datagrams).
    - Enforces timeout bounds (default 5.0s, range [0.1, 60.0]).
    - Filters by receiving interface via IP_PKTINFO when supported.
    - If interface filtering is requested but IP_PKTINFO/recvmsg is unsupported, fails safely.
    - Clean cancellation support via stop_event.
    - Closes sockets deterministically in finally blocks.
    - Note: Userspace filtering via IP_PKTINFO restricts application processing but does
      not act as a physical kernel firewall.
    """

    def __init__(self, port: int = MNDP_DEFAULT_PORT) -> None:
        self.port = port

    def listen(
        self,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        max_packets: int = 500,
        socket_factory: Optional[Any] = None,
    ) -> List[MNDPObservation]:
        """Listen passively for incoming MNDP datagrams.

        Args:
            timeout: Maximum listening window in seconds (bounded between 0.1 and 60.0).
            interface: Optional local interface name to restrict observations to.
            stop_event: Optional threading event to interrupt listening early.
            max_packets: Upper bound on datagrams processed to prevent flood exhaustion.
            socket_factory: Optional factory callable for deterministic offline unit testing.

        Returns:
            List of valid MNDPObservation records received during the window.
        """
        from itsa_network_os.security.validator import InputValidator

        bounded_timeout = max(0.1, min(float(timeout), 60.0))
        target_iface: Optional[str] = None
        if interface:
            target_iface = InputValidator.validate_interface_name(interface)

        if socket_factory is not None:
            sock = socket_factory(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        pktinfo_supported = False
        observations: List[MNDPObservation] = []

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
                            MNDP_MAX_SAFE_DATAGRAM_SIZE, 1024
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
                        data, addr = sock.recvfrom(MNDP_MAX_SAFE_DATAGRAM_SIZE)
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

                pkt = parse_mndp_packet(data)
                if pkt and pkt.is_valid:
                    observations.append(
                        MNDPObservation(
                            packet=pkt,
                            sender_ip=sender_ip,
                            sender_port=sender_port,
                            interface=recv_iface,
                        )
                    )

        finally:
            try:
                sock.close()
            except Exception:
                pass

        return observations

