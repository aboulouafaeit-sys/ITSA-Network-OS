"""IPC protocol schemas, message framing, and constants for privileged operations."""

from __future__ import annotations

import json
import re
import struct
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION: str = "1.0.0"
POLKIT_ACTION_CAPTURE: str = "org.itsa.networkos.capture"

# Message payload length thresholds
MAX_REQUEST_SIZE: int = 64 * 1024        # 64 KB
MAX_RESPONSE_SIZE: int = 1024 * 1024     # 1 MB

# Bounded operational thresholds
MAX_PACKET_COUNT: int = 50
MIN_PACKET_COUNT: int = 1
MAX_TIMEOUT_SECONDS: float = 10.0
MIN_TIMEOUT_SECONDS: float = 0.1
MAX_SCOPE_CIDRS: int = 16

# Finite operation identifiers
OP_PING = "OP_PING"
OP_GET_CAPABILITIES = "OP_GET_CAPABILITIES"
OP_CAPTURE_PACKETS = "OP_CAPTURE_PACKETS"
OP_START_CAPTURE = "OP_START_CAPTURE"
OP_STOP_CAPTURE = "OP_STOP_CAPTURE"
OP_GET_CAPTURE_RESULTS = "OP_GET_CAPTURE_RESULTS"

VALID_ACTIONS = {
    OP_PING,
    OP_GET_CAPABILITIES,
    OP_CAPTURE_PACKETS,
    OP_START_CAPTURE,
    OP_STOP_CAPTURE,
    OP_GET_CAPTURE_RESULTS,
}

# Strict interface and session name regexes
INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,16}$")
SESSION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")

# Disallowed shell metacharacters in filter expressions
FORBIDDEN_FILTER_CHARS = re.compile(r"[;&|\$`><\\\n\r\t]")


class CaptureStatus(str, Enum):
    """Terminal execution status of an IPC capture operation."""

    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    INVALID_REQUEST = "INVALID_REQUEST"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    ERROR = "ERROR"


class ErrorCode(str, Enum):
    """Structured error taxonomy for IPC communication and policy decisions."""

    INVALID_SCHEMA = "INVALID_SCHEMA"
    UNAUTHORIZED = "UNAUTHORIZED"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    INVALID_INTERFACE = "INVALID_INTERFACE"
    INVALID_FILTER = "INVALID_FILTER"
    EXECUTION_TIMEOUT = "EXECUTION_TIMEOUT"
    CAPTURE_ERROR = "CAPTURE_ERROR"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    INVALID_TOKEN = "INVALID_TOKEN"


class ProtocolError(Exception):
    """Raised on message framing, encoding, or protocol schema violations."""


class MessageTooLargeError(ProtocolError):
    """Raised when message length exceeds maximum allowable frame size."""


@dataclass(frozen=True)
class CaptureRequest:
    """Strongly typed, validated IPC request container."""

    request_id: int
    action: str
    interface: Optional[str] = None
    packet_count: int = 10
    timeout_seconds: float = 5.0
    filter_expression: Optional[str] = None
    scope_cidrs: List[str] = field(default_factory=list)
    session_id: Optional[str] = None
    session_token: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "request_id": self.request_id,
            "action": self.action,
            "interface": self.interface,
            "packet_count": self.packet_count,
            "timeout_seconds": self.timeout_seconds,
            "filter_expression": self.filter_expression,
            "scope_cidrs": list(self.scope_cidrs),
        }
        if self.session_id is not None:
            data["session_id"] = self.session_id
        if self.session_token is not None:
            data["session_token"] = self.session_token
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CaptureRequest:
        return validate_request_dict(data)


@dataclass(frozen=True)
class CaptureResponse:
    """Strongly typed, validated IPC response container."""

    request_id: int
    status: CaptureStatus
    error_code: Optional[ErrorCode] = None
    error_message: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "error_code": self.error_code.value if self.error_code else None,
            "error_message": self.error_message,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CaptureResponse:
        status_raw = data.get("status")
        try:
            status = CaptureStatus(status_raw)
        except (ValueError, TypeError) as exc:
            raise ProtocolError(f"Invalid or missing status field: {status_raw}") from exc

        err_code_raw = data.get("error_code")
        error_code = ErrorCode(err_code_raw) if err_code_raw else None

        return cls(
            request_id=int(data.get("request_id", 0)),
            status=status,
            error_code=error_code,
            error_message=data.get("error_message"),
            payload=data.get("payload", {}) or {},
        )


def validate_request_dict(data: Dict[str, Any]) -> CaptureRequest:
    """Validate raw request dictionary against strict security boundaries and parameter limits."""
    if not isinstance(data, dict):
        raise ProtocolError("Request payload must be a JSON object dictionary.")

    # 1. Request ID validation
    req_id = data.get("request_id")
    if not isinstance(req_id, int) or req_id <= 0:
        raise ProtocolError("Missing or invalid 'request_id'; must be positive integer.")

    # 2. Action validation
    action = data.get("action")
    if not isinstance(action, str) or action not in VALID_ACTIONS:
        raise ProtocolError(f"Invalid or unsupported action '{action}'. Valid actions: {sorted(VALID_ACTIONS)}")

    # 3. Parameters for capture initiation (OP_CAPTURE_PACKETS, OP_START_CAPTURE)
    iface: Optional[str] = None
    pkt_count: int = 10
    timeout_s: float = 5.0
    filter_expr: Optional[str] = None
    scope_cidrs: List[str] = []
    sess_id: Optional[str] = None
    sess_tok: Optional[str] = None

    if action in (OP_CAPTURE_PACKETS, OP_START_CAPTURE):
        raw_iface = data.get("interface")
        if not raw_iface or not isinstance(raw_iface, str) or not INTERFACE_REGEX.match(raw_iface):
            raise ProtocolError(f"Invalid network interface name: '{raw_iface}'")
        iface = raw_iface

        raw_count = data.get("packet_count", 10)
        if not isinstance(raw_count, int) or raw_count < MIN_PACKET_COUNT or raw_count > MAX_PACKET_COUNT:
            raise ProtocolError(f"packet_count must be between {MIN_PACKET_COUNT} and {MAX_PACKET_COUNT}")
        pkt_count = raw_count

        raw_timeout = data.get("timeout_seconds", 5.0)
        if not isinstance(raw_timeout, (int, float)) or raw_timeout < MIN_TIMEOUT_SECONDS or raw_timeout > MAX_TIMEOUT_SECONDS:
            raise ProtocolError(f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}")
        timeout_s = float(raw_timeout)

        raw_filter = data.get("filter_expression")
        if raw_filter is not None:
            if not isinstance(raw_filter, str) or len(raw_filter) > 128:
                raise ProtocolError("filter_expression must be string <= 128 characters.")
            if FORBIDDEN_FILTER_CHARS.search(raw_filter):
                raise ProtocolError("filter_expression contains forbidden shell or metacharacters.")
            from itsa_network_os.security.privilege.filter import FilterSyntaxError, PacketFilter
            try:
                PacketFilter.compile(raw_filter)
            except FilterSyntaxError as exc:
                raise ProtocolError(f"Invalid filter expression: {exc}") from exc
            filter_expr = raw_filter.strip()

        # F-04: Mandatory scope enclosure
        raw_cidrs = data.get("scope_cidrs")
        if raw_cidrs is None:
            raise ProtocolError("Missing mandatory 'scope_cidrs'; packet capture requires an authorized network scope enclosure.")
        if not isinstance(raw_cidrs, list):
            raise ProtocolError("scope_cidrs must be a list of CIDR strings.")
        if len(raw_cidrs) == 0:
            raise ProtocolError("scope_cidrs cannot be empty; at least one authorized CIDR network is required.")
        if len(raw_cidrs) > MAX_SCOPE_CIDRS:
            raise ProtocolError(f"scope_cidrs exceeds maximum allowed limit of {MAX_SCOPE_CIDRS} networks.")

        from itsa_network_os.security.validator import InputValidator, SecurityValidationError
        for c in raw_cidrs:
            if not isinstance(c, str) or not c.strip():
                raise ProtocolError("scope_cidrs entries must be non-empty strings.")
            clean_c = c.strip()
            try:
                InputValidator.validate_ip_network(clean_c)
            except SecurityValidationError as exc:
                raise ProtocolError(f"Invalid CIDR in scope_cidrs '{clean_c}': {exc}") from exc
            scope_cidrs.append(clean_c)

        # Optional client-supplied session identity
        raw_sid = data.get("session_id")
        if raw_sid is not None:
            if not isinstance(raw_sid, str) or not SESSION_ID_REGEX.match(raw_sid):
                raise ProtocolError(f"Invalid session_id: '{raw_sid}'")
            sess_id = raw_sid

        raw_tok = data.get("session_token")
        if raw_tok is not None:
            if not isinstance(raw_tok, str) or len(raw_tok) < 1 or len(raw_tok) > 128:
                raise ProtocolError("Invalid session_token length.")
            sess_tok = raw_tok

    # 4. Parameters for session control (OP_STOP_CAPTURE, OP_GET_CAPTURE_RESULTS)
    elif action in (OP_STOP_CAPTURE, OP_GET_CAPTURE_RESULTS):
        raw_sid = data.get("session_id")
        if not raw_sid or not isinstance(raw_sid, str) or not SESSION_ID_REGEX.match(raw_sid):
            raise ProtocolError("Missing or invalid 'session_id'")
        sess_id = raw_sid

        raw_tok = data.get("session_token")
        if not raw_tok or not isinstance(raw_tok, str) or len(raw_tok) < 1 or len(raw_tok) > 128:
            raise ProtocolError("Missing or invalid 'session_token'")
        sess_tok = raw_tok

    return CaptureRequest(
        request_id=req_id,
        action=action,
        interface=iface,
        packet_count=pkt_count,
        timeout_seconds=timeout_s,
        filter_expression=filter_expr,
        scope_cidrs=scope_cidrs,
        session_id=sess_id,
        session_token=sess_tok,
    )


def encode_frame(data: Dict[str, Any], max_size: int = MAX_RESPONSE_SIZE) -> bytes:
    """Encode dictionary into length-prefixed big-endian JSON frame with bounded maximum size."""
    payload_bytes = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    payload_len = len(payload_bytes)
    if payload_len > max_size:
        raise MessageTooLargeError(f"Frame length {payload_len} exceeds maximum size {max_size}")

    return struct.pack("!I", payload_len) + payload_bytes


def decode_frame_from_bytes(data: bytes, max_size: int = MAX_REQUEST_SIZE) -> tuple[Dict[str, Any], int]:
    """Decode a single length-prefixed frame from a byte buffer.

    Returns:
        tuple[Dict[str, Any], int]: (parsed_dict, bytes_consumed)
    """
    if len(data) < 4:
        raise ValueError("Buffer contains less than 4 bytes for length prefix.")

    payload_len = struct.unpack("!I", data[:4])[0]
    if payload_len > max_size:
        raise MessageTooLargeError(f"Incoming frame length {payload_len} exceeds limit of {max_size} bytes.")
    if payload_len == 0:
        raise ProtocolError("Incoming frame length is 0 (empty payload).")

    if len(data) < 4 + payload_len:
        raise ValueError(f"Incomplete frame: requires {4 + payload_len} bytes, got {len(data)}")

    payload_bytes = data[4 : 4 + payload_len]
    try:
        decoded_obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError(f"Malformed JSON in frame: {exc}") from exc

    return decoded_obj, 4 + payload_len


decode_frame = decode_frame_from_bytes


def read_frame_from_socket(sock: Any, max_size: int = MAX_REQUEST_SIZE) -> Dict[str, Any]:
    """Read a single length-prefixed frame synchronously from a socket."""
    # 1. Read 4-byte length prefix
    header = _read_exact(sock, 4)
    if not header:
        raise EOFError("Socket closed while reading frame length prefix.")

    payload_len = struct.unpack("!I", header)[0]
    if payload_len > max_size:
        raise MessageTooLargeError(f"Incoming frame length {payload_len} exceeds limit of {max_size} bytes.")
    if payload_len == 0:
        raise ProtocolError("Incoming frame length is 0 (empty payload).")

    # 2. Read full payload
    payload = _read_exact(sock, payload_len)
    if len(payload) < payload_len:
        raise EOFError("Socket closed prematurely while reading frame payload.")

    try:
        return json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ProtocolError(f"Malformed JSON payload: {exc}") from exc


def _read_exact(sock: Any, num_bytes: int) -> bytes:
    """Helper reading exactly num_bytes from a socket."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)
