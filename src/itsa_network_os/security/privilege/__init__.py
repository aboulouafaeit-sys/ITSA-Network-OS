"""Privileged IPC boundary, PolicyKit authorization, and packet capture helper."""

from __future__ import annotations

from itsa_network_os.security.privilege.authorizer import (
    AuthorizationResult,
    MockAuthorizer,
    PolkitAuthorizer,
)
from itsa_network_os.security.privilege.client import PrivilegedCaptureClient
from itsa_network_os.security.privilege.protocol import (
    OP_CAPTURE_PACKETS,
    OP_GET_CAPABILITIES,
    OP_PING,
    OP_STOP_CAPTURE,
    CaptureRequest,
    CaptureResponse,
    CaptureStatus,
    ErrorCode,
    decode_frame,
    encode_frame,
)
from itsa_network_os.security.privilege.server import PrivilegedCaptureServer

__all__ = [
    "AuthorizationResult",
    "MockAuthorizer",
    "PolkitAuthorizer",
    "PrivilegedCaptureClient",
    "PrivilegedCaptureServer",
    "CaptureRequest",
    "CaptureResponse",
    "CaptureStatus",
    "ErrorCode",
    "OP_PING",
    "OP_GET_CAPABILITIES",
    "OP_CAPTURE_PACKETS",
    "OP_STOP_CAPTURE",
    "encode_frame",
    "decode_frame",
]
