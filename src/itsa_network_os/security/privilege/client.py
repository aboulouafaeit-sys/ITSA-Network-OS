"""Unprivileged client for communicating with privileged packet capture helper."""

from __future__ import annotations

import os
import secrets
import socket
from typing import Any, Dict, List, Optional, Tuple

from itsa_network_os.core.logger import get_logger
from itsa_network_os.security.privilege.protocol import (
    MAX_REQUEST_SIZE,
    MAX_RESPONSE_SIZE,
    OP_CAPTURE_PACKETS,
    OP_GET_CAPABILITIES,
    OP_GET_CAPTURE_RESULTS,
    OP_PING,
    OP_START_CAPTURE,
    OP_STOP_CAPTURE,
    CaptureRequest,
    CaptureResponse,
    CaptureStatus,
    ErrorCode,
    ProtocolError,
    encode_frame,
    read_frame_from_socket,
)

logger = get_logger("itsa_network_os.security.privilege.client")

DEFAULT_HELPER_SOCKET = "/run/itsa-network-os/helper.sock"


class PrivilegedCaptureClient:
    """Unprivileged client interfacing with the privileged helper over Unix domain socket."""

    def __init__(self, socket_path: Optional[str] = None) -> None:
        self.socket_path = socket_path or os.environ.get("ITSA_HELPER_SOCKET", DEFAULT_HELPER_SOCKET)
        self._request_counter = 0
        self._active_session: Optional[Tuple[str, str]] = None

    def _next_request_id(self) -> int:
        self._request_counter += 1
        return self._request_counter

    def is_helper_available(self) -> bool:
        """Check if privileged helper Unix socket is reachable."""
        try:
            return self.ping(timeout=0.5)
        except Exception:
            return False

    def ping(self, timeout: float = 2.0) -> bool:
        """Verify IPC connection and helper responsiveness via OP_PING."""
        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_PING,
        )
        try:
            resp = self._send_request(req, timeout=timeout)
            return resp.status == CaptureStatus.SUCCESS and bool(resp.payload.get("pong"))
        except Exception as exc:
            logger.debug("Helper ping failed: %s", exc)
            return False

    def get_capabilities(self, timeout: float = 2.0) -> Dict[str, Any]:
        """Fetch supported capabilities and operational limits from helper."""
        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_GET_CAPABILITIES,
        )
        resp = self._send_request(req, timeout=timeout)
        if resp.status == CaptureStatus.SUCCESS:
            return resp.payload
        raise RuntimeError(f"Failed to query capabilities: {resp.error_message}")

    def start_capture(
        self,
        interface: str,
        packet_count: int = 10,
        timeout_seconds: float = 5.0,
        filter_expression: Optional[str] = None,
        scope_cidrs: Optional[List[str]] = None,
        timeout: float = 5.0,
    ) -> CaptureResponse:
        """Initiate asynchronous capture session with the privileged helper."""
        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_START_CAPTURE,
            interface=interface,
            packet_count=packet_count,
            timeout_seconds=timeout_seconds,
            filter_expression=filter_expression,
            scope_cidrs=scope_cidrs or [],
        )
        resp = self._send_request(req, timeout=timeout)
        if resp.status == CaptureStatus.SUCCESS:
            sid = resp.payload.get("session_id")
            stok = resp.payload.get("session_token")
            if sid and stok:
                self._active_session = (sid, stok)
        return resp

    def stop_capture(
        self,
        session_id: str,
        session_token: str,
        timeout: float = 2.0,
    ) -> CaptureResponse:
        """Signal cooperative cancellation to a specific capture session."""
        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_STOP_CAPTURE,
            session_id=session_id,
            session_token=session_token,
        )
        return self._send_request(req, timeout=timeout)

    def get_capture_results(
        self,
        session_id: str,
        session_token: str,
        timeout: float = 2.0,
    ) -> CaptureResponse:
        """Retrieve current status or packets from a capture session."""
        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_GET_CAPTURE_RESULTS,
            session_id=session_id,
            session_token=session_token,
        )
        return self._send_request(req, timeout=timeout)

    def capture_packets(
        self,
        interface: str,
        packet_count: int = 10,
        timeout_seconds: float = 5.0,
        filter_expression: Optional[str] = None,
        scope_cidrs: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        session_token: Optional[str] = None,
    ) -> CaptureResponse:
        """Execute bounded packet capture through privileged helper with session tracking."""
        sid = session_id or secrets.token_hex(16)
        stok = session_token or secrets.token_urlsafe(32)
        self._active_session = (sid, stok)

        req = CaptureRequest(
            request_id=self._next_request_id(),
            action=OP_CAPTURE_PACKETS,
            interface=interface,
            packet_count=packet_count,
            timeout_seconds=timeout_seconds,
            filter_expression=filter_expression,
            scope_cidrs=scope_cidrs or [],
            session_id=sid,
            session_token=stok,
        )
        return self._send_request(req, timeout=timeout_seconds + 3.0)

    def cancel_active_capture(self, timeout: float = 2.0) -> bool:
        """Signal cooperative cancellation to the active capture session if tracked."""
        if not self._active_session:
            logger.debug("No active capture session tracked on this client.")
            return False

        sid, tok = self._active_session
        try:
            resp = self.stop_capture(session_id=sid, session_token=tok, timeout=timeout)
            return resp.status == CaptureStatus.SUCCESS
        except Exception as exc:
            logger.warning("Failed to send stop capture signal for session %s: %s", sid, exc)
            return False

    def _send_request(self, request: CaptureRequest, timeout: float) -> CaptureResponse:
        """Establish connection, transmit frame, and await response with strict error handling."""
        if not self.socket_path or not os.path.exists(self.socket_path):
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.SYSTEM_ERROR,
                error_message=f"Helper socket '{self.socket_path}' does not exist or is not running.",
            )

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect(self.socket_path)
            frame_bytes = encode_frame(request.to_dict(), max_size=MAX_REQUEST_SIZE)
            sock.sendall(frame_bytes)

            resp_data = read_frame_from_socket(sock, max_size=MAX_RESPONSE_SIZE)
            return CaptureResponse.from_dict(resp_data)

        except socket.timeout:
            logger.warning("Timeout awaiting response from helper on '%s'", self.socket_path)
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.TIMEOUT,
                error_code=ErrorCode.EXECUTION_TIMEOUT,
                error_message="IPC request to privileged helper timed out.",
            )
        except PermissionError as exc:
            logger.warning("Permission denied connecting to helper socket '%s': %s", self.socket_path, exc)
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.DENIED,
                error_code=ErrorCode.UNAUTHORIZED,
                error_message=f"Permission denied accessing helper socket: {exc}",
            )
        except (ConnectionRefusedError, FileNotFoundError) as exc:
            logger.warning("Unable to connect to helper socket '%s': %s", self.socket_path, exc)
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.SYSTEM_ERROR,
                error_message=f"Unable to connect to privileged helper: {exc}",
            )
        except ProtocolError as exc:
            logger.error("IPC protocol violation with helper: %s", exc)
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.INVALID_SCHEMA,
                error_message=f"Protocol violation: {exc}",
            )
        finally:
            try:
                sock.close()
            except Exception:
                pass
