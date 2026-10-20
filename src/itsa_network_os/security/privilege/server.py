"""Privileged IPC server executing bounded packet capture under PolicyKit authorization."""

from __future__ import annotations

import hmac
import os
import select
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from itsa_network_os.core.logger import get_logger
from itsa_network_os.network.scope import ScopeEnclosure, ScopeGuard, ScopeViolationError
from itsa_network_os.security.lab import EducationalPacketLab, ParsedPacket
from itsa_network_os.security.privilege.authorizer import (
    AuthorizationResult,
    BaseAuthorizer,
    PolkitAuthorizer,
)
from itsa_network_os.security.privilege.dissector import PacketDissector
from itsa_network_os.security.privilege.filter import FilterSyntaxError, PacketFilter
from itsa_network_os.security.privilege.protocol import (
    MAX_PACKET_COUNT,
    MAX_REQUEST_SIZE,
    MAX_RESPONSE_SIZE,
    MAX_TIMEOUT_SECONDS,
    OP_CAPTURE_PACKETS,
    OP_GET_CAPABILITIES,
    OP_GET_CAPTURE_RESULTS,
    OP_PING,
    OP_START_CAPTURE,
    OP_STOP_CAPTURE,
    POLKIT_ACTION_CAPTURE,
    PROTOCOL_VERSION,
    CaptureRequest,
    CaptureResponse,
    CaptureStatus,
    ErrorCode,
    MessageTooLargeError,
    ProtocolError,
    encode_frame,
    read_frame_from_socket,
    validate_request_dict,
)
from itsa_network_os.security.validator import InputValidator, SecurityValidationError

logger = get_logger("itsa_network_os.security.privilege.server")

# Linux socket credential option
SO_PEERCRED = 17


class PeerCredentialError(SecurityValidationError):
    """Raised when peer credentials cannot be securely extracted or are invalid."""


def get_socket_peer_credentials(sock: socket.socket) -> Tuple[int, int, int]:
    """Retrieve verified peer credentials (PID, UID, GID) from a Linux Unix domain socket.

    Fails closed if credentials cannot be extracted or are invalid.
    Never falls back to helper EUID.

    Returns:
        Tuple[int, int, int]: (pid, uid, gid)

    Raises:
        PeerCredentialError: If SO_PEERCRED fails, is unsupported, or returns invalid data.
    """
    if not hasattr(socket, "SOL_SOCKET"):
        raise PeerCredentialError("SOL_SOCKET is not supported on this platform.")

    try:
        creds_size = struct.calcsize("3i")
        creds = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, creds_size)
        if not creds or len(creds) != creds_size:
            raise PeerCredentialError(
                f"SO_PEERCRED returned invalid byte length ({len(creds) if creds else 0} != {creds_size})"
            )
        pid, uid, gid = struct.unpack("3i", creds)
    except (OSError, struct.error, AttributeError) as exc:
        raise PeerCredentialError(f"Failed to retrieve socket peer credentials: {exc}") from exc

    if pid <= 0:
        raise PeerCredentialError(f"Invalid peer PID: {pid} (must be > 0)")
    if uid < 0:
        raise PeerCredentialError(f"Invalid peer UID: {uid} (must be >= 0)")
    if gid < 0:
        raise PeerCredentialError(f"Invalid peer GID: {gid} (must be >= 0)")

    return pid, uid, gid


class SessionStatus(str, Enum):
    """Lifecycle status of an active or recent capture session."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    FAILED = "FAILED"


@dataclass
class CaptureSession:
    """Tracked server-side packet capture session with dedicated cancellation and capability token."""

    session_id: str
    session_token: str
    owner_uid: int
    owner_pid: int
    interface: str
    packet_count: int
    timeout_seconds: float
    filter_expr: Optional[str]
    scope_cidrs: List[str]
    created_at: float = field(default_factory=time.monotonic)
    cancellation_event: threading.Event = field(default_factory=threading.Event)
    completion_event: threading.Event = field(default_factory=threading.Event)
    status: SessionStatus = SessionStatus.ACTIVE
    error_message: Optional[str] = None
    captured_packets: List[Dict[str, Any]] = field(default_factory=list)
    worker_thread: Optional[threading.Thread] = None
    lock: threading.Lock = field(default_factory=threading.Lock)
    raw_sock: Optional[socket.socket] = None


class SessionRegistry:
    """Thread-safe registry managing active capture sessions and enforcing capability-based ownership."""

    def __init__(self, max_active_sessions: int = 16, retention_seconds: float = 30.0) -> None:
        self._sessions: Dict[str, CaptureSession] = {}
        self._lock = threading.Lock()
        self._max_active_sessions = max_active_sessions
        self._retention_seconds = retention_seconds

    def register(self, session: CaptureSession) -> None:
        """Register a new capture session, enforcing max active session bounds."""
        with self._lock:
            self._prune_expired_locked()
            active_count = sum(1 for s in self._sessions.values() if s.status == SessionStatus.ACTIVE)
            if active_count >= self._max_active_sessions:
                raise RuntimeError(f"Maximum concurrent capture sessions ({self._max_active_sessions}) reached.")
            self._sessions[session.session_id] = session

    def get(self, session_id: str) -> Optional[CaptureSession]:
        """Lookup session by session_id."""
        with self._lock:
            return self._sessions.get(session_id)

    def cancel_session(
        self,
        session_id: str,
        session_token: str,
        caller_uid: int,
        is_admin: bool = False,
    ) -> Tuple[bool, str, Optional[CaptureSession]]:
        """Validate ownership and capability token, then trigger session cancellation.

        Returns:
            Tuple[bool, str, Optional[CaptureSession]]: (success, result_code, session)
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False, "SESSION_NOT_FOUND", None

        with session.lock:
            # 1. UID ownership check (unless caller is explicitly verified admin)
            if not is_admin and caller_uid != session.owner_uid:
                return False, "UNAUTHORIZED_OWNER", session

            # 2. Capability token check using constant-time comparison
            if not hmac.compare_digest(session_token.strip(), session.session_token):
                return False, "INVALID_TOKEN", session

            # 3. Idempotent cancellation if already terminal
            if session.status != SessionStatus.ACTIVE:
                return True, "ALREADY_TERMINAL", session

            # 4. Trigger dedicated cancellation
            session.cancellation_event.set()
            session.status = SessionStatus.CANCELLED
            if session.raw_sock is not None:
                try:
                    session.raw_sock.close()
                except Exception:
                    pass
            return True, "CANCELLED", session

    def remove(self, session_id: str) -> Optional[CaptureSession]:
        """Remove session from registry."""
        with self._lock:
            return self._sessions.pop(session_id, None)

    def shutdown_all(self) -> None:
        """Cancel all active sessions and join worker threads cleanly."""
        with self._lock:
            sessions = list(self._sessions.values())

        for session in sessions:
            with session.lock:
                session.cancellation_event.set()
                if session.raw_sock is not None:
                    try:
                        session.raw_sock.close()
                    except Exception:
                        pass

        for session in sessions:
            if session.worker_thread and session.worker_thread.is_alive():
                session.worker_thread.join(timeout=1.0)

        with self._lock:
            self._sessions.clear()

    def _prune_expired_locked(self) -> None:
        now = time.monotonic()
        expired = [
            sid
            for sid, s in self._sessions.items()
            if s.status != SessionStatus.ACTIVE and (now - s.created_at) > self._retention_seconds
        ]
        for sid in expired:
            self._sessions.pop(sid, None)


class PrivilegedCaptureServer:
    """Privileged backend server listening on an isolated Unix domain socket."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        authorizer: Optional[BaseAuthorizer] = None,
        use_synthetic_capture: bool = False,
        credential_extractor: Optional[Callable[[socket.socket], Tuple[int, int, int]]] = None,
    ) -> None:
        self.socket_path = socket_path
        self.authorizer: BaseAuthorizer = authorizer or PolkitAuthorizer()
        self.use_synthetic_capture = use_synthetic_capture
        self._credential_extractor = credential_extractor or get_socket_peer_credentials

        self.session_registry = SessionRegistry()
        self._server_sock: Optional[socket.socket] = None
        self._is_running = False
        self._lock = threading.Lock()
        self._client_threads: List[threading.Thread] = []

    def start_socket(self) -> None:
        """Bind and listen on the configured Unix domain socket."""
        if not self.socket_path:
            raise ValueError("socket_path must be specified to start listening socket.")

        parent_dir = os.path.dirname(self.socket_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, mode=0o700, exist_ok=True)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(self.socket_path)
        try:
            os.chmod(self.socket_path, 0o600)
        except OSError:
            pass

        server_sock.listen(10)
        server_sock.settimeout(0.5)
        self._server_sock = server_sock
        self._is_running = True
        logger.info("Privileged helper listening on Unix socket: %s", self.socket_path)

    def handle_connection_threaded(self, client_sock: socket.socket) -> threading.Thread:
        """Spawn a daemon thread to handle an accepted client connection concurrently."""
        t = threading.Thread(
            target=self.handle_client_connection,
            args=(client_sock,),
            daemon=True,
        )
        t.start()
        with self._lock:
            self._client_threads = [th for th in self._client_threads if th.is_alive()]
            self._client_threads.append(t)
        return t

    def handle_client_connection(self, client_sock: socket.socket) -> None:
        """Handle an incoming client connection with peer credential checks and bounded execution."""
        try:
            client_sock.settimeout(12.0)

            # 1. Fail-closed Peer Credential Extraction
            try:
                pid, uid, gid = self._credential_extractor(client_sock)
            except PeerCredentialError as exc:
                logger.warning("Peer credential extraction failed: %s", exc)
                err_resp = CaptureResponse(
                    request_id=0,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.UNAUTHORIZED,
                    error_message=f"Peer credential verification failed: {exc}",
                )
                self._send_response(client_sock, err_resp)
                return

            logger.info("Client connection verified: PID=%d, UID=%d, GID=%d", pid, uid, gid)

            # 2. Read request frame
            try:
                raw_data = read_frame_from_socket(client_sock, max_size=MAX_REQUEST_SIZE)
            except (MessageTooLargeError, ProtocolError, EOFError) as exc:
                logger.warning("Rejected invalid client frame: %s", exc)
                err_resp = CaptureResponse(
                    request_id=0,
                    status=CaptureStatus.INVALID_REQUEST,
                    error_code=ErrorCode.INVALID_SCHEMA,
                    error_message=str(exc),
                )
                self._send_response(client_sock, err_resp)
                return

            # 3. Validate request schema
            try:
                request = validate_request_dict(raw_data)
            except ProtocolError as exc:
                logger.warning("Request schema validation failed: %s", exc)
                err_resp = CaptureResponse(
                    request_id=raw_data.get("request_id", 0) if isinstance(raw_data, dict) else 0,
                    status=CaptureStatus.INVALID_REQUEST,
                    error_code=ErrorCode.INVALID_SCHEMA,
                    error_message=str(exc),
                )
                self._send_response(client_sock, err_resp)
                return

            # 4. PolicyKit Authorization Check
            auth_result = self.authorizer.check_authorization(
                action_id=POLKIT_ACTION_CAPTURE,
                pid=pid,
                uid=uid,
                allow_user_interaction=False,
            )

            if auth_result != AuthorizationResult.AUTHORIZED:
                logger.warning("Client PID=%d, UID=%d denied authorization for action '%s'", pid, uid, request.action)
                err_resp = CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.UNAUTHORIZED,
                    error_message=f"PolicyKit authorization denied for UID {uid}.",
                )
                self._send_response(client_sock, err_resp)
                return

            # 5. Dispatch Operation
            response = self.dispatch_request(request, caller_uid=uid, caller_pid=pid)
            self._send_response(client_sock, response)

        except Exception as exc:
            logger.error("Unhandled error servicing client connection: %s", exc, exc_info=True)
            err_resp = CaptureResponse(
                request_id=0,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.SYSTEM_ERROR,
                error_message="Internal helper exception occurred.",
            )
            try:
                self._send_response(client_sock, err_resp)
            except Exception:
                pass
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def dispatch_request(
        self,
        request: CaptureRequest,
        caller_uid: int = 1000,
        caller_pid: int = 1,
    ) -> CaptureResponse:
        """Process validated CaptureRequest under strict boundary constraints."""
        if request.action == OP_PING:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SUCCESS,
                payload={"pong": True, "version": PROTOCOL_VERSION, "timestamp": time.time()},
            )

        if request.action == OP_GET_CAPABILITIES:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SUCCESS,
                payload={
                    "version": PROTOCOL_VERSION,
                    "capabilities": ["CAP_NET_RAW"],
                    "operations": [
                        OP_PING,
                        OP_GET_CAPABILITIES,
                        OP_CAPTURE_PACKETS,
                        OP_START_CAPTURE,
                        OP_STOP_CAPTURE,
                        OP_GET_CAPTURE_RESULTS,
                    ],
                    "max_packet_count": MAX_PACKET_COUNT,
                    "max_timeout_seconds": MAX_TIMEOUT_SECONDS,
                },
            )

        if request.action == OP_START_CAPTURE:
            return self._handle_start_capture(request, caller_uid=caller_uid, caller_pid=caller_pid)

        if request.action == OP_STOP_CAPTURE:
            return self._handle_stop_capture(request, caller_uid=caller_uid)

        if request.action == OP_GET_CAPTURE_RESULTS:
            return self._handle_get_capture_results(request, caller_uid=caller_uid)

        if request.action == OP_CAPTURE_PACKETS:
            return self._execute_packet_capture(request, caller_uid=caller_uid, caller_pid=caller_pid)

        return CaptureResponse(
            request_id=request.request_id,
            status=CaptureStatus.INVALID_REQUEST,
            error_code=ErrorCode.INVALID_SCHEMA,
            error_message=f"Unrecognized action '{request.action}'",
        )

    def _handle_start_capture(
        self,
        request: CaptureRequest,
        caller_uid: int,
        caller_pid: int,
    ) -> CaptureResponse:
        """Initiate asynchronous capture session with capability token generation."""
        if not request.interface:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_INTERFACE,
                error_message="Interface parameter is mandatory for packet capture.",
            )

        try:
            clean_iface = InputValidator.validate_interface_name(request.interface)
        except SecurityValidationError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_INTERFACE,
                error_message=str(exc),
            )

        # Mandatory Scope Validation
        if not request.scope_cidrs:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SCOPE_VIOLATION,
                error_code=ErrorCode.SCOPE_VIOLATION,
                error_message="Mandatory scope_cidrs is missing or empty.",
            )

        try:
            enclosure = ScopeEnclosure.from_strings(
                cidrs=request.scope_cidrs,
                interfaces=[clean_iface],
                allow_loopback=True,
                allow_global_internet=False,
            )
            scope_guard = ScopeGuard(enclosure)
        except (SecurityValidationError, ScopeViolationError) as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SCOPE_VIOLATION,
                error_code=ErrorCode.SCOPE_VIOLATION,
                error_message=f"Scope violation: {exc}",
            )

        # Filter Compilation
        try:
            packet_filter = PacketFilter.compile(request.filter_expression)
        except FilterSyntaxError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_FILTER,
                error_message=str(exc),
            )

        session_id = request.session_id or secrets.token_hex(16)
        session_token = request.session_token or secrets.token_urlsafe(32)

        session = CaptureSession(
            session_id=session_id,
            session_token=session_token,
            owner_uid=caller_uid,
            owner_pid=caller_pid,
            interface=clean_iface,
            packet_count=min(request.packet_count, MAX_PACKET_COUNT),
            timeout_seconds=min(request.timeout_seconds, MAX_TIMEOUT_SECONDS),
            filter_expr=request.filter_expression,
            scope_cidrs=request.scope_cidrs,
        )

        try:
            self.session_registry.register(session)
        except RuntimeError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.SYSTEM_ERROR,
                error_message=str(exc),
            )

        # Spawn asynchronous worker thread for this session
        worker = threading.Thread(
            target=self._run_session_worker,
            args=(session, clean_iface, scope_guard, packet_filter),
            daemon=True,
        )
        session.worker_thread = worker
        worker.start()

        return CaptureResponse(
            request_id=request.request_id,
            status=CaptureStatus.SUCCESS,
            payload={
                "session_id": session_id,
                "session_token": session_token,
                "interface": clean_iface,
                "packet_count": session.packet_count,
                "timeout_seconds": session.timeout_seconds,
            },
        )

    def _handle_stop_capture(self, request: CaptureRequest, caller_uid: int) -> CaptureResponse:
        """Cancel capture session after verifying session identifier and capability token."""
        if not request.session_id or not request.session_token:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_SCHEMA,
                error_message="Both 'session_id' and 'session_token' are required to stop capture.",
            )

        success, result_code, session = self.session_registry.cancel_session(
            session_id=request.session_id,
            session_token=request.session_token,
            caller_uid=caller_uid,
        )

        if not success:
            if result_code == "SESSION_NOT_FOUND":
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.INVALID_REQUEST,
                    error_code=ErrorCode.SESSION_NOT_FOUND,
                    error_message=f"Session '{request.session_id}' not found or already pruned.",
                )
            if result_code == "UNAUTHORIZED_OWNER":
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.UNAUTHORIZED,
                    error_message=f"Caller UID {caller_uid} is not authorized to cancel this session.",
                )
            if result_code == "INVALID_TOKEN":
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.INVALID_TOKEN,
                    error_message="Invalid session capability token.",
                )

        return CaptureResponse(
            request_id=request.request_id,
            status=CaptureStatus.SUCCESS,
            payload={"session_id": request.session_id, "cancelled": True},
        )

    def _handle_get_capture_results(self, request: CaptureRequest, caller_uid: int) -> CaptureResponse:
        """Query status and retrieve captured packets for a session."""
        if not request.session_id or not request.session_token:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_SCHEMA,
                error_message="Both 'session_id' and 'session_token' are required.",
            )

        session = self.session_registry.get(request.session_id)
        if session is None:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.SESSION_NOT_FOUND,
                error_message=f"Session '{request.session_id}' not found.",
            )

        with session.lock:
            if caller_uid != session.owner_uid:
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.UNAUTHORIZED,
                    error_message=f"Caller UID {caller_uid} is not authorized to access session results.",
                )

            if not hmac.compare_digest(request.session_token.strip(), session.session_token):
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.DENIED,
                    error_code=ErrorCode.INVALID_TOKEN,
                    error_message="Invalid session capability token.",
                )

            if session.status == SessionStatus.ACTIVE:
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.SUCCESS,
                    payload={
                        "session_id": session.session_id,
                        "active": True,
                        "packets_captured": len(session.captured_packets),
                    },
                )

            term_status = (
                CaptureStatus.CANCELLED
                if session.status == SessionStatus.CANCELLED
                else CaptureStatus.SUCCESS
            )
            return CaptureResponse(
                request_id=request.request_id,
                status=term_status,
                payload={
                    "session_id": session.session_id,
                    "active": False,
                    "status": session.status.value,
                    "packets": list(session.captured_packets),
                    "packets_captured": len(session.captured_packets),
                    "error_message": session.error_message,
                },
            )

    def _execute_packet_capture(
        self,
        request: CaptureRequest,
        caller_uid: int,
        caller_pid: int,
    ) -> CaptureResponse:
        """Execute bounded packet capture with synchronous wait and registered session tracking."""
        if not request.interface:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_INTERFACE,
                error_message="Interface parameter is mandatory for packet capture.",
            )

        try:
            clean_iface = InputValidator.validate_interface_name(request.interface)
        except SecurityValidationError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_INTERFACE,
                error_message=str(exc),
            )

        # F-04: Mandatory Scope Boundary Check
        if not request.scope_cidrs:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SCOPE_VIOLATION,
                error_code=ErrorCode.SCOPE_VIOLATION,
                error_message="Mandatory scope_cidrs is missing or empty.",
            )

        try:
            enclosure = ScopeEnclosure.from_strings(
                cidrs=request.scope_cidrs,
                interfaces=[clean_iface],
                allow_loopback=True,
                allow_global_internet=False,
            )
            scope_guard = ScopeGuard(enclosure)
        except (SecurityValidationError, ScopeViolationError) as exc:
            logger.warning("Scope enclosure rejected: %s", exc)
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SCOPE_VIOLATION,
                error_code=ErrorCode.SCOPE_VIOLATION,
                error_message=f"Scope violation: {exc}",
            )

        # F-03: Filter compilation
        try:
            packet_filter = PacketFilter.compile(request.filter_expression)
        except FilterSyntaxError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.INVALID_REQUEST,
                error_code=ErrorCode.INVALID_FILTER,
                error_message=str(exc),
            )

        # F-01: Session tracking
        session_id = request.session_id or secrets.token_hex(16)
        session_token = request.session_token or secrets.token_urlsafe(32)

        session = CaptureSession(
            session_id=session_id,
            session_token=session_token,
            owner_uid=caller_uid,
            owner_pid=caller_pid,
            interface=clean_iface,
            packet_count=min(request.packet_count, MAX_PACKET_COUNT),
            timeout_seconds=min(request.timeout_seconds, MAX_TIMEOUT_SECONDS),
            filter_expr=request.filter_expression,
            scope_cidrs=request.scope_cidrs,
        )

        try:
            self.session_registry.register(session)
        except RuntimeError as exc:
            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.ERROR,
                error_code=ErrorCode.SYSTEM_ERROR,
                error_message=str(exc),
            )

        start_time = time.monotonic()
        self._capture_loop(session, clean_iface, scope_guard, packet_filter)
        elapsed = round(time.monotonic() - start_time, 3)

        with session.lock:
            if session.status == SessionStatus.CANCELLED:
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.CANCELLED,
                    payload={
                        "session_id": session_id,
                        "packets": list(session.captured_packets),
                        "packets_captured": len(session.captured_packets),
                        "duration_seconds": elapsed,
                        "interface": clean_iface,
                    },
                )

            if session.status == SessionStatus.FAILED:
                return CaptureResponse(
                    request_id=request.request_id,
                    status=CaptureStatus.ERROR,
                    error_code=ErrorCode.CAPTURE_ERROR,
                    error_message=session.error_message or "Capture operation failed.",
                )

            return CaptureResponse(
                request_id=request.request_id,
                status=CaptureStatus.SUCCESS,
                payload={
                    "session_id": session_id,
                    "packets": list(session.captured_packets),
                    "packets_captured": len(session.captured_packets),
                    "duration_seconds": elapsed,
                    "interface": clean_iface,
                },
            )

    def _run_session_worker(
        self,
        session: CaptureSession,
        clean_iface: str,
        scope_guard: ScopeGuard,
        packet_filter: PacketFilter,
    ) -> None:
        """Worker thread entry point for asynchronous capture sessions."""
        self._capture_loop(session, clean_iface, scope_guard, packet_filter)

    def _capture_loop(
        self,
        session: CaptureSession,
        clean_iface: str,
        scope_guard: ScopeGuard,
        packet_filter: PacketFilter,
    ) -> None:
        """Internal capture loop servicing a CaptureSession under filter and scope enforcement."""
        deadline = session.created_at + session.timeout_seconds

        # 1. Check for immediate cancellation
        if session.cancellation_event.is_set():
            with session.lock:
                session.status = SessionStatus.CANCELLED
            session.completion_event.set()
            return

        if self.use_synthetic_capture or not hasattr(socket, "AF_PACKET"):
            # Synthetic offline capture
            sample_trace = EducationalPacketLab.get_sample_trace()
            for pkt in sample_trace:
                if session.cancellation_event.is_set():
                    break
                if time.monotonic() >= deadline:
                    break

                # F-03: Filter check
                if not packet_filter.matches(pkt):
                    continue

                # F-04: Scope check
                src_ip = pkt.src.split(":")[0] if pkt.src else None
                dst_ip = pkt.dst.split(":")[0] if pkt.dst else None
                if not src_ip and not dst_ip:
                    continue

                in_scope = False
                if src_ip and scope_guard.is_authorized(src_ip, interface=clean_iface):
                    in_scope = True
                elif dst_ip and scope_guard.is_authorized(dst_ip, interface=clean_iface):
                    in_scope = True

                if not in_scope:
                    continue

                with session.lock:
                    session.captured_packets.append(pkt.to_dict())
                    if len(session.captured_packets) >= session.packet_count:
                        break

                time.sleep(0.01)

            with session.lock:
                if session.cancellation_event.is_set():
                    session.status = SessionStatus.CANCELLED
                elif time.monotonic() >= deadline and len(session.captured_packets) < session.packet_count:
                    session.status = SessionStatus.TIMED_OUT
                else:
                    session.status = SessionStatus.COMPLETED
            session.completion_event.set()
            return

        # 2. Live Linux AF_PACKET Raw Socket Capture
        raw_sock: Optional[socket.socket] = None
        try:
            # ETH_P_ALL = 0x0003 (network byte order)
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            raw_sock.bind((clean_iface, 0))
            raw_sock.setblocking(False)
            session.raw_sock = raw_sock

            pkt_index = 0
            while True:
                if session.cancellation_event.is_set():
                    break

                with session.lock:
                    if len(session.captured_packets) >= session.packet_count:
                        break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                poll_timeout = min(0.05, remaining)
                try:
                    rlist, _, _ = select.select([raw_sock], [], [], poll_timeout)
                except (OSError, ValueError):
                    break

                if rlist:
                    try:
                        raw_bytes = raw_sock.recv(2048)
                        pkt_index += 1
                        dissected, src_ip, dst_ip = PacketDissector.dissect_frame(raw_bytes, pkt_index)

                        # F-04: Mandatory Scope Enforcement (unproven addresses fail closed)
                        if not src_ip and not dst_ip:
                            continue

                        is_in_scope = False
                        if src_ip and scope_guard.is_authorized(src_ip, interface=clean_iface):
                            is_in_scope = True
                        elif dst_ip and scope_guard.is_authorized(dst_ip, interface=clean_iface):
                            is_in_scope = True

                        if not is_in_scope:
                            continue

                        # F-03: Packet Filter Enforcement
                        if not packet_filter.matches(dissected):
                            continue

                        with session.lock:
                            session.captured_packets.append(dissected.to_dict())
                    except BlockingIOError:
                        continue
        except PermissionError as exc:
            logger.warning("Opening AF_PACKET raw socket requires CAP_NET_RAW: %s", exc)
            with session.lock:
                session.status = SessionStatus.FAILED
                session.error_message = "Raw packet socket requires CAP_NET_RAW capability."
        except OSError as exc:
            logger.error("Raw packet capture error on '%s': %s", clean_iface, exc)
            with session.lock:
                session.status = SessionStatus.FAILED
                session.error_message = f"Raw packet capture failed on interface '{clean_iface}': {exc}"
        finally:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except Exception:
                    pass
                session.raw_sock = None

            with session.lock:
                if session.status not in (SessionStatus.FAILED,):
                    if session.cancellation_event.is_set():
                        session.status = SessionStatus.CANCELLED
                    elif time.monotonic() >= deadline and len(session.captured_packets) < session.packet_count:
                        session.status = SessionStatus.TIMED_OUT
                    else:
                        session.status = SessionStatus.COMPLETED
            session.completion_event.set()

    def _send_response(self, sock: socket.socket, response: CaptureResponse) -> None:
        """Send length-prefixed encoded response frame."""
        frame = encode_frame(response.to_dict(), max_size=MAX_RESPONSE_SIZE)
        sock.sendall(frame)

    def stop(self) -> None:
        """Stop server, shutdown sessions, and clean up socket files."""
        self._is_running = False
        self.session_registry.shutdown_all()

        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

        if self.socket_path and os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
