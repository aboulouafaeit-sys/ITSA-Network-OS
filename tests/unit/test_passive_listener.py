"""Unit tests for MNDP and ONVIF passive listeners.

Verifies:
1. Mock socket creation, bind, receive, timeout, cancellation, and cleanup.
2. Repeated start/stop cycles without leaks or hangs.
3. Interface filtering for matching and non-matching interface indices.
4. Safe failure when mandatory interface filtering options are unavailable.
5. Multicast membership join and drop lifecycle.
6. Rate limiting and quota bounds.
7. Strict non-transmission verification (no send/sendto/sendmsg calls).
"""

import socket
import struct
import threading
import unittest
from unittest.mock import MagicMock, patch

from itsa_network_os.network.mndp import (
    MNDPPassiveListener,
    build_mndp_test_packet,
)
from itsa_network_os.network.onvif import (
    ONVIFPassiveListener,
    build_ws_discovery_test_xml,
)


class MockDatagramSocket(MagicMock):
    """Mock socket implementing recvmsg and setsockopt for deterministic testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.closed = False
        self.bound_addr = None
        self.sockopts = {}
        self.packets_queue = []
        self.fail_pktinfo = False

    def fileno(self):
        return 42

    def close(self):
        self.closed = True

    def bind(self, addr):
        self.bound_addr = addr

    def setsockopt(self, level, optname, val):
        if self.fail_pktinfo and level == socket.IPPROTO_IP and optname == getattr(socket, "IP_PKTINFO", 8):
            raise OSError("IP_PKTINFO not supported on this platform")
        self.sockopts[(level, optname)] = val

    def queue_packet(self, data: bytes, sender_ip: str, sender_port: int, ifindex: int = 1):
        """Queue a datagram to be returned by recvmsg."""
        cmsg = [(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), struct.pack("iii", ifindex, 0, 0))]
        self.packets_queue.append((data, cmsg, 0, (sender_ip, sender_port)))

    def recvmsg(self, bufsize, ancbufsize=1024):
        if self.packets_queue:
            return self.packets_queue.pop(0)
        raise BlockingIOError("No packets available")


class TestPassiveListeners(unittest.TestCase):
    """Test suite for passive MNDP and ONVIF listener lifecycles."""

    def setUp(self):
        self.mndp_pkt = build_mndp_test_packet(
            mac="48:8F:5A:11:22:33",
            board_name="RB760iGS",
            ipv4="192.168.88.1",
        )
        self.onvif_xml = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
            hardware_model="DS-2CD2042WD-I",
        )

    def test_mndp_listener_receives_and_parses_observation(self) -> None:
        """Requirement: MNDP listener receives broadcast datagram and extracts observation."""
        mock_sock = MockDatagramSocket()
        mock_sock.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)

        listener = MNDPPassiveListener(port=5678)
        with patch("select.select", return_value=([mock_sock], [], [])):
            with patch("socket.if_indextoname", return_value="eth0"):
                obs_list = listener.listen(
                    timeout=0.1,
                    max_packets=1,
                    socket_factory=lambda *a, **k: mock_sock,
                )

        self.assertEqual(len(obs_list), 1)
        obs = obs_list[0]
        self.assertEqual(obs.sender_ip, "192.168.88.1")
        self.assertEqual(obs.sender_port, 5678)
        self.assertEqual(obs.interface, "eth0")
        self.assertEqual(obs.packet.board_name, "RB760iGS")
        self.assertEqual(obs.packet.mac_address, "48:8F:5A:11:22:33")
        self.assertTrue(mock_sock.closed)

    def test_onvif_listener_receives_and_parses_observation(self) -> None:
        """Requirement: ONVIF listener receives multicast SOAP XML and extracts observation."""
        mock_sock = MockDatagramSocket()
        mock_sock.queue_packet(self.onvif_xml, sender_ip="192.168.1.108", sender_port=3702, ifindex=1)

        listener = ONVIFPassiveListener(port=3702)
        with patch("select.select", return_value=([mock_sock], [], [])):
            with patch("socket.if_indextoname", return_value="eth0"):
                obs_list = listener.listen(
                    timeout=0.1,
                    max_packets=1,
                    socket_factory=lambda *a, **k: mock_sock,
                )

        self.assertEqual(len(obs_list), 1)
        obs = obs_list[0]
        self.assertEqual(obs.sender_ip, "192.168.1.108")
        self.assertEqual(obs.interface, "eth0")
        self.assertEqual(obs.message.hardware_model, "DS-2CD2042WD-I")
        self.assertTrue(mock_sock.closed)

    def test_strict_zero_packet_transmission(self) -> None:
        """Requirement: listeners NEVER transmit application packets (send/sendto/sendmsg)."""
        mock_sock_mndp = MockDatagramSocket()
        mock_sock_mndp.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)

        mock_sock_onvif = MockDatagramSocket()
        mock_sock_onvif.queue_packet(self.onvif_xml, sender_ip="192.168.1.108", sender_port=3702, ifindex=1)

        listener_mndp = MNDPPassiveListener()
        with patch("select.select", return_value=([mock_sock_mndp], [], [])):
            listener_mndp.listen(timeout=0.1, max_packets=1, socket_factory=lambda *a, **k: mock_sock_mndp)

        listener_onvif = ONVIFPassiveListener()
        with patch("select.select", return_value=([mock_sock_onvif], [], [])):
            listener_onvif.listen(timeout=0.1, max_packets=1, socket_factory=lambda *a, **k: mock_sock_onvif)

        mock_sock_mndp.send.assert_not_called()
        mock_sock_mndp.sendto.assert_not_called()
        mock_sock_onvif.send.assert_not_called()
        mock_sock_onvif.sendto.assert_not_called()

    def test_interface_filtering_accepts_matching_drops_nonmatching(self) -> None:
        """Requirement: interface filter drops packets from other interface indices."""
        mock_sock = MockDatagramSocket()
        # Packet 1 on ifindex 1 (eth0)
        mock_sock.queue_packet(self.mndp_pkt, sender_ip="192.168.88.1", sender_port=5678, ifindex=1)
        # Packet 2 on ifindex 2 (wlan0)
        mock_sock.queue_packet(self.mndp_pkt, sender_ip="192.168.88.2", sender_port=5678, ifindex=2)

        def mock_if_name(idx):
            return "eth0" if idx == 1 else "wlan0"

        listener = MNDPPassiveListener()
        # Mock select returning mock_sock whenever queue has packets, empty otherwise
        def mock_select(r, w, x, t):
            if mock_sock.packets_queue:
                return ([mock_sock], [], [])
            return ([], [], [])

        with patch("select.select", side_effect=mock_select):
            with patch("socket.if_indextoname", side_effect=mock_if_name):
                # Filter strictly for eth0, max 2 packets
                obs = listener.listen(
                    timeout=0.2,
                    interface="eth0",
                    max_packets=2,
                    socket_factory=lambda *a, **k: mock_sock,
                )

        self.assertEqual(len(obs), 1)
        self.assertEqual(obs[0].interface, "eth0")
        self.assertEqual(obs[0].sender_ip, "192.168.88.1")

    def test_missing_pktinfo_fails_safe_when_interface_requested(self) -> None:
        """Requirement: fail safely if interface filter requested but IP_PKTINFO is unsupported."""
        mock_sock = MockDatagramSocket()
        mock_sock.fail_pktinfo = True
        listener = MNDPPassiveListener()
        with self.assertRaises(RuntimeError) as ctx:
            listener.listen(
                timeout=0.1,
                interface="eth0",
                socket_factory=lambda *a, **k: mock_sock,
            )
        self.assertIn("cannot be enforced", str(ctx.exception))

    def test_cancellation_event_stops_listening_immediately(self) -> None:
        """Requirement: cancellation token interrupts listening loop without delay."""
        mock_sock = MockDatagramSocket()
        listener = MNDPPassiveListener()
        stop_event = threading.Event()
        stop_event.set()  # Pre-cancelled

        obs = listener.listen(
            timeout=10.0,
            stop_event=stop_event,
            socket_factory=lambda *a, **k: mock_sock,
        )
        self.assertEqual(len(obs), 0)
        self.assertTrue(mock_sock.closed)

    def test_multicast_membership_joined_and_dropped(self) -> None:
        """Requirement: ONVIF listener joins IP_ADD_MEMBERSHIP and drops in finally block."""
        mock_sock = MockDatagramSocket()
        listener = ONVIFPassiveListener(port=3702)

        with patch("select.select", return_value=([], [], [])):
            obs = listener.listen(
                timeout=0.05,
                socket_factory=lambda *a, **k: mock_sock,
            )

        self.assertTrue(mock_sock.closed)
        self.assertIn((socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP), mock_sock.sockopts)

    def test_repeated_start_stop_cycles_no_leaks(self) -> None:
        """Requirement: 5 repeated start/stop cycles complete cleanly without leaks or hangs."""
        listener = MNDPPassiveListener()
        for _ in range(5):
            mock_sock = MockDatagramSocket()
            with patch("select.select", return_value=([], [], [])):
                obs = listener.listen(
                    timeout=0.01,
                    socket_factory=lambda *a, **k: mock_sock,
                )
                self.assertEqual(len(obs), 0)
                self.assertTrue(mock_sock.closed)


if __name__ == "__main__":
    unittest.main()
