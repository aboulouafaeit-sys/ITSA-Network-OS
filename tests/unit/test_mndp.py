"""Unit tests for pure MikroTik Neighbor Discovery Protocol (MNDP) decoder."""

import struct
import unittest

from itsa_network_os.network.mndp import (
    MNDP_HEADER_SIZE,
    MNDP_MAX_SAFE_DATAGRAM_SIZE,
    MNDPPacket,
    build_mndp_test_packet,
    parse_mndp_packet,
    sanitize_mndp_string,
)


class TestMNDPDecoder(unittest.TestCase):
    """Test suite for bounded, safe MNDP protocol decoder."""

    def test_valid_packet_decoding_all_tlvs(self) -> None:
        """Requirement: parse complete valid MNDP packet with all standard TLVs."""
        raw_pkt = build_mndp_test_packet(
            mac="48:8F:5A:12:34:56",
            identity="Core-Router-RB760iGS",
            version="7.14.3 (stable)",
            platform="MikroTik",
            uptime_seconds=86465,  # 1d 00:01:05
            software_id="ABCD-1234",
            board_name="RB760iGS",
            interface_name="ether1",
            ipv4="192.168.88.1",
            ipv6="fe80::4a8f:5aff:fe12:3456",
        )
        pkt = parse_mndp_packet(raw_pkt)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertTrue(pkt.is_valid)
        self.assertEqual(pkt.mac_address, "48:8F:5A:12:34:56")
        self.assertEqual(pkt.identity, "Core-Router-RB760iGS")
        self.assertEqual(pkt.version, "7.14.3 (stable)")
        self.assertEqual(pkt.platform, "MikroTik")
        self.assertEqual(pkt.uptime_seconds, 86465)
        self.assertEqual(pkt.uptime_formatted, "1d 00:01:05")
        self.assertEqual(pkt.software_id, "ABCD-1234")
        self.assertEqual(pkt.board_name, "RB760iGS")
        self.assertEqual(pkt.interface_name, "ether1")
        self.assertEqual(pkt.ipv4_address, "192.168.88.1")
        self.assertEqual(pkt.ipv6_address, "fe80::4a8f:5aff:fe12:3456")
        self.assertEqual(len(pkt.warnings), 0)

    def test_invalid_header_truncated(self) -> None:
        """Requirement: reject datagrams shorter than 4-byte header."""
        res_empty = parse_mndp_packet(b"")
        self.assertIsNotNone(res_empty)
        assert res_empty is not None
        self.assertFalse(res_empty.is_valid)

        res_short = parse_mndp_packet(b"\x00\x01\x02")
        self.assertIsNotNone(res_short)
        assert res_short is not None
        self.assertFalse(res_short.is_valid)
        self.assertTrue(any("too short" in w.lower() for w in res_short.warnings))

    def test_oversized_datagram_rejected(self) -> None:
        """Requirement: reject datagrams exceeding 64 KB safety bound."""
        oversized = b"\x00" * (MNDP_MAX_SAFE_DATAGRAM_SIZE + 10)
        pkt = parse_mndp_packet(oversized)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertFalse(pkt.is_valid)
        self.assertTrue(any("exceeds maximum" in w.lower() for w in pkt.warnings))

    def test_truncated_tlv_length_handled_safely(self) -> None:
        """Requirement: safely handle TLVs where declared length exceeds buffer size."""
        # Header + TLV with declared length 50, but only 4 bytes of value follow
        raw = b"\x00\x00\x00\x00" + struct.pack(">HH", 0x0005, 50) + b"test"
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertTrue(pkt.is_valid)
        self.assertTrue(any("truncated tlv" in w.lower() for w in pkt.warnings))
        self.assertIsNone(pkt.identity)

    def test_excessive_tlv_length_skipped(self) -> None:
        """Requirement: skip individual TLV declaring length > 1024 bytes."""
        # TLV 0x0005 declares length 2000, followed by valid TLV 0x000c
        fake_huge_data = b"X" * 2000
        raw = (
            b"\x00\x00\x00\x00"
            + struct.pack(">HH", 0x0005, 2000)
            + fake_huge_data
            + struct.pack(">HH", 0x000C, 4)
            + b"hEXS"
        )
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertTrue(any("excessive length" in w.lower() for w in pkt.warnings))
        self.assertEqual(pkt.board_name, "hEXS")

    def test_invalid_mac_length_flagged(self) -> None:
        """Requirement: validate MAC address length is exactly 6 bytes."""
        # MAC TLV with 4 bytes instead of 6
        raw = b"\x00\x00\x00\x00" + struct.pack(">HH", 0x0001, 4) + b"\x11\x22\x33\x44"
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertIsNone(pkt.mac_address)
        self.assertTrue(any("invalid mac" in w.lower() for w in pkt.warnings))

    def test_invalid_uptime_length_flagged(self) -> None:
        """Requirement: validate uptime length is exactly 4 bytes."""
        # Uptime TLV with 2 bytes instead of 4
        raw = b"\x00\x00\x00\x00" + struct.pack(">HH", 0x000A, 2) + b"\x10\x00"
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertIsNone(pkt.uptime_seconds)
        self.assertTrue(any("invalid uptime" in w.lower() for w in pkt.warnings))

    def test_unknown_tlvs_preserved_without_crashing(self) -> None:
        """Requirement: unknown or vendor-proprietary TLVs preserved in unknown_tlvs."""
        extra = {0x9999: b"\xca\xfe\xba\xbe", 0x8888: b"custom-metadata"}
        raw = build_mndp_test_packet(extra_tlvs=extra)
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertIn(0x9999, pkt.unknown_tlvs)
        self.assertEqual(pkt.unknown_tlvs[0x9999], b"\xca\xfe\xba\xbe")
        self.assertIn(0x8888, pkt.unknown_tlvs)
        self.assertEqual(pkt.unknown_tlvs[0x8888], b"custom-metadata")

    def test_control_character_sanitization_and_capping(self) -> None:
        """Requirement: strip control characters and cap string length at max boundary."""
        dirty = "Core\x00\x01\x1b[31mRouter\x7f\x80"
        clean = sanitize_mndp_string(dirty)
        self.assertEqual(clean, "Core[31mRouter")

        long_str = "A" * 300
        capped = sanitize_mndp_string(long_str, max_length=256)
        self.assertEqual(len(capped), 256)

    def test_serialization_to_dict(self) -> None:
        """Requirement: to_dict serialization includes hex-formatted unknown TLVs."""
        raw = build_mndp_test_packet(extra_tlvs={0x1234: b"\x01\x02"})
        pkt = parse_mndp_packet(raw)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        d = pkt.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["board_name"], "RB760iGS")
        self.assertEqual(d["unknown_tlvs"]["0x1234"], "0102")


if __name__ == "__main__":
    unittest.main()
