"""Unit tests for pure ONVIF WS-Discovery protocol decoder."""

import unittest
from unittest.mock import patch

from itsa_network_os.network.onvif import (
    WS_DISCOVERY_MAX_PAYLOAD_SIZE,
    ONVIFDiscoveryMessage,
    build_ws_discovery_test_xml,
    parse_ws_discovery,
)


class TestONVIFDecoder(unittest.TestCase):
    """Test suite for bounded, safe ONVIF WS-Discovery SOAP XML decoder."""

    def test_valid_hello_message_wsd_2005(self) -> None:
        """Requirement: parse valid Hello announcement using WS-Discovery 2005 namespace."""
        raw_xml = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
            types="dn:NetworkVideoTransmitter tds:Device",
            scopes="onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/DS-2CD2042WD-I onvif://www.onvif.org/name/FrontEntrance",
            xaddr="http://192.168.1.108:80/onvif/device_service",
            metadata_version=1,
            namespace_variant="2005",
        )
        msg = parse_ws_discovery(raw_xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertTrue(msg.is_valid)
        self.assertEqual(msg.message_type, "Hello")
        self.assertEqual(msg.endpoint_uuid, "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad")
        self.assertIn("dn:NetworkVideoTransmitter", msg.types)
        self.assertIn("tds:Device", msg.types)
        self.assertEqual(msg.hardware_model, "DS-2CD2042WD-I")
        self.assertEqual(msg.device_name, "FrontEntrance")
        self.assertEqual(msg.ip_address, "192.168.1.108")
        self.assertEqual(msg.port, 80)
        self.assertEqual(msg.metadata_version, 1)

    def test_valid_hello_message_oasis_2009(self) -> None:
        """Requirement: parse valid Hello announcement using OASIS WS-Discovery 2009 namespace."""
        raw_xml = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:a1b2c3d4-e5f6-7890-1234-56789abcdef0",
            types="wsdd:NetworkVideoTransmitter",
            scopes="onvif://www.onvif.org/hardware/IPC-HFW4431R-Z onvif://www.onvif.org/name/WarehouseSouth",
            xaddr="https://10.0.50.25:443/onvif/device_service",
            metadata_version=2,
            namespace_variant="2009",
        )
        msg = parse_ws_discovery(raw_xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertTrue(msg.is_valid)
        self.assertEqual(msg.message_type, "Hello")
        self.assertEqual(msg.endpoint_uuid, "urn:uuid:a1b2c3d4-e5f6-7890-1234-56789abcdef0")
        self.assertEqual(msg.hardware_model, "IPC-HFW4431R-Z")
        self.assertEqual(msg.device_name, "WarehouseSouth")
        self.assertEqual(msg.ip_address, "10.0.50.25")
        self.assertEqual(msg.port, 443)
        self.assertEqual(msg.metadata_version, 2)

    def test_valid_bye_announcement(self) -> None:
        """Requirement: parse Bye announcement representing device departure."""
        raw_xml = build_ws_discovery_test_xml(
            message_type="Bye",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
        )
        msg = parse_ws_discovery(raw_xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertTrue(msg.is_valid)
        self.assertEqual(msg.message_type, "Bye")
        self.assertEqual(msg.endpoint_uuid, "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad")

    def test_probematches_observation(self) -> None:
        """Requirement: parse observed ProbeMatches without generating any probe queries."""
        raw_xml = build_ws_discovery_test_xml(
            message_type="ProbeMatches",
            endpoint_uuid="urn:uuid:11223344-5566-7788-9900-aabbccddeeff",
            hardware_model="Axis-P3245-LV",
        )
        msg = parse_ws_discovery(raw_xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertTrue(msg.is_valid)
        self.assertEqual(msg.message_type, "ProbeMatches")
        self.assertEqual(msg.endpoint_uuid, "urn:uuid:11223344-5566-7788-9900-aabbccddeeff")

    def test_oversized_xml_rejected(self) -> None:
        """Requirement: reject payloads exceeding 64 KB safety bound before XML parsing."""
        oversized = b"<xml>" + b"A" * (WS_DISCOVERY_MAX_PAYLOAD_SIZE + 10) + b"</xml>"
        msg = parse_ws_discovery(oversized)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("exceeds maximum" in w.lower() for w in msg.warnings))

    def test_xxe_and_dtd_expansion_rejection(self) -> None:
        """Requirement: reject any XML containing <!DOCTYPE or <!ENTITY declarations (XXE defense)."""
        xxe_payload = b"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <Hello>&xxe;</Hello>
  </soap:Body>
</soap:Envelope>"""
        msg = parse_ws_discovery(xxe_payload)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("security violation" in w.lower() for w in msg.warnings))

    def test_billion_laughs_rejection(self) -> None:
        """Requirement: reject Billion Laughs recursive entity expansion attempts."""
        billion_laughs = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body><Hello>&lol2;</Hello></soap:Body>
</soap:Envelope>"""
        msg = parse_ws_discovery(billion_laughs)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("security violation" in w.lower() for w in msg.warnings))

    def test_malformed_xml_handled_safely(self) -> None:
        """Requirement: safely handle malformed XML syntax without unhandled exceptions."""
        corrupted = b"<?xml version='1.0'?><soap:Envelope><unclosed_tag>"
        msg = parse_ws_discovery(corrupted)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("malformed xml" in w.lower() for w in msg.warnings))

    def test_disallowed_uri_scheme_in_xaddrs(self) -> None:
        """Requirement: reject malicious URI schemes (javascript:, file:, ftp:) in XAddrs."""
        xml = build_ws_discovery_test_xml(
            message_type="Hello",
            xaddr="file:///etc/shadow",
        )
        msg = parse_ws_discovery(xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertEqual(len(msg.xaddrs), 0)
        self.assertTrue(any("rejected xaddr" in w.lower() for w in msg.warnings))

    def test_empty_or_none_input(self) -> None:
        """Requirement: gracefully return None on empty or non-bytes input."""
        self.assertIsNone(parse_ws_discovery(b""))
        self.assertIsNone(parse_ws_discovery(b"   "))
        self.assertIsNone(parse_ws_discovery(None))  # type: ignore[arg-type]

    def test_no_socket_calls_during_parsing(self) -> None:
        """Requirement: verify zero socket creation or network communication during parsing."""
        raw_xml = build_ws_discovery_test_xml(message_type="Hello")
        with patch("socket.socket") as mock_socket:
            msg = parse_ws_discovery(raw_xml)
            self.assertIsNotNone(msg)
            mock_socket.assert_not_called()

    def test_utf16_doctype_rejection(self) -> None:
        """Requirement: reject DTD declarations even when encoded in UTF-16."""
        payload_str = """<?xml version="1.0" encoding="utf-16"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body><Hello>&xxe;</Hello></soap:Body>
</soap:Envelope>"""
        utf16_payload = payload_str.encode("utf-16")
        msg = parse_ws_discovery(utf16_payload)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("security violation" in w.lower() for w in msg.warnings))

    def test_utf16_entity_expansion_rejection(self) -> None:
        """Requirement: reject entity declarations in UTF-16 payloads to prevent entity expansion."""
        payload_str = """<?xml version="1.0" encoding="utf-16"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body><Hello>&lol2;</Hello></soap:Body>
</soap:Envelope>"""
        utf16_payload = payload_str.encode("utf-16")
        msg = parse_ws_discovery(utf16_payload)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertFalse(msg.is_valid)
        self.assertTrue(any("security violation" in w.lower() for w in msg.warnings))

    def test_utf16_legitimate_payload_parsed(self) -> None:
        """Requirement: legitimate UTF-16 WS-Discovery messages parse cleanly without security rejection."""
        utf8_xml = build_ws_discovery_test_xml(
            message_type="Hello",
            endpoint_uuid="urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad",
            hardware_model="DS-2CD2042WD-I",
        ).decode("utf-8")
        utf16_xml = utf8_xml.replace('encoding="utf-8"', 'encoding="utf-16"').encode("utf-16")
        msg = parse_ws_discovery(utf16_xml)
        self.assertIsNotNone(msg)
        assert msg is not None
        self.assertTrue(msg.is_valid)
        self.assertEqual(msg.message_type, "Hello")
        self.assertEqual(msg.endpoint_uuid, "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad")
        self.assertEqual(msg.hardware_model, "DS-2CD2042WD-I")

    def test_endpoint_uuid_validation_valid_formats(self) -> None:
        """Requirement: accept and canonicalize valid UUIDs with various prefix cases."""
        valid_uuids = [
            ("urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad", "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad"),
            ("URN:UUID:FA3B2469-656C-4866-B258-406A4632B6AD", "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad"),
            ("uuid:fa3b2469-656c-4866-b258-406a4632b6ad", "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad"),
            ("fa3b2469-656c-4866-b258-406a4632b6ad", "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad"),
        ]
        for raw_val, expected_canonical in valid_uuids:
            xml = build_ws_discovery_test_xml(endpoint_uuid=raw_val)
            msg = parse_ws_discovery(xml)
            self.assertIsNotNone(msg)
            assert msg is not None
            self.assertEqual(msg.endpoint_uuid, expected_canonical)
            self.assertEqual(msg.raw_endpoint_address, raw_val)

    def test_endpoint_uuid_validation_malformed_rejected(self) -> None:
        """Requirement: reject malformed UUID strings safely and record warnings."""
        malformed_values = [
            "urn:uuid:not-a-valid-uuid",
            "urn:uuid:fa3b2469-656c-4866-b258",
            "urn:uuid:fa3b2469-656c-4866-b258-406a4632b6ad;drop table devices;",
            "http://192.168.1.1/malicious/path",
            "A" * 300,  # Excessive length
        ]
        for bad_val in malformed_values:
            xml = build_ws_discovery_test_xml(endpoint_uuid=bad_val)
            msg = parse_ws_discovery(xml)
            self.assertIsNotNone(msg)
            assert msg is not None
            self.assertIsNone(msg.endpoint_uuid)
            self.assertTrue(any("rejected malformed" in w.lower() or "exceeds safe" in w.lower() for w in msg.warnings))
            self.assertEqual(msg.raw_endpoint_address, bad_val[:256] if len(bad_val) <= 256 else bad_val)


if __name__ == "__main__":
    unittest.main()
