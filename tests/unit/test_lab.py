"""Unit tests for educational cybersecurity packet laboratory."""

import unittest
from itsa_network_os.security.lab import EducationalPacketLab, ParsedPacket


class TestEducationalPacketLab(unittest.TestCase):
    """Test packet dissection and educational lab structures."""

    def test_sample_trace_generation(self) -> None:
        packets = EducationalPacketLab.get_sample_trace()
        self.assertGreaterEqual(len(packets), 4)

        for pkt in packets:
            self.assertIsInstance(pkt, ParsedPacket)
            self.assertGreater(len(pkt.protocol), 0)
            self.assertGreater(len(pkt.layers), 0)
            self.assertGreater(pkt.length_bytes, 0)

    def test_packet_to_dict_serialization(self) -> None:
        packets = EducationalPacketLab.get_sample_trace()
        first_pkt = packets[0]
        data = first_pkt.to_dict()
        self.assertIn("index", data)
        self.assertIn("protocol", data)
        self.assertIn("layers", data)
        self.assertIsInstance(data["layers"], list)
        self.assertGreater(len(data["layers"][0]["fields"]), 0)


if __name__ == "__main__":
    unittest.main()
