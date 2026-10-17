"""Isolated educational cybersecurity packet analysis laboratory."""

from __future__ import annotations

import struct
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PacketField:
    """Header field explanation and value."""

    name: str
    value: str
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PacketLayer:
    """Protocol layer (e.g., Ethernet, IPv4, TCP)."""

    layer_name: str
    fields: List[PacketField] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_name": self.layer_name,
            "fields": [f.to_dict() for f in self.fields],
        }


@dataclass(frozen=True)
class ParsedPacket:
    """Dissected network packet structure for cybersecurity training."""

    index: int
    protocol: str
    src: str
    dst: str
    summary: str
    length_bytes: int
    layers: List[PacketLayer] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "protocol": self.protocol,
            "src": self.src,
            "dst": self.dst,
            "summary": self.summary,
            "length_bytes": self.length_bytes,
            "layers": [l.to_dict() for l in self.layers],
        }


class EducationalPacketLab:
    """Educational packet dissection engine and synthetic laboratory generator."""

    @classmethod
    def get_sample_trace(cls) -> List[ParsedPacket]:
        """Generate a realistic, safe synthetic packet trace for protocol learning."""
        packets: List[ParsedPacket] = []

        # 1. DNS Query (UDP 53)
        p1 = ParsedPacket(
            index=1,
            protocol="DNS / UDP",
            src="192.168.1.105:51234",
            dst="1.1.1.1:53",
            summary="Standard query 0x1a2b A itsa-network.local",
            length_bytes=74,
            layers=[
                PacketLayer(
                    layer_name="Ethernet II (Data Link)",
                    fields=[
                        PacketField("Source MAC", "02:42:0a:11:00:02", "Host physical interface MAC address."),
                        PacketField("Destination MAC", "00:50:56:fd:aa:01", "Default gateway router MAC address."),
                        PacketField("EtherType", "0x0800 (IPv4)", "Indicates payload is encapsulated IPv4 datagram."),
                    ],
                ),
                PacketLayer(
                    layer_name="IPv4 (Network)",
                    fields=[
                        PacketField("Source IP", "192.168.1.105", "Private client host address (RFC 1918)."),
                        PacketField("Destination IP", "1.1.1.1", "Public Cloudflare recursive DNS resolver."),
                        PacketField("TTL", "64", "Time to live counter decremented by each forwarding hop."),
                        PacketField("Protocol", "17 (UDP)", "User Datagram Protocol transport header."),
                    ],
                ),
                PacketLayer(
                    layer_name="UDP (Transport)",
                    fields=[
                        PacketField("Source Port", "51234", "Ephemeral client source port."),
                        PacketField("Destination Port", "53", "Standard well-known DNS service port."),
                        PacketField("Length", "40 bytes", "Length of UDP header plus DNS payload."),
                    ],
                ),
            ],
        )

        # 2. TCP SYN (Handshake initiation)
        p2 = ParsedPacket(
            index=2,
            protocol="TCP",
            src="192.168.1.105:49152",
            dst="93.184.216.34:443",
            summary="[SYN] Seq=0 Win=65535 Len=0 MSS=1460",
            length_bytes=66,
            layers=[
                PacketLayer(
                    layer_name="Ethernet II (Data Link)",
                    fields=[
                        PacketField("Source MAC", "02:42:0a:11:00:02", "Client MAC."),
                        PacketField("Destination MAC", "00:50:56:fd:aa:01", "Gateway MAC."),
                        PacketField("EtherType", "0x0800 (IPv4)", "IPv4 encapsulated."),
                    ],
                ),
                PacketLayer(
                    layer_name="IPv4 (Network)",
                    fields=[
                        PacketField("Source IP", "192.168.1.105", "Client IP."),
                        PacketField("Destination IP", "93.184.216.34", "Target web server IP."),
                        PacketField("Protocol", "6 (TCP)", "Transmission Control Protocol."),
                    ],
                ),
                PacketLayer(
                    layer_name="TCP (Transport)",
                    fields=[
                        PacketField("Source Port", "49152", "Ephemeral source port."),
                        PacketField("Destination Port", "443 (HTTPS)", "TLS secure web server port."),
                        PacketField("Flags", "0x002 (SYN)", "Synchronize sequence numbers (3-way handshake step 1)."),
                        PacketField("Window Size", "65535", "Flow control receive window advertising buffer space."),
                    ],
                ),
            ],
        )

        # 3. TCP SYN-ACK (Server response)
        p3 = ParsedPacket(
            index=3,
            protocol="TCP",
            src="93.184.216.34:443",
            dst="192.168.1.105:49152",
            summary="[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0",
            length_bytes=66,
            layers=[
                PacketLayer(
                    layer_name="IPv4 (Network)",
                    fields=[
                        PacketField("Source IP", "93.184.216.34", "Remote server address."),
                        PacketField("Destination IP", "192.168.1.105", "Client host address."),
                    ],
                ),
                PacketLayer(
                    layer_name="TCP (Transport)",
                    fields=[
                        PacketField("Flags", "0x012 (SYN, ACK)", "Acknowledgment of client SYN + Server SYN proposal."),
                        PacketField("Acknowledgment Number", "1", "Confirms receipt of client's ISN (Initial Sequence Number)."),
                    ],
                ),
            ],
        )

        # 4. ICMP Echo Request (Ping)
        p4 = ParsedPacket(
            index=4,
            protocol="ICMP",
            src="192.168.1.105",
            dst="8.8.8.8",
            summary="Echo (ping) request id=0x0100 seq=1",
            length_bytes=98,
            layers=[
                PacketLayer(
                    layer_name="IPv4 (Network)",
                    fields=[
                        PacketField("Source IP", "192.168.1.105", "Ping origin."),
                        PacketField("Destination IP", "8.8.8.8", "Google Public DNS target."),
                        PacketField("Protocol", "1 (ICMP)", "Internet Control Message Protocol."),
                    ],
                ),
                PacketLayer(
                    layer_name="ICMP (Control)",
                    fields=[
                        PacketField("Type", "8 (Echo Request)", "Connectivity test inquiry message."),
                        PacketField("Code", "0", "Standard query code."),
                        PacketField("Sequence", "1", "Probe sequence matching."),
                    ],
                ),
            ],
        )

        packets.extend([p1, p2, p3, p4])
        return packets
