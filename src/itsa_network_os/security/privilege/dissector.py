"""Pure standard-library raw packet dissection and layer parsing for cybersecurity education."""

from __future__ import annotations

import socket
import struct
from typing import List, Optional, Tuple

from itsa_network_os.security.lab import PacketField, PacketLayer, ParsedPacket


class PacketDissector:
    """Non-destructive binary decoder for link-layer and network frames."""

    @classmethod
    def dissect_frame(cls, raw_bytes: bytes, index: int) -> Tuple[ParsedPacket, Optional[str], Optional[str]]:
        """Parse raw link-layer bytes into ParsedPacket.

        Returns:
            Tuple[ParsedPacket, Optional[src_ip], Optional[dst_ip]]
        """
        length = len(raw_bytes)
        layers: List[PacketLayer] = []
        proto_name = "RAW"
        src_str = "Unknown"
        dst_str = "Unknown"
        summary = f"Frame #{index} ({length} bytes)"
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None

        if length < 14:
            # Runt frame
            p = ParsedPacket(
                index=index,
                protocol="Runt Frame",
                src="N/A",
                dst="N/A",
                summary=f"Truncated frame ({length} bytes)",
                length_bytes=length,
                layers=[PacketLayer("Malformed Frame", [PacketField("Length", str(length), "Frame < 14 bytes")])],
            )
            return p, None, None

        # 1. Ethernet Header (14 bytes)
        dst_mac = ":".join(f"{b:02x}" for b in raw_bytes[0:6])
        src_mac = ":".join(f"{b:02x}" for b in raw_bytes[6:12])
        ethertype = struct.unpack("!H", raw_bytes[12:14])[0]

        eth_fields = [
            PacketField("Destination MAC", dst_mac, "Target hardware address"),
            PacketField("Source MAC", src_mac, "Originating hardware address"),
            PacketField("EtherType", f"0x{ethertype:04x}", "Payload protocol encapsulation"),
        ]
        layers.append(PacketLayer("Ethernet II (Data Link)", eth_fields))

        offset = 14

        # 2. IPv4 Payload (EtherType 0x0800)
        if ethertype == 0x0800 and length >= offset + 20:
            ip_header = raw_bytes[offset : offset + 20]
            version_ihl, tos, total_len, ident, flags_offset, ttl, ip_proto, chk = struct.unpack("!BBHHHBBH", ip_header[:12])
            version = (version_ihl >> 4) & 0x0F
            ihl = (version_ihl & 0x0F) * 4
            src_bytes = raw_bytes[offset + 12 : offset + 16]
            dst_bytes = raw_bytes[offset + 16 : offset + 20]
            src_ip = socket.inet_ntoa(src_bytes)
            dst_ip = socket.inet_ntoa(dst_bytes)
            src_str = src_ip
            dst_str = dst_ip
            proto_name = "IPv4"

            ip_fields = [
                PacketField("Version", str(version), "IP version"),
                PacketField("Header Length", f"{ihl} bytes", "IPv4 header span"),
                PacketField("TTL", str(ttl), "Time to live hop limit"),
                PacketField("Protocol", str(ip_proto), "Encapsulated L4 protocol number"),
                PacketField("Source IP", src_ip, "Source IP address"),
                PacketField("Destination IP", dst_ip, "Destination IP address"),
            ]
            layers.append(PacketLayer("IPv4 (Network)", ip_fields))

            payload_offset = offset + max(20, ihl)

            # L4 Protocol Parsing
            if ip_proto == 6 and length >= payload_offset + 20:  # TCP
                tcp_header = raw_bytes[payload_offset : payload_offset + 20]
                src_port, dst_port, seq, ack, data_offset_flags, win = struct.unpack("!HHIIHH", tcp_header[:16])
                flags = data_offset_flags & 0x01FF
                flag_str = []
                if flags & 0x02: flag_str.append("SYN")
                if flags & 0x10: flag_str.append("ACK")
                if flags & 0x01: flag_str.append("FIN")
                if flags & 0x04: flag_str.append("RST")
                if flags & 0x08: flag_str.append("PSH")

                proto_name = "TCP"
                src_str = f"{src_ip}:{src_port}"
                dst_str = f"{dst_ip}:{dst_port}"
                summary = f"[{','.join(flag_str) or 'TCP'}] Seq={seq} Ack={ack} Win={win}"

                layers.append(
                    PacketLayer(
                        "TCP (Transport)",
                        [
                            PacketField("Source Port", str(src_port), "Origin port"),
                            PacketField("Destination Port", str(dst_port), "Target port"),
                            PacketField("Sequence Number", str(seq), "TCP sequence number"),
                            PacketField("Flags", f"0x{flags:03x} ({','.join(flag_str)})", "TCP control flags"),
                        ],
                    )
                )

            elif ip_proto == 17 and length >= payload_offset + 8:  # UDP
                udp_header = raw_bytes[payload_offset : payload_offset + 8]
                src_port, dst_port, ulen, _ = struct.unpack("!HHHH", udp_header)
                proto_name = "UDP"
                src_str = f"{src_ip}:{src_port}"
                dst_str = f"{dst_ip}:{dst_port}"
                summary = f"UDP Len={ulen} {src_port} -> {dst_port}"

                layers.append(
                    PacketLayer(
                        "UDP (Transport)",
                        [
                            PacketField("Source Port", str(src_port), "Origin port"),
                            PacketField("Destination Port", str(dst_port), "Target port"),
                            PacketField("Length", f"{ulen} bytes", "Datagram size"),
                        ],
                    )
                )

            elif ip_proto == 1 and length >= payload_offset + 8:  # ICMP
                icmp_type, icmp_code = struct.unpack("!BB", raw_bytes[payload_offset : payload_offset + 2])
                proto_name = "ICMP"
                summary = f"ICMP Type {icmp_type} Code {icmp_code}"
                layers.append(
                    PacketLayer(
                        "ICMP (Control)",
                        [
                            PacketField("Type", str(icmp_type), "Control message type"),
                            PacketField("Code", str(icmp_code), "Control sub-code"),
                        ],
                    )
                )

        elif ethertype == 0x0806 and length >= offset + 28:  # ARP
            arp_data = raw_bytes[offset : offset + 28]
            htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", arp_data[:8])
            sha = ":".join(f"{b:02x}" for b in arp_data[8:14])
            spa = socket.inet_ntoa(arp_data[14:18])
            tha = ":".join(f"{b:02x}" for b in arp_data[18:24])
            tpa = socket.inet_ntoa(arp_data[24:28])

            proto_name = "ARP"
            src_str = spa
            dst_str = tpa
            src_ip = spa
            dst_ip = tpa
            op_name = "Request" if oper == 1 else "Reply" if oper == 2 else str(oper)
            summary = f"ARP {op_name}: Who has {tpa}? Tell {spa}" if oper == 1 else f"ARP {op_name}: {spa} is at {sha}"

            layers.append(
                PacketLayer(
                    "ARP (Resolution)",
                    [
                        PacketField("Operation", f"{op_name} ({oper})", "ARP opcode"),
                        PacketField("Sender IP", spa, "Sender protocol address"),
                        PacketField("Sender MAC", sha, "Sender hardware address"),
                        PacketField("Target IP", tpa, "Target protocol address"),
                    ],
                )
            )

        packet = ParsedPacket(
            index=index,
            protocol=proto_name,
            src=src_str,
            dst=dst_str,
            summary=summary,
            length_bytes=length,
            layers=layers,
        )
        return packet, src_ip, dst_ip
