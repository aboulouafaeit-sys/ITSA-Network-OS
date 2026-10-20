"""Deterministic, safe packet filtering engine for privileged capture helper."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from itsa_network_os.security.lab import ParsedPacket

# Disallowed characters that indicate shell injection, command chaining, or illegal syntax
FORBIDDEN_FILTER_CHARS = re.compile(r"[;&|\$`><\\\n\r\t!]")

# Valid protocol keywords
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "arp"}


class FilterSyntaxError(ValueError):
    """Raised when a filter expression violates supported grammar."""


@dataclass(frozen=True)
class PacketFilter:
    """Compiled deterministic packet filter predicate.

    Supported grammar:
      - Empty or None: match all packets
      - Protocol: 'tcp', 'udp', 'icmp', 'arp'
      - Port: 'port <N>', 'src port <N>', 'dst port <N>' (TCP/UDP only, 1 <= N <= 65535)
      - Compound: '<proto> and [src|dst] port <N>' (proto must be tcp or udp)
    """

    protocol: Optional[str] = None          # 'tcp', 'udp', 'icmp', 'arp'
    port_type: Optional[str] = None         # 'any', 'src', 'dst'
    port_number: Optional[int] = None       # 1 to 65535

    @classmethod
    def compile(cls, expression: Optional[str]) -> PacketFilter:
        """Parse and compile a filter expression string into a PacketFilter.

        Raises:
            FilterSyntaxError: If expression is malformed, uses unsupported syntax,
                               or combines incompatible predicates (e.g. icmp and port).
        """
        if expression is None:
            return cls()

        clean_expr = expression.strip().lower()
        if not clean_expr:
            return cls()

        if len(clean_expr) > 128:
            raise FilterSyntaxError("Filter expression exceeds maximum length of 128 characters.")

        if FORBIDDEN_FILTER_CHARS.search(clean_expr):
            raise FilterSyntaxError("Filter expression contains forbidden characters or operators.")

        tokens = clean_expr.split()
        if not tokens:
            return cls()

        # Parse grammar
        proto: Optional[str] = None
        port_mode: Optional[str] = None
        port_val: Optional[int] = None

        idx = 0
        n_tokens = len(tokens)

        # Check for leading protocol
        if tokens[idx] in VALID_PROTOCOLS:
            proto = tokens[idx]
            idx += 1

        # Check for 'and' connector if more tokens exist
        if idx < n_tokens:
            if proto is not None:
                if tokens[idx] != "and":
                    raise FilterSyntaxError(f"Expected 'and' after protocol, got '{tokens[idx]}'")
                idx += 1
                if idx >= n_tokens:
                    raise FilterSyntaxError("Trailing 'and' with no following predicate.")

            # Parse port expression: [src|dst] port <N> OR port <N>
            if tokens[idx] in ("src", "dst"):
                port_mode = tokens[idx]
                idx += 1
                if idx >= n_tokens or tokens[idx] != "port":
                    raise FilterSyntaxError("Expected 'port' after 'src'/'dst'.")
                idx += 1
            elif tokens[idx] == "port":
                port_mode = "any"
                idx += 1
            else:
                raise FilterSyntaxError(f"Unexpected token in filter: '{tokens[idx]}'")

            # Port number
            if idx >= n_tokens:
                raise FilterSyntaxError("Missing port number after 'port'.")

            raw_port = tokens[idx]
            idx += 1
            try:
                port_val = int(raw_port)
            except ValueError:
                raise FilterSyntaxError(f"Invalid port number: '{raw_port}'") from None

            if port_val < 1 or port_val > 65535:
                raise FilterSyntaxError(f"Port number {port_val} out of range [1, 65535].")

        # Ensure no trailing unparsed tokens
        if idx < n_tokens:
            raise FilterSyntaxError(f"Unrecognized trailing tokens: '{' '.join(tokens[idx:])}'")

        # Incompatibility check: icmp and arp do not have ports
        if proto in ("icmp", "arp") and port_val is not None:
            raise FilterSyntaxError(f"Protocol '{proto}' does not support port filtering.")

        return cls(protocol=proto, port_type=port_mode, port_number=port_val)

    def matches(self, packet: ParsedPacket) -> bool:
        """Evaluate compiled filter against a dissected packet.

        Returns:
            bool: True if packet satisfies all filter criteria, False otherwise.
        """
        # 1. Protocol check
        if self.protocol is not None:
            pkt_proto = (packet.protocol or "").lower()
            has_proto = self.protocol in pkt_proto
            if not has_proto and packet.layers:
                for layer in packet.layers:
                    if self.protocol in (layer.layer_name or "").lower():
                        has_proto = True
                        break
            if not has_proto:
                return False

        # 2. Port check
        if self.port_number is not None:
            src_port: Optional[int] = None
            dst_port: Optional[int] = None

            # Extract ports from packet layers
            if packet.layers:
                for layer in packet.layers:
                    layer_name_lower = (layer.layer_name or "").lower()
                    if "tcp" in layer_name_lower or "udp" in layer_name_lower:
                        for f in (layer.fields or []):
                            if f.name == "Source Port":
                                try:
                                    src_port = int(f.value.split()[0])
                                except (ValueError, TypeError, IndexError):
                                    pass
                            elif f.name == "Destination Port":
                                try:
                                    # Strip any suffix like ' (HTTPS)' or ' (53)'
                                    raw_val = f.value.split()[0]
                                    dst_port = int(raw_val)
                                except (ValueError, TypeError, IndexError):
                                    pass

            # Fallback to endpoint strings (e.g. "192.168.1.105:51234")
            if src_port is None and packet.src and ":" in packet.src:
                try:
                    src_port = int(packet.src.rsplit(":", 1)[1])
                except (ValueError, TypeError, IndexError):
                    pass

            if dst_port is None and packet.dst and ":" in packet.dst:
                try:
                    dst_port = int(packet.dst.rsplit(":", 1)[1])
                except (ValueError, TypeError, IndexError):
                    pass

            if src_port is None and dst_port is None:
                # Packet has no ports
                return False

            if self.port_type == "src":
                return src_port == self.port_number
            elif self.port_type == "dst":
                return dst_port == self.port_number
            else:  # 'any'
                return src_port == self.port_number or dst_port == self.port_number

        return True
