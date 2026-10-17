"""CIDR Subnet calculation engine for IPv4 and IPv6 networks."""

from __future__ import annotations

import ipaddress
from typing import Union

from itsa_network_os.network.models import SubnetCalculationResult
from itsa_network_os.security.validator import InputValidator, SecurityValidationError


class SubnetCalculationError(ValueError):
    """Raised when subnet calculation encounters an invalid parameter."""


class SubnetCalculator:
    """High-precision IP subnet calculator implementing RFC networking rules."""

    @classmethod
    def calculate(cls, cidr: str) -> SubnetCalculationResult:
        """Parse and calculate subnet information for an IPv4 or IPv6 network."""
        try:
            net = InputValidator.validate_ip_network(cidr)
        except SecurityValidationError as exc:
            raise SubnetCalculationError(str(exc)) from exc

        if isinstance(net, ipaddress.IPv4Network):
            return cls._calculate_ipv4(net)
        elif isinstance(net, ipaddress.IPv6Network):
            return cls._calculate_ipv6(net)
        else:
            raise SubnetCalculationError(f"Unsupported network type: {type(net)}")

    @classmethod
    def _calculate_ipv4(cls, net: ipaddress.IPv4Network) -> SubnetCalculationResult:
        """Calculate detailed IPv4 subnet parameters."""
        prefix = net.prefixlen
        total_hosts = net.num_addresses
        wildcard_int = int(net.hostmask)
        wildcard_str = str(ipaddress.IPv4Address(wildcard_int))

        if prefix == 32:
            usable_hosts = 1
            first_ip = str(net.network_address)
            last_ip = str(net.network_address)
            broadcast = str(net.network_address)
        elif prefix == 31:
            # RFC 3021 point-to-point links
            usable_hosts = 2
            first_ip = str(net.network_address)
            last_ip = str(net.broadcast_address)
            broadcast = str(net.broadcast_address)
        else:
            usable_hosts = max(0, total_hosts - 2)
            first_ip = str(net.network_address + 1)
            last_ip = str(net.broadcast_address - 1)
            broadcast = str(net.broadcast_address)

        return SubnetCalculationResult(
            cidr=str(net),
            ip_version=4,
            network_address=str(net.network_address),
            netmask=str(net.netmask),
            wildcard_mask=wildcard_str,
            broadcast_address=broadcast,
            total_hosts=total_hosts,
            usable_hosts=usable_hosts,
            first_usable_ip=first_ip,
            last_usable_ip=last_ip,
        )

    @classmethod
    def _calculate_ipv6(cls, net: ipaddress.IPv6Network) -> SubnetCalculationResult:
        """Calculate IPv6 network parameters."""
        total_hosts = net.num_addresses
        return SubnetCalculationResult(
            cidr=str(net),
            ip_version=6,
            network_address=str(net.network_address),
            netmask=str(net.netmask),
            wildcard_mask=str(net.hostmask),
            broadcast_address="N/A (IPv6 uses Multicast)",
            total_hosts=total_hosts,
            usable_hosts=total_hosts,
            first_usable_ip=str(net.network_address),
            last_usable_ip=str(net[total_hosts - 1]) if total_hosts <= 65536 else f"{net.network_address} + {total_hosts - 1}",
        )
