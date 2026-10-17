"""Export formatters for diagnostic results and network data."""

from __future__ import annotations

import json
from typing import Any, Dict


class ReportExporter:
    """Format and export reports into standardized representations."""

    @staticmethod
    def to_json(data: Dict[str, Any] | list[Any], indent: int = 2) -> str:
        """Export data structure as formatted JSON."""
        return json.dumps(data, indent=indent)

    @staticmethod
    def format_subnet_text(result_dict: Dict[str, Any]) -> str:
        """Render subnet calculation as clean key-value text."""
        lines = [
            "============================================================",
            f" Subnet Report: {result_dict.get('cidr')}",
            "============================================================",
            f" IP Version         : IPv{result_dict.get('ip_version')}",
            f" Network Address    : {result_dict.get('network_address')}",
            f" Subnet Netmask     : {result_dict.get('netmask')}",
            f" Wildcard Hostmask  : {result_dict.get('wildcard_mask')}",
            f" Broadcast Address  : {result_dict.get('broadcast_address')}",
            f" Total Host Space   : {result_dict.get('total_hosts'):,}",
            f" Usable Host Space  : {result_dict.get('usable_hosts'):,}",
            f" Usable Host Range  : {result_dict.get('first_usable_ip')} -> {result_dict.get('last_usable_ip')}",
            "============================================================",
        ]
        return "\n".join(lines)
