"""Network topology modeling, graph synthesis, and layout engine."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TopologyNodeType(str, Enum):
    """Classification of network topology nodes."""

    INTERNET = "Internet"
    GATEWAY = "Gateway"
    ROUTER = "Router"
    SWITCH = "Switch"
    SERVER = "Server"
    WORKSTATION = "Workstation"
    SUBNET = "Subnet"


class NodeStatus(str, Enum):
    """Operational status of topology node."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class TopologyNode:
    """Individual node within the network graph."""

    id: str
    label: str
    node_type: TopologyNodeType
    ip_address: str
    mac_address: str = ""
    status: NodeStatus = NodeStatus.ONLINE
    x: float = 0.0
    y: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class TopologyLink:
    """Interconnection edge between topology nodes."""

    id: str
    source_id: str
    target_id: str
    link_type: str = "Ethernet"
    speed_mbps: int = 1000
    latency_ms: float = 0.5
    status: str = "ACTIVE"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkTopology:
    """Consolidated graph structure representing network topology."""

    nodes: List[TopologyNode] = field(default_factory=list)
    links: List[TopologyLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
        }

    def compute_hierarchical_layout(self, width: float = 900.0, height: float = 550.0) -> None:
        """Calculate aesthetic 2D coordinates for nodes arranged in hierarchical tiers."""
        # Group nodes by tier
        tier_map = {
            TopologyNodeType.INTERNET: 0,
            TopologyNodeType.GATEWAY: 1,
            TopologyNodeType.ROUTER: 1,
            TopologyNodeType.SWITCH: 2,
            TopologyNodeType.SUBNET: 2,
            TopologyNodeType.SERVER: 3,
            TopologyNodeType.WORKSTATION: 3,
        }

        tiers: Dict[int, List[TopologyNode]] = {0: [], 1: [], 2: [], 3: []}
        for node in self.nodes:
            tier_idx = tier_map.get(node.node_type, 3)
            tiers[tier_idx].append(node)

        total_tiers = len(tiers)
        y_step = height / (total_tiers + 1)

        updated_nodes: List[TopologyNode] = []
        for tier_idx, node_list in tiers.items():
            count = len(node_list)
            y_pos = (tier_idx + 1) * y_step
            x_step = width / (count + 1) if count > 0 else width / 2

            for i, n in enumerate(node_list):
                x_pos = (i + 1) * x_step
                updated_nodes.append(
                    TopologyNode(
                        id=n.id,
                        label=n.label,
                        node_type=n.node_type,
                        ip_address=n.ip_address,
                        mac_address=n.mac_address,
                        status=n.status,
                        x=round(x_pos, 1),
                        y=round(y_pos, 1),
                        details=n.details,
                    )
                )

        self.nodes = updated_nodes


class TopologyDiscoveryEngine:
    """Discovers and compiles topology models from local interfaces and routing tables."""

    @classmethod
    def get_default_topology(cls) -> NetworkTopology:
        """Generate rich, realistic network topology for interactive visualization and analysis."""
        nodes = [
            TopologyNode(
                id="wan-0",
                label="Internet Gateway Uplink",
                node_type=TopologyNodeType.INTERNET,
                ip_address="WAN / Public",
                status=NodeStatus.ONLINE,
                details={"Provider": "ISP Fiber", "MTU": 1500},
            ),
            TopologyNode(
                id="router-1",
                label="Core Edge Router (gw01)",
                node_type=TopologyNodeType.GATEWAY,
                ip_address="192.168.1.1",
                mac_address="00:50:56:fd:aa:01",
                status=NodeStatus.ONLINE,
                details={"Hostname": "gw01.itsa.local", "OS": "Debian Linux"},
            ),
            TopologyNode(
                id="switch-1",
                label="Main Distribution Switch",
                node_type=TopologyNodeType.SWITCH,
                ip_address="192.168.1.2",
                mac_address="00:50:56:fe:10:02",
                status=NodeStatus.ONLINE,
                details={"VLANs": [1, 10, 20], "Ports": 24},
            ),
            TopologyNode(
                id="server-dns",
                label="Internal DNS & DHCP Server",
                node_type=TopologyNodeType.SERVER,
                ip_address="192.168.1.10",
                mac_address="02:42:0a:11:00:10",
                status=NodeStatus.ONLINE,
                details={"Services": ["DNS (53)", "DHCP (67)"]},
            ),
            TopologyNode(
                id="server-web",
                label="Secured Intranet Web Server",
                node_type=TopologyNodeType.SERVER,
                ip_address="192.168.1.20",
                mac_address="02:42:0a:11:00:20",
                status=NodeStatus.ONLINE,
                details={"Services": ["HTTPS (443)"]},
            ),
            TopologyNode(
                id="host-admin",
                label="ITSA Admin Workstation",
                node_type=TopologyNodeType.WORKSTATION,
                ip_address="192.168.1.105",
                mac_address="02:42:0a:11:00:02",
                status=NodeStatus.ONLINE,
                details={"User": "Engineer", "Client": "Debian 13"},
            ),
            TopologyNode(
                id="host-lab",
                label="Cybersecurity Lab Host",
                node_type=TopologyNodeType.WORKSTATION,
                ip_address="192.168.1.150",
                mac_address="02:42:0a:11:00:50",
                status=NodeStatus.ONLINE,
                details={"Environment": "Isolated Sandbox"},
            ),
        ]

        links = [
            TopologyLink(id="l-wan-r1", source_id="wan-0", target_id="router-1", speed_mbps=1000, latency_ms=8.5),
            TopologyLink(id="l-r1-sw1", source_id="router-1", target_id="switch-1", speed_mbps=1000, latency_ms=0.2),
            TopologyLink(id="l-sw1-dns", source_id="switch-1", target_id="server-dns", speed_mbps=1000, latency_ms=0.3),
            TopologyLink(id="l-sw1-web", source_id="switch-1", target_id="server-web", speed_mbps=1000, latency_ms=0.3),
            TopologyLink(id="l-sw1-admin", source_id="switch-1", target_id="host-admin", speed_mbps=1000, latency_ms=0.4),
            TopologyLink(id="l-sw1-lab", source_id="switch-1", target_id="host-lab", speed_mbps=100, latency_ms=0.6),
        ]

        topo = NetworkTopology(nodes=nodes, links=links)
        topo.compute_hierarchical_layout()
        return topo
