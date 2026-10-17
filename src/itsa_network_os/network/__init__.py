"""Networking subsystem for ITSA Network OS."""

from itsa_network_os.network.dns import DNSDiagnosticResult, DNSDiagnostics, DNSRecord
from itsa_network_os.network.inspector import (
    HostNetworkProvider,
    MockNetworkProvider,
    NetworkInspector,
    NetworkProvider,
)
from itsa_network_os.network.latency import (
    LatencyBenchmarkResult,
    LatencyProbe,
    LatencyTester,
)
from itsa_network_os.network.models import (
    InterfaceState,
    InterfaceType,
    IPAddressInfo,
    NetworkInterface,
    SubnetCalculationResult,
)
from itsa_network_os.network.routes import RouteEntry, RouteParser, VlanInfo
from itsa_network_os.network.subnet import SubnetCalculationError, SubnetCalculator
from itsa_network_os.network.topology import (
    NetworkTopology,
    NodeStatus,
    TopologyDiscoveryEngine,
    TopologyLink,
    TopologyNode,
    TopologyNodeType,
)

__all__ = [
    "InterfaceState",
    "InterfaceType",
    "IPAddressInfo",
    "NetworkInterface",
    "SubnetCalculationResult",
    "SubnetCalculator",
    "SubnetCalculationError",
    "NetworkProvider",
    "MockNetworkProvider",
    "HostNetworkProvider",
    "NetworkInspector",
    "DNSDiagnostics",
    "DNSRecord",
    "DNSDiagnosticResult",
    "LatencyTester",
    "LatencyProbe",
    "LatencyBenchmarkResult",
    "RouteEntry",
    "VlanInfo",
    "RouteParser",
    "TopologyNode",
    "TopologyLink",
    "NetworkTopology",
    "TopologyNodeType",
    "NodeStatus",
    "TopologyDiscoveryEngine",
]
