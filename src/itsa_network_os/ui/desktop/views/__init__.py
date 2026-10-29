"""Modular desktop GUI view components for ITSA Network OS."""

from itsa_network_os.ui.desktop.views.overview_view import SystemOverviewView
from itsa_network_os.ui.desktop.views.subnet_view import SubnetCalculatorView
from itsa_network_os.ui.desktop.views.interfaces_view import InterfacesView
from itsa_network_os.ui.desktop.views.dns_view import DNSDiagnosticsView
from itsa_network_os.ui.desktop.views.latency_view import LatencyBenchmarkView
from itsa_network_os.ui.desktop.views.security_audit_view import SecurityAuditView
from itsa_network_os.ui.desktop.views.packet_lab_view import PacketLabView
from itsa_network_os.ui.desktop.views.routes_view import RoutingTableView
from itsa_network_os.ui.desktop.views.asset_detail_inspector import AssetDetailInspector
from itsa_network_os.ui.desktop.views.asset_inventory_view import AssetInventoryView

__all__ = [
    "SystemOverviewView",
    "SubnetCalculatorView",
    "InterfacesView",
    "DNSDiagnosticsView",
    "LatencyBenchmarkView",
    "SecurityAuditView",
    "PacketLabView",
    "RoutingTableView",
    "AssetDetailInspector",
    "AssetInventoryView",
]
