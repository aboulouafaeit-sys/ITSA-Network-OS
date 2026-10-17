"""Application controller and service orchestrator for ITSA Network OS."""

from __future__ import annotations

import json
from typing import List, Optional

from itsa_network_os.core.config import AppConfig, get_default_config, load_config
from itsa_network_os.core.health import HealthCheckService, SystemHealthReport
from itsa_network_os.core.logger import get_logger, setup_logging
from itsa_network_os.network.dns import DNSDiagnosticResult, DNSDiagnostics
from itsa_network_os.network.inspector import NetworkInspector
from itsa_network_os.network.latency import LatencyBenchmarkResult, LatencyTester
from itsa_network_os.network.models import NetworkInterface, SubnetCalculationResult
from itsa_network_os.network.routes import RouteEntry, RouteParser
from itsa_network_os.network.subnet import SubnetCalculator
from itsa_network_os.security.auditor import SecurityAuditReport, SecurityAuditor
from itsa_network_os.security.lab import EducationalPacketLab, ParsedPacket
from itsa_network_os.storage.database import DatabaseManager


class Application:
    """Core application coordinator."""

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or load_config()
        self.logger = setup_logging(level=self.config.log_level)
        self.database = DatabaseManager(self.config.database_file)
        self.logger.debug("Application initialized with configuration: %s", self.config.app_name)

    def check_health(self) -> SystemHealthReport:
        """Run system diagnostics."""
        self.logger.info("Executing read-only health checks")
        return HealthCheckService.run_health_check()

    def calculate_subnet(self, cidr: str) -> SubnetCalculationResult:
        """Calculate network subnet parameters and persist event."""
        self.logger.info("Calculating subnet for CIDR: %s", cidr)
        result = SubnetCalculator.calculate(cidr)

        # Record in local SQLite database safely
        try:
            self.database.record_subnet_query(
                cidr=result.cidr,
                usable_hosts=result.usable_hosts,
                net_addr=result.network_address,
                bcast_addr=result.broadcast_address,
            )
        except Exception as exc:
            self.logger.warning("Could not persist subnet calculation to local db: %s", exc)

        return result

    def get_network_interfaces(self, force_live: bool = False) -> List[NetworkInterface]:
        """Fetch network interfaces using configured or requested provider."""
        use_mock = self.config.use_mock_network and not force_live
        mode_str = "mock" if use_mock else "host read-only"
        self.logger.info("Querying interfaces in %s mode", mode_str)

        inspector = NetworkInspector(use_mock=use_mock)
        return inspector.list_interfaces()

    def diagnose_dns(self, host: str, force_live: bool = False) -> DNSDiagnosticResult:
        """Run safe DNS diagnostics for a target host."""
        use_mock = self.config.use_mock_network and not force_live
        self.logger.info("Running DNS diagnostics for '%s' (mock=%s)", host, use_mock)
        result = DNSDiagnostics.query(host, use_mock=use_mock)

        try:
            records_json = json.dumps([r.to_dict() for r in result.records])
            self.database.record_dns_query(
                host=result.target_host,
                status=result.status,
                response_time_ms=result.response_time_ms,
                records_json=records_json,
            )
        except Exception as exc:
            self.logger.warning("Could not persist DNS query to local db: %s", exc)

        return result

    def benchmark_latency(
        self, host: str, port: int = 443, count: int = 4, force_live: bool = False
    ) -> LatencyBenchmarkResult:
        """Run safe non-root latency benchmark."""
        use_mock = self.config.use_mock_network and not force_live
        self.logger.info("Benchmarking latency to %s:%d (count=%d, mock=%s)", host, port, count, use_mock)
        result = LatencyTester.benchmark(host, port=port, count=count, use_mock=use_mock)

        try:
            self.database.record_latency_benchmark(
                host=result.target_host,
                port=result.target_port,
                packet_loss=result.packet_loss_percent,
                avg_latency_ms=result.avg_latency_ms,
                jitter_ms=result.jitter_ms,
            )
        except Exception as exc:
            self.logger.warning("Could not persist latency benchmark to local db: %s", exc)

        return result

    def run_security_audit(self, force_live: bool = False) -> SecurityAuditReport:
        """Execute non-destructive security auditing."""
        use_mock = self.config.use_mock_network and not force_live
        self.logger.info("Running security audit (mock=%s)", use_mock)
        return SecurityAuditor.run_audit(use_mock=use_mock)

    def get_packet_lab_trace(self) -> List[ParsedPacket]:
        """Fetch educational synthetic packet trace for protocol dissection."""
        self.logger.info("Generating educational packet analysis trace")
        return EducationalPacketLab.get_sample_trace()

    def get_routing_table(self, force_live: bool = False) -> List[RouteEntry]:
        """Inspect system routing table entries in read-only mode."""
        use_mock = self.config.use_mock_network and not force_live
        self.logger.info("Querying routing table (mock=%s)", use_mock)
        return RouteParser.get_routes(use_mock=use_mock)

    def get_topology(self) -> NetworkTopology:
        """Fetch network topology graph with computed node coordinates."""
        from itsa_network_os.network.topology import NetworkTopology, TopologyDiscoveryEngine
        self.logger.info("Synthesizing network topology graph")
        return TopologyDiscoveryEngine.get_default_topology()
