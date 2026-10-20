"""Application controller and service orchestrator for ITSA Network OS."""

from __future__ import annotations

import ipaddress
import json
import threading
from typing import Iterable, List, Optional, Union

from itsa_network_os.core.config import AppConfig, get_default_config, load_config
from itsa_network_os.core.health import HealthCheckService, SystemHealthReport
from itsa_network_os.core.logger import get_logger, setup_logging
from itsa_network_os.network.dns import DNSDiagnosticResult, DNSDiagnostics
from itsa_network_os.network.inspector import NetworkInspector
from itsa_network_os.network.latency import LatencyBenchmarkResult, LatencyTester
from itsa_network_os.network.models import NetworkInterface, SubnetCalculationResult
from itsa_network_os.network.routes import RouteEntry, RouteParser
from itsa_network_os.network.scope import ScopeEnclosure, ScopeGuard, ScopeViolationError
from itsa_network_os.network.subnet import SubnetCalculator
from itsa_network_os.network.wifi import (
    AccessPointInfo,
    ChannelCongestionReport,
    SpectrumBand,
    WirelessSpectrumAnalyzer,
)
from itsa_network_os.network.bandwidth import BandwidthRate, TrafficMonitorEngine
from itsa_network_os.network.spf import SPFSimulationResult, SPFSimulatorEngine
from itsa_network_os.network.vendor_manager import (
    DeviceCategory,
    DiscoveryMode,
    VendorDiscoveryReport,
    VendorManagerEngine,
)
from itsa_network_os.security.auditor import SecurityAuditReport, SecurityAuditor
from itsa_network_os.security.lab import EducationalPacketLab, ParsedPacket
from itsa_network_os.security.tls import TLSInspectionReport, TLSInspectorEngine
from itsa_network_os.security.validator import InputValidator
from itsa_network_os.storage.database import DatabaseManager


class Application:
    """Core application coordinator."""

    def __init__(self, config: Optional[AppConfig] = None) -> None:
        self.config = config or load_config()
        self.logger = setup_logging(level=self.config.log_level)
        self.database = DatabaseManager(self.config.database_file)
        self._traffic_monitor = TrafficMonitorEngine(use_mock=self.config.use_mock_network)
        self.scope_guard = ScopeGuard()
        self.logger.debug("Application initialized with configuration: %s", self.config.app_name)

    def set_authorized_scope(
        self,
        scope: Union[ScopeEnclosure, str, Iterable[str]],
        interfaces: Union[str, Iterable[str]] = (),
        allow_loopback: bool = True,
        allow_global_internet: bool = False,
    ) -> ScopeEnclosure:
        """Configure user-authorized network scope enclosure for runtime boundary enforcement."""
        if isinstance(scope, ScopeEnclosure):
            enclosure = scope
        else:
            enclosure = ScopeEnclosure.from_strings(
                cidrs=scope,
                interfaces=interfaces,
                allow_loopback=allow_loopback,
                allow_global_internet=allow_global_internet,
            )
        self.scope_guard.set_enclosure(enclosure)
        self.logger.info("Configured authorized network scope enclosure: %s", enclosure.to_dict())
        return enclosure

    def get_authorized_scope(self) -> Optional[ScopeEnclosure]:
        """Retrieve currently configured ScopeEnclosure, or None if unconstrained."""
        return self.scope_guard.enclosure

    def clear_authorized_scope(self) -> None:
        """Clear the active scope enclosure, resetting to unconstrained."""
        self.scope_guard.clear()
        self.logger.info("Cleared authorized network scope enclosure")

    # -------------------------------------------------------------------------
    # Diagnostic Session & Audit Trail Orchestration (TASK-012)
    # -------------------------------------------------------------------------

    def start_diagnostic_session(
        self,
        name: str,
        operator: Optional[str] = "system",
        metadata: Optional[Dict[str, Any]] = None,
        session_uuid: Optional[str] = None,
    ) -> int:
        """Start a new tracked diagnostic assessment session.

        Delegates persistence and metadata secret redaction to DatabaseManager.
        Attaches the currently authorized ScopeEnclosure if configured.
        """
        self.logger.info("Initiating diagnostic assessment session: '%s'", name)
        return self.database.create_diagnostic_session(
            name=name,
            operator=operator,
            scope_enclosure=self.scope_guard.enclosure,
            metadata=metadata,
            session_uuid=session_uuid,
        )

    def record_session_snapshot(
        self,
        session_id: int,
        snapshot_type: str,
        payload: Union[Dict[str, Any], List[Any], Any],
        target: Optional[str] = None,
        status: str = "COMPLETED",
    ) -> int:
        """Record an audit trail snapshot linked to an active diagnostic session.

        Delegates mandatory secret redaction and persistence to DatabaseManager.
        """
        self.logger.debug(
            "Recording session snapshot (session_id=%d, type='%s', target=%s)",
            session_id,
            snapshot_type,
            target,
        )
        return self.database.record_session_snapshot(
            session_id=session_id,
            snapshot_type=snapshot_type,
            payload=payload,
            target=target,
            status=status,
        )

    def complete_diagnostic_session(
        self,
        session_id: int,
        status: str = "COMPLETED",
        summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Finalize an active diagnostic assessment session with sanitized summary."""
        self.logger.info("Finalizing diagnostic session %d with status: %s", session_id, status)
        self.database.complete_diagnostic_session(
            session_id=session_id,
            status=status,
            summary=summary,
        )

    def get_diagnostic_session(
        self,
        session_id: Union[int, str],
        include_snapshots: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve diagnostic session record and attached snapshots."""
        return self.database.get_diagnostic_session(
            session_id=session_id,
            include_snapshots=include_snapshots,
        )

    def list_diagnostic_sessions(
        self,
        limit: int = 50,
        offset: int = 0,
        status_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical diagnostic assessment sessions."""
        return self.database.list_diagnostic_sessions(
            limit=limit,
            offset=offset,
            status_filter=status_filter,
        )

    def export_diagnostic_session(
        self,
        session_id: Union[int, str],
        format: str = "json",
        output_path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
        create_dirs: bool = False,
    ) -> Tuple[str, Optional[Path]]:
        """Export a stored diagnostic assessment session into JSON, CSV, or Markdown.

        Delegates session retrieval to DatabaseManager and export formatting to ReportExporter.
        Raises SessionNotFoundError if the session does not exist.
        """
        from itsa_network_os.reports.exporter import ReportExporter, SessionNotFoundError

        session = self.get_diagnostic_session(session_id, include_snapshots=True)
        if session is None:
            raise SessionNotFoundError(f"Diagnostic session '{session_id}' not found.")

        self.logger.info(
            "Exporting diagnostic session %s in '%s' format (output=%s)",
            session_id,
            format,
            output_path,
        )
        return ReportExporter.export_session(
            session=session,
            format=format,
            output_path=output_path,
            overwrite=overwrite,
            create_dirs=create_dirs,
        )

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

    def diagnose_dns(
        self, host: str, force_live: bool = False, interface: Optional[str] = None
    ) -> DNSDiagnosticResult:
        """Run safe DNS diagnostics for a target host."""
        use_mock = self.config.use_mock_network and not force_live
        if interface is None and self.scope_guard.enclosure and len(self.scope_guard.enclosure.interfaces) == 1:
            interface = self.scope_guard.enclosure.interfaces[0]

        if not use_mock:
            self.scope_guard.assert_authorized(host, interface=interface)
        elif self.scope_guard.is_configured:
            try:
                ipaddress.ip_address(host.strip())
                self.scope_guard.assert_authorized(host.strip(), interface=interface)
            except ValueError:
                pass

        self.logger.info("Running DNS diagnostics for '%s' (mock=%s)", host, use_mock)
        result = DNSDiagnostics.query(
            host,
            use_mock=use_mock,
            interface=interface,
            scope_guard=self.scope_guard if not use_mock else None,
        )

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
        self,
        host: str,
        port: int = 443,
        count: int = 4,
        force_live: bool = False,
        interface: Optional[str] = None,
    ) -> LatencyBenchmarkResult:
        """Run safe non-root latency benchmark."""
        use_mock = self.config.use_mock_network and not force_live
        if interface is None and self.scope_guard.enclosure and len(self.scope_guard.enclosure.interfaces) == 1:
            interface = self.scope_guard.enclosure.interfaces[0]

        if not use_mock:
            self.scope_guard.assert_authorized(host, interface=interface)
        elif self.scope_guard.is_configured:
            self.scope_guard.assert_authorized(host, interface=interface)

        self.logger.info("Benchmarking latency to %s:%d (count=%d, mock=%s)", host, port, count, use_mock)
        result = LatencyTester.benchmark(
            host,
            port=port,
            count=count,
            use_mock=use_mock,
            interface=interface,
            scope_guard=self.scope_guard if not use_mock else None,
        )

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

    def get_wifi_access_points(self, force_live: bool = False) -> List[AccessPointInfo]:
        """Discover wireless access points (offline-first mock by default, non-destructive)."""
        use_mock = self.config.use_mock_network and not force_live
        self.logger.info("Scanning Wi-Fi access points (mock=%s)", use_mock)
        return WirelessSpectrumAnalyzer.get_access_points(use_mock=use_mock)

    def analyze_wifi_spectrum(
        self, band: SpectrumBand = SpectrumBand.BAND_2_4_GHZ, force_live: bool = False
    ) -> List[ChannelCongestionReport]:
        """Analyze wireless spectrum utilization and RF channel interference."""
        aps = self.get_wifi_access_points(force_live=force_live)
        self.logger.info("Analyzing Wi-Fi spectrum for band %s across %d APs", band.value, len(aps))
        return WirelessSpectrumAnalyzer.analyze_spectrum(aps, band=band)

    def sample_bandwidth(self, force_live: bool = False) -> List[BandwidthRate]:
        """Sample network adapter traffic velocity, throughput rates, and packet flow."""
        use_mock = self.config.use_mock_network and not force_live
        if self._traffic_monitor.use_mock != use_mock:
            self._traffic_monitor = TrafficMonitorEngine(use_mock=use_mock)

        samples = self._traffic_monitor.sample_all()
        rates = self._traffic_monitor.calculate_rates(samples)
        self.logger.debug("Sampled traffic flow for %d network adapters", len(rates))
        return rates

    def inspect_tls(
        self,
        host: str,
        port: int = 443,
        force_live: bool = False,
        interface: Optional[str] = None,
    ) -> TLSInspectionReport:
        """Inspect TLS endpoint certificates, cipher suites, and cryptographic integrity."""
        sanitized_host = InputValidator.validate_hostname(host)
        sanitized_port = InputValidator.validate_port(port)
        use_mock = self.config.use_mock_network and not force_live
        if interface is None and self.scope_guard.enclosure and len(self.scope_guard.enclosure.interfaces) == 1:
            interface = self.scope_guard.enclosure.interfaces[0]

        if not use_mock:
            self.scope_guard.assert_authorized(sanitized_host, interface=interface)
        elif self.scope_guard.is_configured:
            self.scope_guard.assert_authorized(sanitized_host, interface=interface)

        self.logger.info("Executing TLS inspection for %s:%d (mock=%s)", sanitized_host, sanitized_port, use_mock)
        return TLSInspectorEngine.inspect(
            host=sanitized_host,
            port=sanitized_port,
            use_mock=use_mock,
            interface=interface,
            scope_guard=self.scope_guard if not use_mock else None,
        )

    def simulate_spf(
        self, source: str = "R1", failed_link: Optional[str] = None
    ) -> SPFSimulationResult:
        """Run educational Dijkstra SPF shortest-path link-state calculation."""
        sanitized_source = InputValidator.validate_interface_name(source) if source else "R1"
        self.logger.info(
            "Simulating OSPF Dijkstra SPF tree from root '%s' (failed_link=%s)",
            sanitized_source,
            failed_link,
        )
        return SPFSimulatorEngine.calculate_spf(source_id=sanitized_source, failed_link_id=failed_link)

    def discover_vendor_devices(
        self,
        category: Optional[str] = None,
        force_live: bool = False,
        timeout: float = 5.0,
        interface: Optional[str] = None,
        mndp_socket_factory: Optional[Any] = None,
        onvif_socket_factory: Optional[Any] = None,
        mode: Optional[Union[DiscoveryMode, str]] = None,
        use_mock: Optional[bool] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> VendorDiscoveryReport:
        """Discover and inspect multi-vendor hardware (MikroTik, Ubiquiti, TP-Link CPE, ONVIF Cameras).

        Mode resolution rules:
        - If mode is specified, it takes canonical precedence.
        - If use_mock is specified without mode, it resolves to MOCK if True, LIVE_PASSIVE if False.
        - If force_live=True is specified, it resolves to LIVE_PASSIVE.
        - Contradictory combinations (e.g., force_live=True with use_mock=True or mode='mock') raise ValueError.
        - Explicit live requests (force_live=True or mode=LIVE_PASSIVE or use_mock=False) can never be overridden
          by application configuration.
        - If neither mode, use_mock, nor force_live=True is passed, falls back to config.use_mock_network.
        """
        cat_enum: Optional[DeviceCategory] = None
        if category:
            cat_lower = category.lower().strip()
            if "cam" in cat_lower or "cctv" in cat_lower:
                cat_enum = DeviceCategory.IP_CAMERA
            elif "mikro" in cat_lower or "routeros" in cat_lower:
                cat_enum = DeviceCategory.MIKROTIK
            elif "ubnt" in cat_lower or "ubiquiti" in cat_lower or "unifi" in cat_lower:
                cat_enum = DeviceCategory.UBIQUITI
            elif "tp" in cat_lower or "cpe" in cat_lower or "pharos" in cat_lower:
                cat_enum = DeviceCategory.TPLINK_CPE
            elif "linux" in cat_lower or "ubuntu" in cat_lower or "srv" in cat_lower:
                cat_enum = DeviceCategory.LINUX_SERVER

        # Validate and resolve canonical discovery mode
        if mode is not None:
            if isinstance(mode, DiscoveryMode):
                norm_mode = mode
            elif isinstance(mode, str):
                try:
                    norm_mode = DiscoveryMode(mode)
                except ValueError:
                    raise ValueError(
                        f"Invalid discovery mode: {mode!r}. Must be one of {[m.value for m in DiscoveryMode]}"
                    )
            else:
                raise TypeError(
                    f"mode must be a DiscoveryMode or str, got {type(mode).__name__}"
                )

            # Check contradictions with use_mock
            if use_mock is not None:
                if norm_mode == DiscoveryMode.LIVE_PASSIVE and use_mock is True:
                    raise ValueError(
                        "Contradictory discovery parameters: mode='live_passive' conflicts with use_mock=True"
                    )
                if norm_mode == DiscoveryMode.MOCK and use_mock is False:
                    raise ValueError(
                        "Contradictory discovery parameters: mode='mock' conflicts with use_mock=False"
                    )

            # Check contradictions with force_live
            if force_live and norm_mode == DiscoveryMode.MOCK:
                raise ValueError(
                    "Contradictory discovery parameters: force_live=True conflicts with mode='mock'"
                )

        elif use_mock is not None:
            if force_live and use_mock is True:
                raise ValueError(
                    "Contradictory discovery parameters: force_live=True conflicts with use_mock=True"
                )
            norm_mode = DiscoveryMode.MOCK if use_mock else DiscoveryMode.LIVE_PASSIVE

        elif force_live:
            norm_mode = DiscoveryMode.LIVE_PASSIVE

        else:
            norm_mode = (
                DiscoveryMode.MOCK
                if self.config.use_mock_network
                else DiscoveryMode.LIVE_PASSIVE
            )

        if interface is None and self.scope_guard.enclosure and len(self.scope_guard.enclosure.interfaces) == 1:
            interface = self.scope_guard.enclosure.interfaces[0]

        self.logger.info(
            "Executing multi-vendor device discovery (filter=%s, mode=%s, timeout=%.1fs, iface=%s)",
            cat_enum,
            norm_mode.value,
            timeout,
            interface,
        )
        return VendorManagerEngine.discover_devices(
            category_filter=cat_enum,
            mode=norm_mode,
            timeout=timeout,
            interface=interface,
            scope_guard=self.scope_guard if norm_mode == DiscoveryMode.LIVE_PASSIVE else None,
            mndp_socket_factory=mndp_socket_factory,
            onvif_socket_factory=onvif_socket_factory,
            stop_event=stop_event,
        )

