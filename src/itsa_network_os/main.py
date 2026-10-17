"""Primary CLI and GUI entry point for ITSA Network OS."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from itsa_network_os import __app_name__, __version__
from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.network.subnet import SubnetCalculationError
from itsa_network_os.reports.exporter import ReportExporter
from itsa_network_os.security.validator import SecurityValidationError
from itsa_network_os.ui.cli import TerminalFormatter


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="itsa-network-os",
        description=f"{__app_name__} — Modular Network Engineering & Cybersecurity Platform",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} v{__version__}",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the desktop graphical dashboard (requires PySide6)",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Run system and runtime health diagnostics",
    )
    parser.add_argument(
        "--calc-subnet",
        metavar="CIDR",
        type=str,
        help="Calculate IPv4 or IPv6 subnet parameters (e.g., 192.168.1.0/24 or 10.0.0.0/22)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces (uses safe mock provider by default)",
    )
    parser.add_argument(
        "--dns",
        metavar="HOST",
        type=str,
        help="Run non-destructive DNS resolution and latency check on target host",
    )
    parser.add_argument(
        "--latency",
        metavar="HOST",
        type=str,
        help="Benchmark TCP round-trip latency to target host without root privileges",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="Target port for latency benchmark or TLS inspection (default: 443)",
    )
    parser.add_argument(
        "--tls",
        metavar="HOST",
        type=str,
        help="Inspect TLS/SSL certificates, cipher suites, and cryptographic posture on target host",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=4,
        help="Number of latency probes to execute (default: 4)",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Run non-destructive local cybersecurity posture and service audit",
    )
    parser.add_argument(
        "--lab",
        action="store_true",
        help="Run educational cybersecurity packet and protocol dissection laboratory",
    )
    parser.add_argument(
        "--routes",
        action="store_true",
        help="Inspect system routing table entries safely (read-only)",
    )
    parser.add_argument(
        "--topology",
        action="store_true",
        help="Synthesize and inspect network topology graph and interconnects",
    )
    parser.add_argument(
        "--wifi-scan",
        action="store_true",
        help="Scan and list nearby wireless access points and security ratings",
    )
    parser.add_argument(
        "--wifi-spectrum",
        action="store_true",
        help="Analyze RF spectrum channel congestion and cleanest channel recommendations",
    )
    parser.add_argument(
        "--bandwidth",
        action="store_true",
        help="Sample real-time network adapter throughput rates, bandwidth, and packet counters",
    )
    parser.add_argument(
        "--spf",
        action="store_true",
        help="Simulate OSPF Dijkstra Shortest Path First (SPF) routing table calculation and link-state convergence",
    )
    parser.add_argument(
        "--source",
        type=str,
        default="R1",
        help="Root router identifier for SPF tree calculation (default: R1)",
    )
    parser.add_argument(
        "--fail-link",
        type=str,
        default=None,
        metavar="LINK_ID",
        help="Simulate link failure to evaluate dynamic OSPF re-convergence (e.g. R1-R2)",
    )
    parser.add_argument(
        "--vendor-scan",
        action="store_true",
        help="Scan and inventory multi-vendor hardware (MikroTik, Ubiquiti, TP-Link CPE, ONVIF Cameras)",
    )
    parser.add_argument(
        "--cams",
        action="store_true",
        help="Filter specifically for IP surveillance cameras, RTSP streams, and ONVIF specifications",
    )
    parser.add_argument(
        "--vendor",
        type=str,
        default=None,
        help="Filter discovered devices by vendor or category (e.g. mikrotik, ubiquiti, tplink, camera, linux)",
    )
    parser.add_argument(
        "--band",
        choices=["2.4ghz", "5ghz"],
        default="2.4ghz",
        help="Frequency band for spectrum analysis (default: 2.4ghz)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Execute live queries instead of using safe mock provider",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Application main entry point function."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Initialize application with safe defaults (in-memory SQLite for ephemeral CLI runs)
    config = AppConfig(database_file=":memory:")
    app = Application(config=config)

    # Handle desktop GUI launch
    if args.gui:
        try:
            from itsa_network_os.ui.desktop.launcher import launch_gui
            return launch_gui(app)
        except Exception as exc:
            print(f"Error launching graphical interface: {exc}", file=sys.stderr)
            return 1

    # If no functional arguments provided, print banner and help
    has_command = (
        args.health
        or args.calc_subnet
        or args.list_interfaces
        or args.dns
        or args.latency
        or args.audit
        or args.lab
        or args.routes
        or args.topology
        or args.wifi_scan
        or args.wifi_spectrum
        or args.bandwidth
        or args.tls
        or args.spf
        or args.vendor_scan
        or args.cams
    )
    if not has_command:
        TerminalFormatter.print_banner()
        parser.print_help()
        return 0

    try:
        if args.health:
            report = app.check_health()
            if args.json:
                print(ReportExporter.to_json(report.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_health_report(report)
            return 0

        if args.calc_subnet:
            result = app.calculate_subnet(args.calc_subnet)
            if args.json:
                print(ReportExporter.to_json(result.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_subnet_result(result)
            return 0

        if args.list_interfaces:
            interfaces = app.get_network_interfaces(force_live=args.live)
            if args.json:
                data = [i.to_dict() for i in interfaces]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_interfaces(interfaces)
            return 0

        if args.dns:
            dns_result = app.diagnose_dns(args.dns, force_live=args.live)
            if args.json:
                print(ReportExporter.to_json(dns_result.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_dns_result(dns_result)
            return 0

        if args.latency:
            latency_result = app.benchmark_latency(
                host=args.latency,
                port=args.port,
                count=args.count,
                force_live=args.live,
            )
            if args.json:
                print(ReportExporter.to_json(latency_result.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_latency_result(latency_result)
            return 0

        if args.audit:
            audit_report = app.run_security_audit(force_live=args.live)
            if args.json:
                print(ReportExporter.to_json(audit_report.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_security_audit(audit_report)
            return 0

        if args.lab:
            packets = app.get_packet_lab_trace()
            if args.json:
                data = [p.to_dict() for p in packets]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_packet_lab(packets)
            return 0

        if args.routes:
            routes = app.get_routing_table(force_live=args.live)
            if args.json:
                data = [r.to_dict() for r in routes]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_routes(routes)
            return 0

        if args.topology:
            topology = app.get_topology()
            if args.json:
                print(ReportExporter.to_json(topology.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_topology(topology)
            return 0

        if args.wifi_scan:
            aps = app.get_wifi_access_points(force_live=args.live)
            if args.json:
                data = [ap.to_dict() for ap in aps]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_wifi_scan(aps)
            return 0

        if args.wifi_spectrum:
            from itsa_network_os.network.wifi import SpectrumBand
            band = SpectrumBand.BAND_5_GHZ if args.band.lower() == "5ghz" else SpectrumBand.BAND_2_4_GHZ
            reports = app.analyze_wifi_spectrum(band=band, force_live=args.live)
            if args.json:
                data = [r.to_dict() for r in reports]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_wifi_spectrum(reports, band_name=band.value)
            return 0

        if args.bandwidth:
            rates = app.sample_bandwidth(force_live=args.live)
            if args.json:
                data = [r.to_dict() for r in rates]
                print(ReportExporter.to_json(data))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_bandwidth_monitor(rates)
            return 0

        if args.tls:
            tls_report = app.inspect_tls(args.tls, port=args.port, force_live=args.live)
            if args.json:
                print(ReportExporter.to_json(tls_report.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_tls_inspection(tls_report)
            return 0

        if args.spf:
            spf_result = app.simulate_spf(source=args.source, failed_link=args.fail_link)
            if args.json:
                print(ReportExporter.to_json(spf_result.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_spf_simulation(spf_result)
            return 0

        if args.vendor_scan or args.cams:
            filter_cat = "camera" if args.cams else args.vendor
            vendor_report = app.discover_vendor_devices(category=filter_cat, force_live=args.live)
            if args.json:
                print(ReportExporter.to_json(vendor_report.to_dict()))
            else:
                TerminalFormatter.print_banner()
                TerminalFormatter.print_vendor_discovery(vendor_report)
            return 0

    except (SecurityValidationError, SubnetCalculationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected operational error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
