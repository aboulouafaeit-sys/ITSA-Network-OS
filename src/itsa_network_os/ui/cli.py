"""Command line user interface utilities for ITSA Network OS."""

from __future__ import annotations

import sys
from typing import Any, List

from itsa_network_os.core.health import SystemHealthReport
from itsa_network_os.network.dns import DNSDiagnosticResult
from itsa_network_os.network.bandwidth import BandwidthRate, format_total_bytes
from itsa_network_os.network.latency import LatencyBenchmarkResult
from itsa_network_os.network.models import NetworkInterface, SubnetCalculationResult
from itsa_network_os.network.routes import RouteEntry
from itsa_network_os.network.wifi import AccessPointInfo, ChannelCongestionReport
from itsa_network_os.security.auditor import SecurityAuditReport
from itsa_network_os.security.lab import ParsedPacket
from itsa_network_os.network.spf import SPFSimulationResult
from itsa_network_os.network.vendor_manager import VendorDiscoveryReport
from itsa_network_os.security.tls import TLSInspectionReport


class TerminalFormatter:
    """Format tabular data and diagnostic cards for standard terminal output."""

    @staticmethod
    def print_banner() -> None:
        """Display ASCII header banner."""
        banner = (
            "============================================================\n"
            "            ITSA Network OS — Core Platform                 \n"
            "   Modular Network Engineering & Cybersecurity Environment  \n"
            "============================================================"
        )
        print(banner)

    @staticmethod
    def print_health_report(report: SystemHealthReport) -> None:
        """Render health check results."""
        status_marker = "[OK]" if report.status.value == "HEALTHY" else f"[{report.status.value}]"
        print(f"\nSystem Status: {status_marker}")
        print(f"  • Platform          : {report.platform_name} ({report.architecture})")
        print(f"  • Python Runtime    : {report.python_version}")
        print(f"  • Virtual Env Active: {'Yes' if report.is_virtual_env else 'No (Direct System Interpreter)'}")
        print(f"  • Non-Root Privilege: {'Yes (Safe)' if report.user_non_root else 'No (Running as root)'}")
        print(f"  • Free Home Disk    : {report.disk_free_gb} GB")

        if report.issues:
            print("\n  Advisory Notices:")
            for issue in report.issues:
                print(f"    - {issue}")
        print()

    @staticmethod
    def print_subnet_result(result: SubnetCalculationResult) -> None:
        """Render subnet calculation card."""
        print("\n------------------------------------------------------------")
        print(f" Subnet Breakdown: {result.cidr}")
        print("------------------------------------------------------------")
        print(f"  • IP Version       : IPv{result.ip_version}")
        print(f"  • Network Address  : {result.network_address}")
        print(f"  • Netmask          : {result.netmask}")
        print(f"  • Wildcard Mask    : {result.wildcard_mask}")
        print(f"  • Broadcast Address: {result.broadcast_address}")
        print(f"  • Total Addresses  : {result.total_hosts:,}")
        print(f"  • Usable Host Count: {result.usable_hosts:,}")
        print(f"  • Usable Host Span : {result.first_usable_ip}  ->  {result.last_usable_ip}")
        print("------------------------------------------------------------\n")

    @staticmethod
    def print_interfaces(interfaces: List[NetworkInterface]) -> None:
        """Render table of network interfaces."""
        print("\n-------------------------------------------------------------------------------")
        print(f" {'Interface':<12} | {'State':<7} | {'Type':<10} | {'MTU':<6} | {'MAC Address':<18} | {'Addresses'}")
        print("-------------------------------------------------------------------------------")
        for iface in interfaces:
            addr_strs = [f"{a.address}/{a.prefix_length}" for a in iface.addresses]
            addrs_display = ", ".join(addr_strs) if addr_strs else "(none)"
            print(
                f" {iface.name:<12} | {iface.state.value:<7} | {iface.interface_type.value:<10} | "
                f"{iface.mtu:<6} | {iface.mac_address:<18} | {addrs_display}"
            )
        print("-------------------------------------------------------------------------------\n")

    @staticmethod
    def print_dns_result(result: DNSDiagnosticResult) -> None:
        """Render DNS diagnostic report card."""
        status_marker = "[OK]" if result.status == "SUCCESS" else f"[{result.status}]"
        print("\n------------------------------------------------------------")
        print(f" DNS Resolution: {result.target_host} {status_marker}")
        print("------------------------------------------------------------")
        print(f"  • Response Latency  : {result.response_time_ms} ms")
        print(f"  • Active Resolvers  : {', '.join(result.system_resolvers)}")

        if result.error_message:
            print(f"  • Error             : {result.error_message}")

        if result.records:
            print("  • Resolved Records  :")
            for rec in result.records:
                print(f"    - {rec.record_type:<6} : {rec.value}")
        print("------------------------------------------------------------\n")

    @staticmethod
    def print_latency_result(result: LatencyBenchmarkResult) -> None:
        """Render latency and connectivity benchmark card."""
        loss_marker = "[OK]" if result.packet_loss_percent == 0.0 else f"[{result.packet_loss_percent}% LOSS]"
        print("\n------------------------------------------------------------")
        print(f" Latency Benchmark: {result.target_host}:{result.target_port} {loss_marker}")
        print("------------------------------------------------------------")
        print(f"  • Probes Sent/Recv : {result.probes_sent} sent / {result.probes_received} received")
        print(f"  • Packet Loss      : {result.packet_loss_percent}%")
        print(f"  • Round-Trip Min   : {result.min_latency_ms} ms")
        print(f"  • Round-Trip Avg   : {result.avg_latency_ms} ms")
        print(f"  • Round-Trip Max   : {result.max_latency_ms} ms")
        print(f"  • Jitter           : {result.jitter_ms} ms")

        if result.probes:
            print("  • Probe Breakdown  :")
            for p in result.probes:
                status_str = f"{p.latency_ms} ms" if p.success else f"FAIL ({p.error})"
                print(f"    - Seq #{p.sequence:<2} : {status_str}")
        print("------------------------------------------------------------\n")

    @staticmethod
    def print_security_audit(report: SecurityAuditReport) -> None:
        """Render security audit findings and posture score."""
        score_badge = f"{report.overall_score}/100"
        print("\n------------------------------------------------------------")
        print(f" Cybersecurity Posture Audit — Score: {score_badge}")
        print("------------------------------------------------------------")
        ports_str = ", ".join(str(p) for p in report.open_local_ports) if report.open_local_ports else "(none)"
        print(f"  • Open Localhost Ports : {ports_str}")
        print("\n  Audit Findings & Recommendations:")
        for idx, finding in enumerate(report.findings, start=1):
            print(f"  {idx}. [{finding.severity.value}] {finding.title}")
            print(f"     Description   : {finding.description}")
            print(f"     Recommendation: {finding.recommendation}\n")
        print("------------------------------------------------------------\n")

    @staticmethod
    def print_packet_lab(packets: List[ParsedPacket]) -> None:
        """Render educational cybersecurity packet lab trace."""
        print("\n===============================================================================")
        print("        Educational Cybersecurity Laboratory — Packet Protocol Dissection     ")
        print("===============================================================================")
        for pkt in packets:
            print(f"\n[Packet #{pkt.index}] Protocol: {pkt.protocol:<10} Length: {pkt.length_bytes} bytes")
            print(f"  Flow: {pkt.src}  -->  {pkt.dst}")
            print(f"  Summary: {pkt.summary}")
            for layer in pkt.layers:
                print(f"    + Layer: {layer.layer_name}")
                for field in layer.fields:
                    print(f"        - {field.name:<20}: {field.value:<25} | {field.explanation}")
        print("\n===============================================================================\n")

    @staticmethod
    def print_routes(routes: List[RouteEntry]) -> None:
        """Render routing table entries."""
        print("\n-------------------------------------------------------------------------------")
        print(f" {'Destination':<18} | {'Gateway':<18} | {'Netmask':<16} | {'Iface':<8} | {'Flags':<6} | {'Metric'}")
        print("-------------------------------------------------------------------------------")
        for r in routes:
            print(f" {r.destination:<18} | {r.gateway:<18} | {r.netmask:<16} | {r.interface:<8} | {r.flags:<6} | {r.metric}")
        print("-------------------------------------------------------------------------------\n")

    @staticmethod
    def print_topology(topology: Any) -> None:
        """Render network topology graph overview in terminal."""
        print("\n===============================================================================")
        print("                   Network Topology Graph & Interconnections                   ")
        print("===============================================================================")
        print(f"\nDiscovered Nodes: {len(topology.nodes)} | Interconnect Links: {len(topology.links)}\n")
        print("-------------------------------------------------------------------------------")
        print(f" {'Node ID':<14} | {'Type':<12} | {'IP Address':<18} | {'Status':<8} | {'Label'}")
        print("-------------------------------------------------------------------------------")
        for n in topology.nodes:
            print(f" {n.id:<14} | {n.node_type.value:<12} | {n.ip_address:<18} | {n.status.value:<8} | {n.label}")
        print("-------------------------------------------------------------------------------")

        print("\nInterconnect Topology Links:")
        for l in topology.links:
            print(f"  • [{l.source_id}] <--- {l.speed_mbps} Mbps ({l.latency_ms} ms) ---> [{l.target_id}] ({l.status})")
        print("===============================================================================\n")

    @staticmethod
    def print_wifi_scan(access_points: List[AccessPointInfo]) -> None:
        """Render table of discovered Wi-Fi access points and security warnings."""
        print("\n=====================================================================================================")
        print("               Discovered Wi-Fi Access Points & Security Profiles (Read-Only)                        ")
        print("=====================================================================================================")
        print(f" Discovered APs: {len(access_points)}\n")
        print(f" {'SSID':<24} | {'BSSID':<18} | {'RSSI':<8} | {'Signal':<14} | {'CH':<4} | {'Width':<7} | {'Security'}")
        print("-----------------------------------------------------------------------------------------------------")
        for ap in access_points:
            # Render a 6-block signal bar
            bars = int(ap.signal_percent / 16.6)
            bar_str = "[" + "#" * bars + "-" * (6 - bars) + "]"
            signal_disp = f"{bar_str} {ap.signal_percent}%"
            print(
                f" {ap.ssid:<24} | {ap.bssid:<18} | {ap.rssi_dbm} dBm | {signal_disp:<14} | "
                f"{ap.channel:<4} | {ap.channel_width_mhz} MHz | {ap.security.value}"
            )
            if ap.security_warnings:
                for w in ap.security_warnings:
                    print(f"   [!] SECURITY WARNING: {w}")
        print("=====================================================================================================\n")

    @staticmethod
    def print_wifi_spectrum(reports: List[ChannelCongestionReport], band_name: str = "2.4 GHz") -> None:
        """Render RF channel spectrum congestion and optimization recommendations."""
        print("\n===============================================================================")
        print(f"         Wireless Spectrum Analysis & RF Channel Congestion ({band_name})       ")
        print("===============================================================================")
        print(f"\n {'Channel':<8} | {'Freq (MHz)':<11} | {'AP Count':<9} | {'Max RSSI':<9} | {'Congestion':<11} | {'Recommendation'}")
        print("-------------------------------------------------------------------------------")
        for r in reports:
            max_rssi_str = f"{r.strongest_rssi_dbm} dBm" if r.strongest_rssi_dbm > -100 else "Quiet"
            rec_str = "⭐ RECOMMENDED" if r.recommended else ("AVOID (Overcrowded)" if r.congestion_level in ("HIGH", "SEVERE") else "Acceptable")
            print(
                f" CH {r.channel:<5} | {r.frequency_mhz:<11} | {r.ap_count:<9} | "
                f"{max_rssi_str:<9} | {r.congestion_level:<11} | {rec_str}"
            )
        print("-------------------------------------------------------------------------------")

        recommended_channels = [str(r.channel) for r in reports if r.recommended]
        if recommended_channels:
            print(f"  Best Operating Channels for {band_name}: Channels {', '.join(recommended_channels)}")
        print("===============================================================================\n")

    @staticmethod
    def print_bandwidth_monitor(rates: List[BandwidthRate]) -> None:
        """Render live network interface throughput rates and packet counters."""
        print("\n=====================================================================================================")
        print("                 Live Network Interface Bandwidth & Traffic Flow Monitor                             ")
        print("=====================================================================================================")
        print(f"\n {'Interface':<12} | {'RX Throughput':<14} | {'TX Throughput':<14} | {'RX Pkts/s':<11} | {'TX Pkts/s':<11} | {'Total RX':<12} | {'Total TX'}")
        print("-----------------------------------------------------------------------------------------------------")
        for r in rates:
            tot_rx = format_total_bytes(r.total_rx_bytes)
            tot_tx = format_total_bytes(r.total_tx_bytes)
            print(
                f" {r.interface_name:<12} | {r.rx_rate_formatted:<14} | {r.tx_rate_formatted:<14} | "
                f"{r.rx_packets_sec:<11.1f} | {r.tx_packets_sec:<11.1f} | {tot_rx:<12} | {tot_tx}"
            )
        print("-----------------------------------------------------------------------------------------------------")
        errors = sum(r.rx_errors + r.tx_errors for r in rates)
        drops = sum(r.rx_dropped + r.tx_dropped for r in rates)
        print(f" Aggregate Status: {errors} Interface Errors | {drops} Dropped Packets")
        print("=====================================================================================================\n")

    @staticmethod
    def print_tls_inspection(report: TLSInspectionReport) -> None:
        """Render TLS/SSL cryptographic inspection report."""
        print("\n===============================================================================")
        print(f"        TLS / SSL Cryptographic & Certificate Inspection: {report.target_host}:{report.target_port}")
        print("===============================================================================")
        print(f"  • Posture Score       : {report.overall_score} / 100")
        print(f"  • Negotiated Protocol : {report.negotiated_protocol}")
        print(f"  • Cipher Suite        : {report.negotiated_cipher}")
        print(f"  • Cipher Strength     : {report.cipher_security.value}")

        if report.certificate_chain:
            cert = report.certificate_chain[0]
            status_desc = "EXPIRED" if cert.is_expired else ("SELF-SIGNED" if cert.is_self_signed else "VALID")
            print("\n  --- Public Key Certificate (X.509) ---")
            print(f"  • Subject Common Name : {cert.subject_cn}")
            print(f"  • Issuer Authority    : {cert.issuer_cn} ({cert.issuer_organization})")
            print(f"  • Validity Period     : {cert.valid_from}  -->  {cert.valid_to}")
            print(f"  • Expiration Status   : [{status_desc}] ({cert.days_until_expiration} days remaining)")
            print(f"  • Key Specification   : {cert.key_type} {cert.key_bits}-bit ({cert.signature_algorithm})")
            print(f"  • SHA-256 Fingerprint : {cert.fingerprint_sha256}")
            if cert.san_list:
                sans_disp = ", ".join(cert.san_list[:6])
                if len(cert.san_list) > 6:
                    sans_disp += f" (+{len(cert.san_list) - 6} more)"
                print(f"  • SAN DNS Names       : {sans_disp}")

        if report.vulnerabilities:
            print("\n  Security Vulnerabilities & Findings:")
            for v in report.vulnerabilities:
                print(f"    [!] {v}")

        if report.recommendations:
            print("\n  Hardening Recommendations:")
            for rec in report.recommendations:
                print(f"    [*] {rec}")
        print("===============================================================================\n")

    @staticmethod
    def print_spf_simulation(result: SPFSimulationResult) -> None:
        """Render OSPF Link-State and Dijkstra Shortest Path First simulation results."""
        print("\n=====================================================================================================")
        print(f"             OSPF Dijkstra Shortest Path First (SPF) Routing Engine [Root: {result.source_router}]            ")
        print("=====================================================================================================")
        print(f" Convergence Status : {result.convergence_status}")
        print(f" Calculation Time   : {result.convergence_time_ms} ms")
        if result.failed_link_id:
            print(f" Severed Link       : [!] {result.failed_link_id} (Simulated Link Down)")
        if result.unreachable_nodes:
            print(f" Unreachable Nodes  : [!] {', '.join(result.unreachable_nodes)} (Partitioned Network)")

        print("\n --- Computed OSPF Shortest-Path Routing Table ---")
        print(f" {'Dest':<6} | {'Subnet':<15} | {'Cost':<6} | {'Next-Hop':<9} | {'Next-Hop IP':<15} | {'Interface':<12} | {'Shortest Path'}")
        print("-----------------------------------------------------------------------------------------------------")
        for r in result.routes:
            path_str = " -> ".join(r.full_path)
            print(
                f" {r.destination_node:<6} | {r.destination_subnet:<15} | {r.total_cost:<6} | "
                f"{r.next_hop_router:<9} | {r.next_hop_ip:<15} | {r.outgoing_interface:<12} | {path_str}"
            )
        print("-----------------------------------------------------------------------------------------------------")

        print("\n --- Step-by-Step Dijkstra Execution Trace ---")
        for s in result.steps:
            conf_str = ", ".join(f"{k}:{v}" for k, v in s.confirmed_tree.items()) or "(none)"
            tent_str = ", ".join(f"{k}:{v}" for k, v in s.tentative_distances.items()) or "(none)"
            print(f" [Step {s.step_number:02d}] Node: {s.current_node:<3} | Confirmed: [{conf_str}] | Tentative: [{tent_str}]")
            print(f"           Explanation: {s.explanation}")
        print("=====================================================================================================\n")

    @staticmethod
    def print_vendor_discovery(report: VendorDiscoveryReport) -> None:
        """Render multi-vendor hardware inventory and IP surveillance camera diagnostics."""
        print("\n=====================================================================================================")
        print("          Multi-Vendor Network Hardware & IP Surveillance Device Inventory (Read-Only)               ")
        print("=====================================================================================================")
        print(f" Total Discovered Devices: {report.total_devices}")
        counts_str = " | ".join(f"{k}: {v}" for k, v in report.category_counts.items())
        print(f" Category Breakdown      : {counts_str}")
        if report.vulnerable_device_count > 0:
            print(f" Security Advisories     : [!] {report.vulnerable_device_count} device(s) have warnings or default credentials!")

        print("\n-----------------------------------------------------------------------------------------------------")
        print(f" {'ID':<7} | {'Device Name':<26} | {'Vendor':<12} | {'Category':<22} | {'IP Address':<15} | {'Status'}")
        print("-----------------------------------------------------------------------------------------------------")
        for d in report.devices:
            print(
                f" {d.device_id:<7} | {d.name:<26} | {d.vendor:<12} | {d.category.value:<22} | "
                f"{d.ip_address:<15} | {d.security_status.value}"
            )
        print("-----------------------------------------------------------------------------------------------------")

        # Render specialized detail highlights
        print("\n --- Device Telemetry & Profile Highlights ---")
        for d in report.devices:
            print(f"\n • [{d.device_id}] {d.name} ({d.vendor} {d.model}) - IP: {d.ip_address} | MAC: {d.mac_address}")
            print(f"   Firmware / OS: {d.firmware_version} (via {d.discovery_protocol})")

            if d.camera_info:
                cam = d.camera_info
                print(f"   [CCTV] RTSP URI   : {cam.rtsp_uri}")
                print(f"   [CCTV] Spec       : {cam.resolution} @ {cam.fps}fps ({cam.codec}) | ONVIF Port: {cam.onvif_port}")
                if cam.has_default_credentials:
                    print("   [!] ALERT: Factory default credentials active! Change immediately.")

            if d.wireless_info:
                w = d.wireless_info
                print(f"   [PtP] Wireless    : {w.wireless_mode} on {w.frequency_mhz} MHz ({w.channel_width_mhz} MHz)")
                print(f"   [PtP] Signal/CCQ  : RSSI {w.signal_rssi_dbm} dBm | Noise {w.noise_floor_dbm} dBm | SNR {w.snr_db} dB | CCQ {w.ccq_percent}%")
                print(f"   [PtP] Link Speed  : TX {w.tx_rate_mbps} Mbps / RX {w.rx_rate_mbps} Mbps | Distance: {w.distance_km} km")

            if d.router_info:
                r = d.router_info
                print(f"   [RouterOS] Board  : {r.board_name} ({r.architecture}) | Uptime: {r.uptime_str}")
                print(f"   [RouterOS] Health : CPU Load: {r.cpu_load_percent}% | Free RAM: {r.free_memory_mb} MB | Interfaces: {r.active_interfaces}")

            if d.security_notes:
                for note in d.security_notes:
                    print(f"   [*] Advisory      : {note}")

        print("=====================================================================================================\n")

