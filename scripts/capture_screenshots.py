"""Capture pixel-perfect screenshots of all 8 ITSA Network OS Desktop interface tabs."""

import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from itsa_network_os.app import Application
from itsa_network_os.core.config import AppConfig
from itsa_network_os.ui.desktop.app_window import MainWindow
from itsa_network_os.ui.desktop.theme import DARK_THEME_QSS

DOCS_IMG_DIR = Path(__file__).resolve().parent.parent / "docs" / "images"
ARTIFACT_DIR = Path(os.environ.get("ARTIFACT_DIR", "/tmp"))

DOCS_IMG_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


def capture_all() -> None:
    qt_app = QApplication.instance() or QApplication([])
    qt_app.setStyleSheet(DARK_THEME_QSS)

    app = Application(config=AppConfig(database_file=":memory:"))
    win = MainWindow(app)
    win.resize(1180, 780)
    win.show()
    qt_app.processEvents()

    tabs = [
        (0, "overview_dashboard.png"),
        (1, "subnet_calculator.png"),
        (2, "interfaces_inspector.png"),
        (3, "dns_diagnostics.png"),
        (4, "latency_benchmark.png"),
        (5, "security_audit.png"),
        (6, "packet_protocol_lab.png"),
        (7, "routing_table.png"),
        (8, "network_topology.png"),
        (9, "wifi_spectrum_analyzer.png"),
        (10, "bandwidth_monitor.png"),
        (11, "tls_inspector.png"),
        (12, "spf_simulator.png"),
        (13, "vendor_manager.png"),
    ]

    for index, filename in tabs:
        win.sidebar.setCurrentRow(index)
        win.pages_stack.setCurrentIndex(index)
        qt_app.processEvents()

        # Specific triggers to populate realistic diagnostic data
        if index == 1:
            win.subnet_input.setText("10.50.0.0/22")
            win._on_calculate_subnet()
        elif index == 3:
            win.dns_input.setText("cloudflare.com")
            win._on_resolve_dns()
        elif index == 4:
            win.lat_host_input.setText("1.1.1.1")
            win._on_run_latency()
        elif index == 5:
            win._run_audit_scan()
        elif index == 6:
            win._on_packet_selected(1)  # Select TCP SYN handshake packet
        elif index == 7:
            win._load_routes()
        elif index == 10:
            win.bandwidth_widget._on_timer_tick()
        elif index == 11:
            win.tls_widget.inspect_target("cloudflare.com", 443)
        elif index == 12:
            win.spf_widget.run_simulation("R1", None)
        elif index == 13:
            win.vendor_widget.refresh_devices()

        qt_app.processEvents()

        # Grab and save
        pixmap = win.grab()
        local_path = DOCS_IMG_DIR / filename
        artifact_path = ARTIFACT_DIR / filename

        pixmap.save(str(local_path), "PNG")
        pixmap.save(str(artifact_path), "PNG")

        print(f"Captured {filename}: {local_path.stat().st_size} bytes")

    win.bandwidth_widget.timer.stop()
    win.close()


if __name__ == "__main__":
    capture_all()
