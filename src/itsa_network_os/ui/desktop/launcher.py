"""Desktop GUI application launcher with graceful fallback for headless environments."""

from __future__ import annotations

import sys
from typing import Optional

from itsa_network_os.app import Application

try:
    from PySide6.QtWidgets import QApplication
    from itsa_network_os.ui.desktop.app_window import MainWindow
    from itsa_network_os.ui.desktop.theme import DARK_THEME_QSS
    PYSIDE6_AVAILABLE = True
except ImportError:
    PYSIDE6_AVAILABLE = False


def launch_gui(app: Application) -> int:
    """Initialize and launch desktop graphical user interface."""
    if not PYSIDE6_AVAILABLE:
        print(
            "Error: PySide6 is not installed in the active environment.\n"
            "To enable the desktop graphical interface, please install PySide6:\n"
            "    pip install PySide6\n"
            "Or run the application in CLI mode:\n"
            "    itsa-network-os --help",
            file=sys.stderr,
        )
        return 1

    try:
        qt_app = QApplication.instance()
        if qt_app is None:
            qt_app = QApplication(sys.argv)

        qt_app.setStyleSheet(DARK_THEME_QSS)

        window = MainWindow(app)
        window.show()

        return qt_app.exec()
    except Exception as exc:
        print(f"Error initializing graphical session: {exc}", file=sys.stderr)
        return 1
