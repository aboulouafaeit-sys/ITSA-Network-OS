"""Modern dark theme and styling for ITSA Network OS Desktop interface."""

DARK_THEME_QSS = """
/* Global Window & Base Styles */
QMainWindow, QDialog, QWidget#CentralWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', sans-serif;
    font-size: 13px;
}

/* Sidebar Navigation */
QListWidget#SidebarList {
    background-color: #161b22;
    border: none;
    border-right: 1px solid #30363d;
    outline: none;
    padding: 12px 6px;
    font-size: 14px;
    font-weight: 500;
}

QListWidget#SidebarList::item {
    color: #8b949e;
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 4px;
}

QListWidget#SidebarList::item:hover {
    background-color: #21262d;
    color: #f0f6fc;
}

QListWidget#SidebarList::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
    font-weight: 600;
}

/* Cards & Containers */
QFrame.CardFrame {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 16px;
}

QFrame.CardFrame:hover {
    border: 1px solid #58a6ff;
}

/* Headers & Labels */
QLabel#HeaderTitle {
    font-size: 20px;
    font-weight: 700;
    color: #f0f6fc;
}

QLabel#HeaderSubtitle {
    font-size: 13px;
    color: #8b949e;
}

QLabel#CardTitle {
    font-size: 15px;
    font-weight: 600;
    color: #58a6ff;
    margin-bottom: 8px;
}

QLabel#ValueBadge {
    font-size: 22px;
    font-weight: 700;
    color: #3fb950;
}

/* Input Fields */
QLineEdit {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #f0f6fc;
    padding: 10px 14px;
    font-size: 14px;
    selection-background-color: #1f6feb;
}

QLineEdit:focus {
    border: 1px solid #58a6ff;
    background-color: #161b22;
}

/* Action Buttons */
QPushButton.PrimaryButton {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton.PrimaryButton:hover {
    background-color: #2ea043;
}

QPushButton.PrimaryButton:pressed {
    background-color: #238636;
}

QPushButton.SecondaryButton {
    background-color: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 16px;
    font-size: 13px;
}

QPushButton.SecondaryButton:hover {
    background-color: #30363d;
    color: #f0f6fc;
}

/* Table Widget */
QTableWidget {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    gridline-color: #21262d;
    color: #c9d1d9;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #21262d;
    color: #8b949e;
    padding: 8px 12px;
    border: none;
    border-right: 1px solid #30363d;
    border-bottom: 1px solid #30363d;
    font-weight: 600;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background-color: #0d1117;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #30363d;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #8b949e;
}

/* Shell Header & Status Bar */
QFrame#ShellHeader {
    background-color: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 6px 16px;
}

QStatusBar {
    background-color: #161b22;
    color: #8b949e;
    border-top: 1px solid #30363d;
    font-size: 11px;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
    border-radius: 6px;
}

QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    border: 1px solid #30363d;
    border-bottom: none;
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 4px;
    font-size: 12px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #0d1117;
    color: #58a6ff;
    border-top: 2px solid #1f6feb;
}

QTabBar::tab:hover:!selected {
    background-color: #21262d;
    color: #f0f6fc;
}
"""
