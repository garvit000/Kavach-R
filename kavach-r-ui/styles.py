DARK_STYLE = """
QMainWindow {
    background-color: #0F1117;
}

QWidget {
    background-color: #0F1117;
    color: #E6EDF3;
    font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
}

/* Sidebar */
#Sidebar {
    background-color: #11141A;
    border-right: 1px solid #2A2F3A;
    min-width: 220px;
}

/* Generic Buttons */
QPushButton {
    background-color: #1F2937;
    border: 1px solid #2A2F3A;
    color: #E6EDF3;
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: #2A3441;
    border-color: #3B4252;
}

QPushButton:pressed {
    background-color: #111827;
}

/* Action Button (Start Scan) */
QPushButton#ActionBtn {
    background-color: #16A34A;
    color: #FFFFFF;
    border: none;
    font-size: 14px;
    padding: 14px;
}

QPushButton#ActionBtn:hover {
    background-color: #22C55E;
}

/* Sidebar Navigation Buttons */
QPushButton#SidebarBtn {
    background-color: transparent;
    border: none;
    text-align: left;
    padding: 12px 20px;
    color: #9DA7B3;
    border-radius: 6px;
    margin: 2px 10px;
}

QPushButton#SidebarBtn:hover {
    background-color: #1A2230;
    color: #E6EDF3;
}

QPushButton#SidebarBtn[active="true"] {
    background-color: #1F2937;
    color: #E6EDF3;
    border-left: 3px solid #3B82F6;
    border-top-left-radius: 0;
    border-bottom-left-radius: 0;
}

/* Cards & Containers */
QFrame#Card {
    background-color: #1A1D24;
    border: 1px solid #2A2F3A;
    border-radius: 12px;
}

/* Labels */
QLabel#RiskLabel {
    font-size: 56px;
    font-weight: 700;
    color: #E6EDF3;
}

QLabel#StatusLabel {
    font-size: 16px;
    font-weight: 700;
    padding: 8px 16px;
    border-radius: 6px;
}

/* List Widget (Logs) */
QListWidget {
    background-color: #1A1D24;
    border: 1px solid #2A2F3A;
    border-radius: 8px;
    color: #9DA7B3;
    padding: 10px;
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 12px;
}

QListWidget::item {
    padding: 5px;
    border-bottom: 1px solid #2A2F3A;
}

QListWidget::item:selected {
    background-color: #1F2937;
    color: #E6EDF3;
}
"""
