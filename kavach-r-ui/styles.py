DARK_STYLE = """
QMainWindow {
    background-color: #121212;
}

QWidget {
    background-color: #121212;
    color: #E0E0E0;
    font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
}

/* Sidebar */
#Sidebar {
    background-color: #1E1E1E;
    border-right: 1px solid #333333;
    min-width: 200px;
}

QPushButton {
    background-color: #2D2D2D;
    border: none;
    color: #FFFFFF;
    padding: 12px;
    border-radius: 5px;
    font-size: 14px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #3D3D3D;
}

QPushButton#ActionBtn {
    background-color: #0078D4;
}

QPushButton#ActionBtn:hover {
    background-color: #0086F0;
}

QPushButton#SidebarBtn {
    background-color: transparent;
    text-align: left;
    padding-left: 20px;
}

QPushButton#SidebarBtn:hover {
    background-color: #2D2D2D;
}

QPushButton#SidebarBtn[active="true"] {
    background-color: #333333;
    border-left: 4px solid #0078D4;
}

/* Header Labels */
QLabel#RiskLabel {
    font-size: 64px;
    font-weight: bold;
    color: #FFFFFF;
}

QLabel#StatusLabel {
    font-size: 24px;
    font-weight: bold;
    padding: 10px 20px;
    border-radius: 5px;
}

/* Containers */
QFrame#Card {
    background-color: #1E1E1E;
    border: 1px solid #333333;
    border-radius: 10px;
}

QListWidget {
    background-color: #1E1E1E;
    border: 1px solid #333333;
    border-radius: 5px;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
"""
