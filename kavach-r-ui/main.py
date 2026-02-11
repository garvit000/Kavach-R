import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QStackedWidget, QListWidget, QFrame, QMessageBox
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal

from backend_mock import backend
from dashboard import DashboardWidget
from styles import DARK_STYLE

class UpdateThread(QThread):
    data_received = Signal(float, dict, list)

    def __init__(self):
        super().__init__()
        self._running = True

    def run(self):
        while self._running:
            if backend.scanning:
                risk = backend.get_current_risk_score()
                metrics = backend.get_activity_metrics()
                logs = backend.get_recent_logs()
                self.data_received.emit(risk, metrics, logs)
            self.msleep(1000)

    def stop(self):
        self._running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kavach-R | Ransomware Early Warning")
        self.resize(1100, 750)
        self.setStyleSheet(DARK_STYLE)

        # Central Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 20)
        sidebar_layout.setSpacing(10)

        app_logo = QLabel("KAVACH-R")
        app_logo.setStyleSheet("font-size: 24px; font-weight: bold; color: #0078D4; margin-bottom: 20px;")
        app_logo.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(app_logo)

        self.btn_dashboard = QPushButton("  Dashboard")
        self.btn_dashboard.setObjectName("SidebarBtn")
        self.btn_dashboard.setProperty("active", "true")
        self.btn_dashboard.clicked.connect(lambda: self.switch_page(0))
        sidebar_layout.addWidget(self.btn_dashboard)

        self.btn_logs = QPushButton("  System Logs")
        self.btn_logs.setObjectName("SidebarBtn")
        self.btn_logs.clicked.connect(lambda: self.switch_page(1))
        sidebar_layout.addWidget(self.btn_logs)

        sidebar_layout.addStretch()

        # Simulation Controls
        sim_label = QLabel("SIMULATION CONTROLS")
        sim_label.setStyleSheet("font-size: 10px; color: #555555; font-weight: bold; margin-top: 20px;")
        sidebar_layout.addWidget(sim_label)

        self.btn_idle = QPushButton("Normal Activity")
        self.btn_idle.clicked.connect(lambda: backend.set_scenario("IDLE"))
        sidebar_layout.addWidget(self.btn_idle)

        self.btn_unzip = QPushButton("Large Unzip")
        self.btn_unzip.clicked.connect(lambda: backend.set_scenario("UNZIP"))
        sidebar_layout.addWidget(self.btn_unzip)

        self.btn_update = QPushButton("Software Update")
        self.btn_update.clicked.connect(lambda: backend.set_scenario("SOFTWARE_UPDATE"))
        sidebar_layout.addWidget(self.btn_update)

        self.btn_attack = QPushButton("Ransomware Attack")
        self.btn_attack.clicked.connect(lambda: backend.set_scenario("ATTACK"))
        self.btn_attack.setStyleSheet("color: #FF5252;")
        sidebar_layout.addWidget(self.btn_attack)

        sidebar_layout.addStretch()
        
        # Action Buttons
        self.btn_scan = QPushButton("START SCAN")
        self.btn_scan.setObjectName("ActionBtn")
        self.btn_scan.clicked.connect(self.toggle_scan)
        sidebar_layout.addWidget(self.btn_scan)

        self.btn_clear = QPushButton("Clear Logs")
        self.btn_clear.clicked.connect(self.clear_logs)
        sidebar_layout.addWidget(self.btn_clear)

        self.main_layout.addWidget(self.sidebar)

        # Right Side Content
        self.content_stack = QStackedWidget()
        
        # Dashboard Page
        self.dashboard_page = DashboardWidget()
        self.content_stack.addWidget(self.dashboard_page)

        # Logs Page
        self.logs_page = QWidget()
        logs_layout = QVBoxLayout(self.logs_page)
        logs_layout.setContentsMargins(20, 20, 20, 20)
        logs_layout.addWidget(QLabel("Real-time Activity Events"))
        self.log_list = QListWidget()
        logs_layout.addWidget(self.log_list)
        self.content_stack.addWidget(self.logs_page)

        self.main_layout.addWidget(self.content_stack)

        # Update Thread
        self.update_thread = UpdateThread()
        self.update_thread.data_received.connect(self.on_data_received)
        self.update_thread.start()

        self.alert_shown = False

    def switch_page(self, index):
        self.content_stack.setCurrentIndex(index)
        self.btn_dashboard.setProperty("active", "true" if index == 0 else "false")
        self.btn_logs.setProperty("active", "true" if index == 1 else "false")
        self.btn_dashboard.setStyle(self.btn_dashboard.style())
        self.btn_logs.setStyle(self.btn_logs.style())

    def toggle_scan(self):
        if not backend.scanning:
            backend.start_scan()
            self.btn_scan.setText("STOP SCAN")
            self.btn_scan.setStyleSheet("background-color: #C62828;")
        else:
            backend.stop_scan()
            self.btn_scan.setText("START SCAN")
            self.btn_scan.setStyleSheet("")
            self.dashboard_page.reset_ui()
            self.alert_shown = False

    def clear_logs(self):
        backend.clear_logs()
        self.log_list.clear()

    def on_data_received(self, risk, metrics, logs):
        self.dashboard_page.update_ui(risk, metrics)
        
        # Update logs list
        self.log_list.clear()
        self.log_list.addItems(logs[::-1])

        # Check for Critical Alert
        if risk > 0.8 and not self.alert_shown:
            self.alert_shown = True
            QMessageBox.critical(
                self, 
                "THREAT DETECTED", 
                "Potential Ransomware Behavior Detected.\nHigh-risk process activity identified.\n\nActions taken: Process activity suspended."
            )

    def closeEvent(self, event):
        self.update_thread.stop()
        self.update_thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
