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
                risk, metrics = backend.get_risk_and_metrics()
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

        # Removed logo from sidebar as it is now in the dashboard header

        self.btn_dashboard = QPushButton("  Dashboard")
        self.btn_dashboard.setObjectName("SidebarBtn")
        self.btn_dashboard.setProperty("active", "true")
        self.btn_dashboard.clicked.connect(lambda: self.switch_page(0))
        sidebar_layout.addWidget(self.btn_dashboard)

        self.btn_logs = QPushButton("  System Logs")
        self.btn_logs.setObjectName("SidebarBtn")
        self.btn_logs.clicked.connect(lambda: self.switch_page(1))
        sidebar_layout.addWidget(self.btn_logs)

        # Divider 1
        line1 = QFrame()
        line1.setFrameShape(QFrame.HLine)
        line1.setFrameShadow(QFrame.Sunken)
        line1.setStyleSheet("background-color: #ffffff; margin-top: 16px; margin-bottom: 16px;")
        line1.setFixedHeight(1)
        sidebar_layout.addWidget(line1)

        # Simulation Controls
        # Move buttons downward with spacing
        sim_container = QWidget()
        sim_layout = QVBoxLayout(sim_container)
        sim_layout.setContentsMargins(0, 5, 0, 0) # Reduced top margin from 20px to 5px
        sim_layout.setSpacing(8)

        sim_label = QLabel("Threat Simulation")
        sim_label.setStyleSheet("font-size: 11px; color: #9DA7B3; font-weight: bold; margin-bottom: 8px; letter-spacing: 0.5px; text-transform: uppercase;")
        sim_layout.addWidget(sim_label)

        self.btn_idle = QPushButton("🔵  Normal Environment")
        self.btn_idle.clicked.connect(lambda: backend.set_scenario("IDLE"))
        self.btn_idle.setStyleSheet("background-color: #2563EB; border: none; text-align: left; padding-left: 15px;")
        sim_layout.addWidget(self.btn_idle)

        self.btn_attack = QPushButton("🔴  Simulate Ransomware")
        self.btn_attack.clicked.connect(lambda: backend.set_scenario("ATTACK"))
        self.btn_attack.setStyleSheet("background-color: #DC2626; border: none; font-weight: bold; text-align: left; padding-left: 15px;")
        sim_layout.addWidget(self.btn_attack)
        
        sidebar_layout.addWidget(sim_container)

        # Divider 2
        line2 = QFrame()
        line2.setFrameShape(QFrame.HLine)
        line2.setFrameShadow(QFrame.Sunken)
        line2.setStyleSheet("background-color: #ffffff; margin-top: 16px; margin-bottom: 16px;")
        line2.setFixedHeight(1)
        sidebar_layout.addWidget(line2)
        
        # Action Buttons
        self.btn_scan = QPushButton("START SCAN")
        self.btn_scan.setObjectName("ActionBtn")
        self.btn_scan.clicked.connect(self.toggle_scan)
        sidebar_layout.addWidget(self.btn_scan)

        self.btn_clear = QPushButton("Clear Logs")
        self.btn_clear.clicked.connect(self.clear_logs)
        self.btn_clear.setStyleSheet("background-color: #6B7280; color: white; border: none;")
        sidebar_layout.addWidget(self.btn_clear)

        sidebar_layout.addStretch()

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
            self.btn_scan.setStyleSheet("background-color: #DC2626; color: white;")
        else:
            backend.stop_scan()
            self.btn_scan.setText("START SCAN")
            self.btn_scan.setStyleSheet("") # Revert to stylesheet (Green)
            self.dashboard_page.reset_ui()
            self.alert_shown = False
            
            # Manually update logs to show "Scan Stopped"
            logs = backend.get_recent_logs()
            self.log_list.clear() # Clear main logs list
            self.log_list.addItems(logs[::-1]) # Add updated logs
            self.dashboard_page.incident_panel.update_logs(logs) # Update dashboard panel

    def clear_logs(self):
        backend.clear_logs()
        self.log_list.clear() # Clear main logs page
        self.dashboard_page.incident_panel.update_logs([]) # Clear dashboard incident panel

    def on_data_received(self, risk, metrics, logs):
        self.dashboard_page.update_ui(risk, metrics, logs)
        
        # Update logs list (main logs page)
        self.log_list.clear()
        self.log_list.addItems(logs[::-1])

        scenario = metrics.get("scenario", "IDLE")

        # Check for Critical Alert - ONLY trigger on actual attack scenario
        if scenario == "ATTACK" and risk > 0.8 and not self.alert_shown:
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
