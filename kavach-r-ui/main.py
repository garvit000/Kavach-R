import argparse
import os
import sys

# Ensure kavach-r-ui/ directory is first on sys.path so local imports
# (dashboard, styles, backend_*) resolve here rather than the project root.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QStackedWidget, QListWidget, QFrame, QMessageBox
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal

from backend_mock import BackendMock
from backend_real import RealBackend, is_model_available
from dashboard import DashboardWidget
from styles import DARK_STYLE


def _select_backend(use_mock: bool) -> object:
    """Choose the backend based on CLI flag and model availability."""
    if use_mock:
        print("[Kavach-R] Running in MOCK mode (simulated data)")
        return BackendMock()

    if is_model_available():
        print("[Kavach-R] Running in REAL mode (live ML detection)")
        return RealBackend()
    else:
        print("[Kavach-R] WARNING: model.joblib not found — falling back to MOCK mode")
        return BackendMock()


class UpdateThread(QThread):
    data_received = Signal(float, dict, list)

    def __init__(self, backend):
        super().__init__()
        self._running = True
        self._backend = backend

    def run(self):
        while self._running:
            if self._backend.scanning:
                risk, metrics = self._backend.get_risk_and_metrics()
                logs = self._backend.get_recent_logs()
                self.data_received.emit(risk, metrics, logs)
            self.msleep(1000)

    def stop(self):
        self._running = False


class MainWindow(QMainWindow):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.is_mock = isinstance(backend, BackendMock)

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

        # Simulation Controls (only for MOCK mode)
        sim_container = QWidget()
        sim_layout = QVBoxLayout(sim_container)
        sim_layout.setContentsMargins(0, 5, 0, 0)
        sim_layout.setSpacing(8)

        if self.is_mock:
            sim_label = QLabel("Threat Simulation")
            sim_label.setStyleSheet("font-size: 11px; color: #9DA7B3; font-weight: bold; margin-bottom: 8px; letter-spacing: 0.5px; text-transform: uppercase;")
            sim_layout.addWidget(sim_label)

            self.btn_idle = QPushButton("🔵  Normal Environment")
            self.btn_idle.clicked.connect(lambda: self.backend.set_scenario("IDLE"))
            self.btn_idle.setStyleSheet("background-color: #2563EB; border: none; text-align: left; padding-left: 15px;")
            sim_layout.addWidget(self.btn_idle)

            self.btn_attack = QPushButton("🔴  Simulate Ransomware")
            self.btn_attack.clicked.connect(lambda: self.backend.set_scenario("ATTACK"))
            self.btn_attack.setStyleSheet("background-color: #DC2626; border: none; font-weight: bold; text-align: left; padding-left: 15px;")
            sim_layout.addWidget(self.btn_attack)
        else:
            mode_label = QLabel("Live Detection")
            mode_label.setStyleSheet("font-size: 11px; color: #9DA7B3; font-weight: bold; margin-bottom: 8px; letter-spacing: 0.5px; text-transform: uppercase;")
            sim_layout.addWidget(mode_label)

            mode_info = QLabel("🟢  Real-time ML Monitoring")
            mode_info.setStyleSheet("color: #22C55E; font-size: 12px; padding: 8px 12px;")
            sim_layout.addWidget(mode_info)

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
        self.update_thread = UpdateThread(self.backend)
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
        if not self.backend.scanning:
            self.backend.start_scan()
            self.btn_scan.setText("STOP SCAN")
            self.btn_scan.setStyleSheet("background-color: #DC2626; color: white;")
        else:
            self.backend.stop_scan()
            self.btn_scan.setText("START SCAN")
            self.btn_scan.setStyleSheet("") # Revert to stylesheet (Green)
            self.dashboard_page.reset_ui()
            self.alert_shown = False
            
            # Manually update logs to show "Scan Stopped"
            logs = self.backend.get_recent_logs()
            self.log_list.clear()
            self.log_list.addItems(logs[::-1])
            self.dashboard_page.incident_panel.update_logs(logs)

    def clear_logs(self):
        self.backend.clear_logs()
        self.log_list.clear()
        self.dashboard_page.incident_panel.update_logs([])

    def on_data_received(self, risk, metrics, logs):
        self.dashboard_page.update_ui(risk, metrics, logs)
        
        # Update logs list (main logs page)
        self.log_list.clear()
        self.log_list.addItems(logs[::-1])

        scenario = metrics.get("scenario", "IDLE")

        # Check for Critical Alert
        if scenario == "ATTACK" and risk > 0.8 and not self.alert_shown:
            self.alert_shown = True
            QMessageBox.critical(
                self, 
                "THREAT DETECTED", 
                "Potential Ransomware Behavior Detected.\nHigh-risk process activity identified.\n\nActions taken: Process activity flagged."
            )

    def closeEvent(self, event):
        # Stop the backend if scanning
        if self.backend.scanning:
            self.backend.stop_scan()
        self.update_thread.stop()
        self.update_thread.wait()
        event.accept()


def main():
    parser = argparse.ArgumentParser(description="Kavach-R Dashboard")
    parser.add_argument("--mock", action="store_true", help="Use mock backend (simulated data)")
    args = parser.parse_args()

    backend = _select_backend(use_mock=args.mock)

    app = QApplication(sys.argv)
    window = MainWindow(backend)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
