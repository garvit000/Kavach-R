import argparse
import logging
import os
import sys
import time
from pathlib import Path

# Ensure kavach-r-ui/ directory is first on sys.path so local imports
# (dashboard, styles, backend_*) resolve here rather than the project root.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

_PROJECT_ROOT = os.path.dirname(_THIS_DIR)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QStackedWidget, QListWidget, QFrame, QMessageBox,
    QSpinBox, QProgressBar, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QColor

from backend_mock import BackendMock
from backend_real import RealBackend, is_model_available
from dashboard import DashboardWidget
from styles import DARK_STYLE

logger = logging.getLogger("kavach.ui")


def _select_backend(use_mock: bool) -> object:
    """Choose the backend based on CLI flag and model availability."""
    if use_mock:
        print("[Kavach-R] Running in MOCK mode (simulated data)")
        return BackendMock()

    if is_model_available():
        print("[Kavach-R] Running in REAL mode (live ML detection)")
    else:
        print("[Kavach-R] Running in REAL mode (model not trained yet — use Train Model)")
    return RealBackend()


class TrainingWorker(QThread):
    """Background thread that trains the anomaly detection model."""
    progress = Signal(str)        # log messages
    finished = Signal(bool, str)  # (success, message)

    def __init__(self, duration: float, model_path: str):
        super().__init__()
        self.duration = duration
        self.model_path = model_path

    def run(self):
        try:
            # Ensure project root is on path for kavach imports
            if _PROJECT_ROOT not in sys.path:
                sys.path.append(_PROJECT_ROOT)

            from kavach.feature_engine import FeatureEngine
            from kavach.model import KavachModel
            from kavach.events import FileEvent

            engine = FeatureEngine(window_size=10.0)
            samples = []

            self.progress.emit("Starting model training...")
            self.progress.emit(f"Collecting {self.duration:.0f}s of baseline activity...")

            # Try to use the real monitor
            try:
                from kavach.monitor import start as monitor_start, stop as monitor_stop

                collecting = True

                def _on_event(event: FileEvent):
                    if not collecting:
                        return
                    engine.add_event(event)
                    features = engine.extract_features()
                    samples.append(features)

                monitor_start(callback=_on_event)
                self.progress.emit("Monitor started. Collecting normal activity...")

                # Collect for the specified duration, emitting progress updates
                start_time = time.time()
                while time.time() - start_time < self.duration:
                    elapsed = time.time() - start_time
                    pct = int((elapsed / self.duration) * 100)
                    self.progress.emit(f"Collecting... {pct}% ({len(samples)} samples)")
                    time.sleep(2)

                collecting = False
                monitor_stop()
                self.progress.emit(f"Collection done. {len(samples)} samples captured.")

            except ImportError:
                self.progress.emit("Monitor not available — using synthetic data.")
                samples = self._generate_synthetic(200)

            if not samples:
                self.progress.emit("No live samples — using synthetic data.")
                samples = self._generate_synthetic(200)

            # Train the model
            self.progress.emit("Training IsolationForest model...")
            model = KavachModel(contamination=0.05)
            model.train(samples)
            model.save_model(self.model_path)
            self.progress.emit(f"Model saved to {self.model_path}")
            self.finished.emit(True, f"Training complete! {len(samples)} samples. Model saved.")

        except Exception as e:
            self.progress.emit(f"ERROR: {e}")
            self.finished.emit(False, str(e))

    @staticmethod
    def _generate_synthetic(count=200):
        import random
        rng = random.Random(42)
        samples = []
        for _ in range(count):
            if rng.random() < 0.3:
                samples.append({
                    "files_modified_per_sec": rng.uniform(0.0, 0.1),
                    "rename_rate": 0.0,
                    "unique_files_touched": rng.uniform(0, 2),
                    "extension_change_rate": 0.0,
                    "entropy_change": rng.uniform(0.0, 5.0),
                })
            else:
                samples.append({
                    "files_modified_per_sec": rng.uniform(0.0, 5.0),
                    "rename_rate": rng.uniform(0.0, 0.5),
                    "unique_files_touched": rng.uniform(1, 15),
                    "extension_change_rate": rng.uniform(0.0, 0.05),
                    "entropy_change": rng.uniform(0.0, 6.0),
                })
        return samples


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

        self.nav_buttons = []

        self.btn_dashboard = QPushButton("  Dashboard")
        self.btn_dashboard.setObjectName("SidebarBtn")
        self.btn_dashboard.setProperty("active", "true")
        self.btn_dashboard.clicked.connect(lambda: self.switch_page(0))
        sidebar_layout.addWidget(self.btn_dashboard)
        self.nav_buttons.append(self.btn_dashboard)

        self.btn_logs = QPushButton("  System Logs")
        self.btn_logs.setObjectName("SidebarBtn")
        self.btn_logs.clicked.connect(lambda: self.switch_page(1))
        sidebar_layout.addWidget(self.btn_logs)
        self.nav_buttons.append(self.btn_logs)

        if not self.is_mock:
            self.btn_train = QPushButton("  Train Model")
            self.btn_train.setObjectName("SidebarBtn")
            self.btn_train.clicked.connect(lambda: self.switch_page(2))
            sidebar_layout.addWidget(self.btn_train)
            self.nav_buttons.append(self.btn_train)

            self.btn_processes = QPushButton("  Processes")
            self.btn_processes.setObjectName("SidebarBtn")
            self.btn_processes.clicked.connect(lambda: self.switch_page(3))
            sidebar_layout.addWidget(self.btn_processes)
            self.nav_buttons.append(self.btn_processes)

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

        # Page 0: Dashboard
        self.dashboard_page = DashboardWidget()
        self.content_stack.addWidget(self.dashboard_page)

        # Page 1: Logs
        self.logs_page = QWidget()
        logs_layout = QVBoxLayout(self.logs_page)
        logs_layout.setContentsMargins(20, 20, 20, 20)
        logs_layout.addWidget(QLabel("Real-time Activity Events"))
        self.log_list = QListWidget()
        logs_layout.addWidget(self.log_list)
        self.content_stack.addWidget(self.logs_page)

        # Page 2: Training (real mode only)
        if not self.is_mock:
            self._build_training_page()

        # Page 3: Flagged Processes (real mode only)
        if not self.is_mock:
            self._build_processes_page()

        self.main_layout.addWidget(self.content_stack)

        # Update Thread
        self.update_thread = UpdateThread(self.backend)
        self.update_thread.data_received.connect(self.on_data_received)
        self.update_thread.start()

        self.alert_shown = False

    def _build_training_page(self):
        """Build the Model Training page (page index 2)."""
        self.training_page = QWidget()
        t_layout = QVBoxLayout(self.training_page)
        t_layout.setContentsMargins(24, 24, 24, 24)
        t_layout.setSpacing(16)

        # Header
        header = QLabel("🧠 MODEL TRAINING")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #E6EDF3;")
        t_layout.addWidget(header)

        desc = QLabel(
            "Train the anomaly detection model on your system's normal behavior.\n"
            "During training, use your computer normally so the model learns\n"
            "your typical file activity patterns."
        )
        desc.setStyleSheet("color: #9DA7B3; font-size: 13px; line-height: 1.5;")
        desc.setWordWrap(True)
        t_layout.addWidget(desc)

        # Duration control
        dur_container = QHBoxLayout()
        dur_label = QLabel("Training Duration (seconds):")
        dur_label.setStyleSheet("color: #E6EDF3; font-size: 13px;")
        dur_container.addWidget(dur_label)

        self.train_duration_spin = QSpinBox()
        self.train_duration_spin.setRange(10, 300)
        self.train_duration_spin.setValue(60)
        self.train_duration_spin.setSuffix(" s")
        self.train_duration_spin.setStyleSheet("""
            QSpinBox {
                background-color: #1A1D24; border: 1px solid #2A2F3A;
                border-radius: 6px; padding: 8px 12px; color: #E6EDF3;
                font-size: 14px; min-width: 100px;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #2A2F3A; border: none; width: 20px;
            }
        """)
        dur_container.addWidget(self.train_duration_spin)
        dur_container.addStretch()
        t_layout.addLayout(dur_container)

        # Train button
        self.btn_start_training = QPushButton("🚀  START TRAINING")
        self.btn_start_training.setStyleSheet("""
            QPushButton {
                background-color: #7C3AED; color: white; border: none;
                font-size: 14px; font-weight: bold; padding: 14px;
                border-radius: 8px;
            }
            QPushButton:hover { background-color: #6D28D9; }
            QPushButton:disabled { background-color: #4B5563; color: #9DA7B3; }
        """)
        self.btn_start_training.clicked.connect(self.start_training)
        t_layout.addWidget(self.btn_start_training)

        # Progress bar
        self.train_progress = QProgressBar()
        self.train_progress.setRange(0, 0)  # indeterminate
        self.train_progress.setVisible(False)
        self.train_progress.setStyleSheet("""
            QProgressBar {
                background-color: #1A1D24; border: 1px solid #2A2F3A;
                border-radius: 6px; height: 8px; text-align: center;
            }
            QProgressBar::chunk {
                background-color: #7C3AED; border-radius: 4px;
            }
        """)
        t_layout.addWidget(self.train_progress)

        # Training log output
        self.train_log = QTextEdit()
        self.train_log.setReadOnly(True)
        self.train_log.setStyleSheet("""
            QTextEdit {
                background-color: #11141A; border: 1px solid #2A2F3A;
                border-radius: 8px; color: #9DA7B3; padding: 12px;
                font-family: Consolas, monospace; font-size: 12px;
            }
        """)
        self.train_log.setPlaceholderText("Training output will appear here...")
        t_layout.addWidget(self.train_log)

        # Model status
        model_path = os.path.join(_PROJECT_ROOT, "model.joblib")
        if os.path.exists(model_path):
            mod_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(model_path)))
            status_text = f"✅ Current model: model.joblib (last trained: {mod_time})"
            status_color = "#22C55E"
        else:
            status_text = "⚠️ No trained model found. Train one before starting detection."
            status_color = "#F59E0B"

        self.model_status_label = QLabel(status_text)
        self.model_status_label.setStyleSheet(f"color: {status_color}; font-size: 12px; padding: 8px;")
        t_layout.addWidget(self.model_status_label)

        t_layout.addStretch()
        self.content_stack.addWidget(self.training_page)
        self._training_worker = None

    def start_training(self):
        """Launch the training worker thread."""
        duration = self.train_duration_spin.value()
        model_path = os.path.join(_PROJECT_ROOT, "model.joblib")

        # Disable controls during training
        self.btn_start_training.setEnabled(False)
        self.btn_start_training.setText("⏳  TRAINING...")
        self.train_duration_spin.setEnabled(False)
        self.train_progress.setVisible(True)
        self.train_log.clear()
        self.train_log.append(f"[Training] Duration: {duration}s")
        self.train_log.append(f"[Training] Output: {model_path}")
        self.train_log.append("")

        self._training_worker = TrainingWorker(duration, model_path)
        self._training_worker.progress.connect(self._on_training_progress)
        self._training_worker.finished.connect(self._on_training_finished)
        self._training_worker.start()

    def _on_training_progress(self, msg):
        self.train_log.append(f"  {msg}")

    def _on_training_finished(self, success, msg):
        self.btn_start_training.setEnabled(True)
        self.btn_start_training.setText("🚀  START TRAINING")
        self.train_duration_spin.setEnabled(True)
        self.train_progress.setVisible(False)

        if success:
            self.train_log.append(f"\n✅ {msg}")
            model_path = os.path.join(_PROJECT_ROOT, "model.joblib")
            mod_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(model_path)))
            self.model_status_label.setText(f"✅ Current model: model.joblib (last trained: {mod_time})")
            self.model_status_label.setStyleSheet("color: #22C55E; font-size: 12px; padding: 8px;")

            # Reload backend with new model
            if isinstance(self.backend, RealBackend):
                self.backend.model_path = Path(model_path)
                self.train_log.append("Model will be used on next scan start.")
        else:
            self.train_log.append(f"\n❌ Training failed: {msg}")

    def _build_processes_page(self):
        """Build the Flagged Processes page (page index 3)."""
        self.processes_page = QWidget()
        p_layout = QVBoxLayout(self.processes_page)
        p_layout.setContentsMargins(24, 24, 24, 24)
        p_layout.setSpacing(16)

        # Header
        header = QLabel("🔍 FLAGGED PROCESSES")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #E6EDF3;")
        p_layout.addWidget(header)

        desc = QLabel(
            "Processes flagged by the anomaly detection engine during scanning.\n"
            "Each row shows a process whose file activity triggered the ML model."
        )
        desc.setStyleSheet("color: #9DA7B3; font-size: 13px;")
        desc.setWordWrap(True)
        p_layout.addWidget(desc)

        # Process count label
        self.process_count_label = QLabel("No flagged processes yet.")
        self.process_count_label.setStyleSheet("color: #9DA7B3; font-size: 12px; padding: 4px 0;")
        p_layout.addWidget(self.process_count_label)

        # Table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(7)
        self.process_table.setHorizontalHeaderLabels([
            "Time", "PID", "Process Name", "Path", "Score", "Risk", "Status"
        ])
        self.process_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.process_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.process_table.setAlternatingRowColors(True)
        self.process_table.verticalHeader().setVisible(False)

        # Column widths
        header_view = self.process_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Time
        header_view.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # PID
        header_view.setSectionResizeMode(2, QHeaderView.Interactive)       # Name
        header_view.setSectionResizeMode(3, QHeaderView.Stretch)           # Path
        header_view.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Score
        header_view.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Risk
        header_view.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Status

        self.process_table.setStyleSheet("""
            QTableWidget {
                background-color: #11141A; border: 1px solid #2A2F3A;
                border-radius: 8px; color: #E6EDF3; gridline-color: #2A2F3A;
                font-size: 12px;
            }
            QTableWidget::item { padding: 6px 10px; }
            QTableWidget::item:selected { background-color: #1E3A5F; }
            QHeaderView::section {
                background-color: #1A1D24; color: #9DA7B3;
                font-weight: bold; font-size: 11px; padding: 8px;
                border: none; border-bottom: 1px solid #2A2F3A;
            }
            QTableWidget::item:alternate { background-color: #151820; }
        """)

        p_layout.addWidget(self.process_table)

        # Clear button
        btn_clear_proc = QPushButton("Clear Flagged Processes")
        btn_clear_proc.setStyleSheet("""
            QPushButton {
                background-color: #6B7280; color: white; border: none;
                padding: 10px; border-radius: 6px; font-size: 13px;
                max-width: 200px;
            }
            QPushButton:hover { background-color: #4B5563; }
        """)
        btn_clear_proc.clicked.connect(self._clear_flagged_processes)
        p_layout.addWidget(btn_clear_proc)

        self.content_stack.addWidget(self.processes_page)

    def _refresh_processes_table(self):
        """Update the processes table from backend data."""
        if not hasattr(self, "process_table"):
            return
        if not hasattr(self.backend, "get_flagged_processes"):
            return

        records = self.backend.get_flagged_processes()
        self.process_table.setRowCount(len(records))
        self.process_count_label.setText(
            f"{len(records)} flagged process{'es' if len(records) != 1 else ''}"
            if records else "No flagged processes yet."
        )

        for row, rec in enumerate(reversed(records)):  # newest first
            risk = rec.get("risk", 0)

            # Pick row color based on risk
            if risk >= 0.7:
                row_color = QColor(127, 29, 29, 80)   # dark red
            elif risk >= 0.4:
                row_color = QColor(120, 53, 15, 80)    # dark amber
            else:
                row_color = QColor(20, 83, 45, 60)     # dark green

            items = [
                rec.get("timestamp", ""),
                str(rec.get("pid", "N/A")),
                rec.get("name", "Unknown"),
                rec.get("exe", "N/A"),
                str(rec.get("score", "")),
                f"{risk:.2f}",
                rec.get("status", "Flagged"),
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setBackground(row_color)
                self.process_table.setItem(row, col, item)

    def _clear_flagged_processes(self):
        """Clear the flagged processes list."""
        if hasattr(self.backend, "_flagged_processes"):
            self.backend._flagged_processes.clear()
        if hasattr(self, "process_table"):
            self.process_table.setRowCount(0)
            self.process_count_label.setText("No flagged processes yet.")

    def switch_page(self, index):
        self.content_stack.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_buttons):
            btn.setProperty("active", "true" if i == index else "false")
            btn.setStyle(btn.style())

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

        # Refresh the processes table (real mode only)
        self._refresh_processes_table()

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
