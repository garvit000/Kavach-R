from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout, QGridLayout
from PySide6.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt

class RiskGraph(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        # Dark theme for matplotlib
        plt.style.use('dark_background')
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        self.axes.set_title("Live Risk Analysis")
        self.axes.set_ylim(0, 1)
        self.axes.grid(True, linestyle='--', alpha=0.3)
        
        fig.patch.set_facecolor('#1E1E1E')
        self.axes.set_facecolor('#1E1E1E')
        
        self.x_data = []
        self.y_data = []
        self.line, = self.axes.plot([], [], color='#0078D4', linewidth=2)
        
        super().__init__(fig)
        self.setParent(parent)

    def update_graph(self, new_risk):
        self.y_data.append(new_risk)
        self.x_data.append(len(self.y_data))
        
        # Keep last 60 points
        if len(self.y_data) > 60:
            self.y_data = self.y_data[-60:]
            self.x_data = self.x_data[-60:]
            
        self.line.set_data(self.x_data, self.y_data)
        self.axes.set_xlim(min(self.x_data), max(self.x_data) if len(self.x_data) > 1 else 10)
        self.draw()

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Top Section: Score and Status
        top_layout = QHBoxLayout()
        
        # Risk Score Card
        score_card = QFrame()
        score_card.setObjectName("Card")
        score_vbox = QVBoxLayout(score_card)
        score_vbox.addWidget(QLabel("Current Risk Score"))
        self.score_val = QLabel("0.00")
        self.score_val.setObjectName("RiskLabel")
        self.score_val.setAlignment(Qt.AlignCenter)
        score_vbox.addWidget(self.score_val)
        top_layout.addWidget(score_card, 2)

        # Status Card
        status_card = QFrame()
        status_card.setObjectName("Card")
        status_vbox = QVBoxLayout(status_card)
        status_vbox.addWidget(QLabel("System Status"))
        self.status_val = QLabel("SECURE")
        self.status_val.setObjectName("StatusLabel")
        self.status_val.setAlignment(Qt.AlignCenter)
        self.status_val.setStyleSheet("background-color: #2E7D32; color: white;")
        status_vbox.addWidget(self.status_val)
        top_layout.addWidget(status_card, 1)

        layout.addLayout(top_layout)

        # Metrics Grid Section (2 x 4)
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(10)
        
        self.metric_files = self._create_metric("Files/Sec", "0.0")
        self.metric_renames = self._create_metric("Renames/Sec", "0.0")
        self.metric_entropy = self._create_metric("Entropy Δ", "0.0")
        self.metric_ext = self._create_metric("Ext Change Rate", "0.0")
        
        self.metric_unique = self._create_metric("Unique Files/Min", "0")
        self.metric_ratio = self._create_metric("Mod/Acc Ratio", "0.0")
        self.metric_cpu = self._create_metric("CPU Usage %", "0.0")
        self.metric_handles = self._create_metric("File Handles", "0")

        metrics_grid.addWidget(self.metric_files, 0, 0)
        metrics_grid.addWidget(self.metric_renames, 0, 1)
        metrics_grid.addWidget(self.metric_entropy, 0, 2)
        metrics_grid.addWidget(self.metric_ext, 0, 3)
        
        metrics_grid.addWidget(self.metric_unique, 1, 0)
        metrics_grid.addWidget(self.metric_ratio, 1, 1)
        metrics_grid.addWidget(self.metric_cpu, 1, 2)
        metrics_grid.addWidget(self.metric_handles, 1, 3)

        layout.addLayout(metrics_grid)

        # Graph Section
        graph_card = QFrame()
        graph_card.setObjectName("Card")
        graph_vbox = QVBoxLayout(graph_card)
        self.canvas = RiskGraph(self)
        graph_vbox.addWidget(self.canvas)
        layout.addWidget(graph_card, 1)

    def _create_metric(self, title, val):
        card = QFrame()
        card.setObjectName("Card")
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(10, 10, 10, 10)
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 11px; color: #AAAAAA;")
        vbox.addWidget(title_label)
        lbl = QLabel(val)
        lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #0078D4;")
        vbox.addWidget(lbl)
        card.value_label = lbl
        return card

    def update_ui(self, risk, metrics):
        self.score_val.setText(f"{risk:.2f}")
        self.canvas.update_graph(risk)
        
        self.metric_files.value_label.setText(str(metrics["files_modified_per_sec"]))
        self.metric_renames.value_label.setText(str(metrics["renames_per_sec"]))
        self.metric_entropy.value_label.setText(str(metrics["entropy_change"]))
        self.metric_ext.value_label.setText(str(metrics["ext_change_rate"]))
        
        self.metric_unique.value_label.setText(str(metrics["unique_files_per_min"]))
        self.metric_ratio.value_label.setText(str(metrics["mod_acc_ratio"]))
        self.metric_cpu.value_label.setText(str(metrics["cpu_usage"]))
        self.metric_handles.value_label.setText(str(metrics["file_handles"]))
        
        if risk < 0.5:
            self.status_val.setText("SAFE")
            self.status_val.setStyleSheet("background-color: #2E7D32; color: white;")
        elif risk < 0.8:
            self.status_val.setText("WARNING")
            self.status_val.setStyleSheet("background-color: #EF6C00; color: white;")
        else:
            self.status_val.setText("CRITICAL")
            self.status_val.setStyleSheet("background-color: #C62828; color: white;")

    def reset_ui(self):
        self.score_val.setText("0.00")
        self.status_val.setText("SECURE")
        self.status_val.setStyleSheet("background-color: #2E7D32; color: white;")
        
        self.metric_files.value_label.setText("0.0")
        self.metric_renames.value_label.setText("0.0")
        self.metric_entropy.value_label.setText("0.0")
        self.metric_ext.value_label.setText("0.0")
        self.metric_unique.value_label.setText("0")
        self.metric_ratio.value_label.setText("0.0")
        self.metric_cpu.value_label.setText("0.0")
        self.metric_handles.value_label.setText("0")
        # Clear graph data? (Line will restart)
