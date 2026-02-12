from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout, QGridLayout, QListWidget
from PySide6.QtCore import Qt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from matplotlib.collections import LineCollection
import numpy as np

class RiskGraph(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        # Dark theme for matplotlib
        plt.style.use('dark_background')
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        
        # Clean styling - Minimalist EDR Look
        self.axes.set_ylim(0, 1.05)
        self.axes.set_xlim(0, 60)
        
        # Custom Grid - Subtle vertical/horizontal
        self.axes.grid(True, linestyle=':', alpha=0.1, color='#E6EDF3')
        
        # Remove Spines for clean look
        self.axes.spines['top'].set_visible(False)
        self.axes.spines['right'].set_visible(False)
        self.axes.spines['left'].set_visible(False)
        self.axes.spines['bottom'].set_visible(False)
        
        # Remove ticks
        self.axes.set_xticks([])
        self.axes.set_yticks([0, 0.5, 1.0])
        self.axes.tick_params(axis='y', colors='#4B5563', labelsize=8)
        
        # Match card background
        fig.patch.set_facecolor('#1A1D24')
        self.axes.set_facecolor('#1A1D24')
        
        # Remove padding
        fig.tight_layout(pad=1.5)
        
        # Initialize data with zeros (flat line start)
        self.x_data = list(range(60))
        self.y_data = [0.0] * 60
        
        # Main Line
        self.line, = self.axes.plot(self.x_data, self.y_data, color='#22C55E', linewidth=2)
        
        # Fill area (Area Chart effect)
        self.fill = self.axes.fill_between(self.x_data, self.y_data, color='#22C55E', alpha=0.1)
        
        super().__init__(fig)
        self.setParent(parent)

    def update_graph(self, new_risk):
        # Sliding window update
        self.y_data.append(new_risk)
        self.y_data.pop(0)
        
        # Determine Color based on current risk
        if new_risk >= 0.6:
            color = '#EF4444' # Red
        elif new_risk >= 0.3:
            color = '#F59E0B' # Amber
        else:
            color = '#22C55E' # Green
            
        self.line.set_ydata(self.y_data)
        self.line.set_color(color)
        
        # Update Fill
        # fill_between returns a PolyCollection, we can't easily update data
        # removing and adding is the reliable way in backend_qt5agg for dynamic updates
        self.fill.remove()
        self.fill = self.axes.fill_between(self.x_data, self.y_data, color=color, alpha=0.12)
        
        self.draw()

    def reset_graph(self):
        self.y_data = [0.0] * 60
        self.line.set_ydata(self.y_data)
        self.line.set_color('#22C55E')
        self.fill.remove()
        self.fill = self.axes.fill_between(self.x_data, self.y_data, color='#22C55E', alpha=0.1)
        self.draw()

class ThreatDetailsCard(QFrame):
    def __init__(self):
        super().__init__()
        # Remove ObjectName "Card" to remove default card style
        # Apply specific style: transparent background, no border except the left indicator
        self.setStyleSheet("""
            background-color: transparent; 
            border: none;
        """) 
        self.setMaximumHeight(250)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 5, 5, 5) # Added top margin
        layout.setSpacing(5) # Reduce spacing
        
        header = QLabel("🚨 THREAT DETAILS")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #E6EDF3; margin-bottom: 2px;")
        header.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.addWidget(header)
        
        self.content_label = QLabel("No active threats detected.")
        self.content_label.setStyleSheet("color: #9DA7B3; font-size: 13px;")
        self.content_label.setWordWrap(True)
        self.content_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        layout.addWidget(self.content_label)
        
        layout.addStretch() # Push everything up
        
    def update_threats(self, status, details=None):
        if status == "CRITICAL" and details:
            self.setStyleSheet("""
                background-color: transparent; 
                border: none;
            """)
            # Using HTML for formatting
            text = f"""
            <p><b>Source Process:</b> <span style='color:#EF4444'>{details.get('source_process', 'N/A')}</span></p>
            <p><b>PID:</b> {details.get('pid', 'N/A')} &nbsp;|&nbsp; <b>Parent:</b> {details.get('parent_process', 'N/A')}</p>
            <p><b>Path:</b> {details.get('origin_path', 'N/A')}</p>
            <p><b>Hash:</b> {details.get('hash', 'N/A')}</p>
            <p><b>Action Taken:</b> <span style='color:#22C55E; font-weight:bold'>{details.get('action_taken', 'Monitoring')}</span></p>
            """
            self.content_label.setText(text)
        else:
            self.setStyleSheet("""
                background-color: transparent; 
                border: none;
            """)
            self.content_label.setText("No active threats detected.\nSystem monitoring baseline activity.")

class IncidentLogPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("Card")
        self.setMaximumHeight(250) # Maintain max height
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        header = QLabel("📜 INCIDENT LOG")
        header.setStyleSheet("font-size: 12px; font-weight: bold; color: #9DA7B3; margin-bottom: 5px; background-color: transparent;")
        layout.addWidget(header)
        
        self.log_list = QListWidget()
        self.log_list.setStyleSheet("""
            QListWidget {
                background-color: #11141A; 
                border: 1px solid #2A2F3A; 
                border-radius: 4px; 
                color: #E6EDF3;
                font-family: Consolas, monospace;
                font-size: 11px;
            }
            QListWidget::item {
                padding: 2px;
                border-bottom: 1px solid #1A2230;
            }
        """)
        layout.addWidget(self.log_list)
        
    def update_logs(self, logs):
        self.log_list.clear()
        # Take only the last 20 logs for the dashboard panel
        recent_logs = logs[-20:]
        self.log_list.addItems(recent_logs[::-1]) # Newest first

class DashboardWidget(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # ------------------------------------------------------------------
        # HEADER: KAVACH-R Logo (Left) & Risk Info (Right)
        # ------------------------------------------------------------------
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 10)
        header_layout.setSpacing(12) # Match spacing of rows below
        
        # Logo (Left - 60% width to match columns below)
        logo_label = QLabel('<html><head/><body><p><span style="color:#FF9933;">KA</span><span style="color:#FFFFFF;">VA</span><span style="color:#138808;">CH</span><span style="color:#3B82F6;">-R</span></p></body></html>')
        logo_label.setStyleSheet("font-size: 26px; font-weight: bold; letter-spacing: 1px;")
        logo_label.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        header_layout.addWidget(logo_label, 6)

        # Status Container Box (Right - 40% width to match columns below)
        status_box = QFrame()
        status_box.setStyleSheet("""
            background-color: #11141A; 
            border: 1px solid #2A2F3A; 
            border-radius: 6px;
        """)
        status_layout = QHBoxLayout(status_box)
        status_layout.setContentsMargins(12, 6, 12, 6)
        status_layout.setSpacing(16)
        
        # Center the content inside the box
        status_layout.addStretch()

        # Risk Value
        self.score_val = QLabel("0.00")
        self.score_val.setObjectName("RiskLabel")
        self.score_val.setStyleSheet("font-size: 44px; font-weight: 700; color: #22C55E; background-color: transparent; border: none;") 
        self.score_val.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        status_layout.addWidget(self.score_val)

        # Risk Status Badge
        self.response_badge = QLabel("Not Monitoring")
        self.response_badge.setStyleSheet("background-color: #4B5563; color: #E6EDF3; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; border: none;")
        self.response_badge.setAlignment(Qt.AlignCenter)
        self.response_badge.setFixedHeight(24)
        status_layout.addWidget(self.response_badge)

        # System Status Badge
        self.status_val = QLabel("SECURE")
        self.status_val.setObjectName("StatusLabel")
        self.status_val.setAlignment(Qt.AlignCenter)
        self.status_val.setFixedHeight(24)
        # Using padding to make it look like a badge
        self.status_val.setStyleSheet("background-color: #14532D; color: #22C55E; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px; border: none;") 
        status_layout.addWidget(self.status_val)
        
        status_layout.addStretch()

        header_layout.addWidget(status_box, 4)

        layout.addLayout(header_layout, 1) # Small vertical weight for header

        # ------------------------------------------------------------------
        # ROW 2: Threat Details (50%) & Incident Log (50%) - 30% Height
        # ------------------------------------------------------------------
        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(12)
        
        self.threat_card = ThreatDetailsCard()
        row2_layout.addWidget(self.threat_card, 6)
        
        self.incident_panel = IncidentLogPanel()
        row2_layout.addWidget(self.incident_panel, 4)
        
        layout.addLayout(row2_layout, 3) # 30% vertical weight

        # ------------------------------------------------------------------
        # ROW 3: Live Risk Graph (60%) & Metric Cards (40%) - 50% Height
        # ------------------------------------------------------------------
        row3_layout = QHBoxLayout()
        row3_layout.setSpacing(12)

        # Graph Section (Left - 60%)
        graph_card = QFrame()
        graph_card.setObjectName("Card")
        graph_card.setMaximumHeight(350) # Maintain max height as per request
        graph_vbox = QVBoxLayout(graph_card)
        graph_vbox.setContentsMargins(8, 8, 8, 8)
        
        # Header for Graph
        graph_header = QLabel("LIVE RISK ANALYSIS")
        graph_header.setStyleSheet("font-size: 11px; font-weight: bold; color: #9DA7B3; margin-left: 8px; margin-top: 4px; background-color: transparent;")
        graph_vbox.addWidget(graph_header)
        
        self.canvas = RiskGraph(self)
        graph_vbox.addWidget(self.canvas)
        row3_layout.addWidget(graph_card, 6)

        # Metrics Grid (Right - 40%)
        # 2 Rows x 4 Cols Layout (User request)
        metrics_container = QWidget()
        metrics_grid = QGridLayout(metrics_container)
        metrics_grid.setContentsMargins(0, 0, 0, 0)
        metrics_grid.setSpacing(8)
        
        # Initialize Metrics
        self.metric_files = self._create_metric("Files/Sec", "0.0", "#3B82F6")
        self.metric_renames = self._create_metric("Renames/Sec", "0.0", "#3B82F6")
        self.metric_unique = self._create_metric("Unique/Min", "0", "#3B82F6") # Shortened title
        self.metric_entropy = self._create_metric("Entropy Δ", "0.0", "#F59E0B")
        self.metric_ext = self._create_metric("Ext Chg Rate", "0.0", "#F59E0B") # Shortened title
        self.metric_ratio = self._create_metric("Mod/Acc Ratio", "0.0", "#F59E0B")
        self.metric_cpu = self._create_metric("CPU Usage %", "0.0", "#8B5CF6")
        self.metric_handles = self._create_metric("File Handles", "0", "#8B5CF6")

        # Add to Grid (2 Rows x 4 Cols)
        metrics_grid.addWidget(self.metric_files, 0, 0)
        metrics_grid.addWidget(self.metric_renames, 0, 1)
        metrics_grid.addWidget(self.metric_unique, 0, 2)
        metrics_grid.addWidget(self.metric_entropy, 0, 3)
        
        metrics_grid.addWidget(self.metric_ext, 1, 0)
        metrics_grid.addWidget(self.metric_ratio, 1, 1)        
        metrics_grid.addWidget(self.metric_cpu, 1, 2)
        metrics_grid.addWidget(self.metric_handles, 1, 3)

        row3_layout.addWidget(metrics_container, 4)

        layout.addLayout(row3_layout, 5) # 50% vertical weight

    def _create_metric(self, title, val, color):
        card = QFrame()
        # Remove "Card" object name to remove border/background
        card.setStyleSheet("background-color: transparent; border: none;")
        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(4, 4, 4, 4)
        vbox.setSpacing(2)
        
        title_label = QLabel(title)
        title_label.setStyleSheet("font-size: 10px; font-weight: 600; color: #9DA7B3;")
        title_label.setAlignment(Qt.AlignCenter)
        vbox.addWidget(title_label)
        
        lbl = QLabel(val)
        lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
        lbl.setAlignment(Qt.AlignCenter)
        vbox.addWidget(lbl)
        
        card.value_label = lbl
        return card

    def update_ui(self, risk, metrics, logs=[]):
        self.score_val.setText(f"{risk:.2f}")
        
        # Dynamic Risk Score Coloring & Glow
        # IMPORTANT: Maintain font size and transparency when updating color
        base_style = "font-size: 44px; font-weight: 700; background-color: transparent;"
        
        if risk < 0.3:
            # Green
            self.score_val.setStyleSheet(f"{base_style} color: #22C55E;")
        elif risk < 0.6:
            # Amber
            self.score_val.setStyleSheet(f"{base_style} color: #F59E0B;")
        else:
            # Red
            self.score_val.setStyleSheet(f"{base_style} color: #EF4444;")

        self.canvas.update_graph(risk)
        
        self.metric_files.value_label.setText(str(metrics["files_modified_per_sec"]))
        self.metric_renames.value_label.setText(str(metrics["renames_per_sec"]))
        self.metric_entropy.value_label.setText(str(metrics["entropy_change"]))
        self.metric_ext.value_label.setText(str(metrics["ext_change_rate"]))
        
        self.metric_unique.value_label.setText(str(metrics["unique_files_per_min"]))
        self.metric_ratio.value_label.setText(str(metrics["mod_acc_ratio"]))
        self.metric_cpu.value_label.setText(str(metrics["cpu_usage"]))
        self.metric_handles.value_label.setText(str(metrics["file_handles"]))
        
        scenario = metrics.get("scenario", "IDLE")
        threat_details = metrics.get("threat_details", None)

        # System Status Box Logic & Threat Card Update
        if scenario in ["IDLE"]:
            self.status_val.setText("SECURE")
            self.status_val.setStyleSheet("background-color: #14532D; color: #22C55E; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.threat_card.update_threats("SECURE")
            
            # Response Badge
            self.response_badge.setText("Monitoring")
            self.response_badge.setStyleSheet("background-color: #22C55E; color: #000; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;")

        elif scenario == "ATTACK":
            self.status_val.setText("CRITICAL")
            self.status_val.setStyleSheet("background-color: #7F1D1D; color: #EF4444; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.threat_card.update_threats("CRITICAL", threat_details)
            
            # Response Badge — show actual action taken
            action = "Threat Flagged"
            if threat_details and threat_details.get("action_taken") == "Process Terminated":
                action = "Process Terminated"
            self.response_badge.setText(action)
            self.response_badge.setStyleSheet("background-color: #EF4444; color: #FFF; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;")
        
        else: # Legacy/Other
            self.status_val.setText("WARNING")
            self.status_val.setStyleSheet("background-color: #78350F; color: #F59E0B; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;")
            self.threat_card.update_threats("WARNING") # Defaults to secure message
            self.response_badge.setText("Analyzing")
            self.response_badge.setStyleSheet("background-color: #F59E0B; color: #000; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;")
            
        # Update Incident Log Panel
        if logs:
            self.incident_panel.update_logs(logs)

    def reset_ui(self):
        self.score_val.setText("0.00")
        self.score_val.setStyleSheet("font-size: 44px; font-weight: 700; background-color: transparent; color: #22C55E;") # Reset to Green
        
        self.status_val.setText("SECURE")
        self.status_val.setStyleSheet("background-color: #14532D; color: #22C55E; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 11px;")
        
        self.metric_files.value_label.setText("0.0")
        self.metric_renames.value_label.setText("0.0")
        self.metric_entropy.value_label.setText("0.0")
        self.metric_ext.value_label.setText("0.0")
        self.metric_unique.value_label.setText("0")
        self.metric_ratio.value_label.setText("0.0")
        self.metric_cpu.value_label.setText("0.0")
        self.metric_handles.value_label.setText("0")
        self.canvas.reset_graph()
        self.threat_card.update_threats("SECURE")
        self.response_badge.setText("Not Monitoring")
        self.response_badge.setStyleSheet("background-color: #4B5563; color: #E6EDF3; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;")
        # Logs usually cleared by backend clear

