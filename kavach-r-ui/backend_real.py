"""
backend_real.py — Real detection-engine backend for the Kavach-R UI.

Wraps the kavach detection pipeline (monitor + detector + ML model)
and exposes the same interface as BackendMock so the UI can swap
between them seamlessly.
"""

import logging
import os
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# Ensure the project root is on sys.path so `kavach` package imports work
_UI_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _UI_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.append(str(_PROJECT_ROOT))

from kavach.detector import Detector
from kavach.events import FileEvent
from kavach.feature_engine import FeatureEngine
from kavach.monitor import start as monitor_start, stop as monitor_stop
from kavach.process_monitor import get_process_info

logger = logging.getLogger("kavach.backend_real")

# Default model path (repo root)
_DEFAULT_MODEL_PATH = _PROJECT_ROOT / "model.joblib"


class RealBackend:
    """Real detection backend that wraps the kavach ML pipeline.

    Provides the same public interface as BackendMock:
        scanning, start_scan, stop_scan, set_scenario,
        get_risk_and_metrics, get_recent_logs, clear_logs
    """

    def __init__(self, model_path: str | Path | None = None, window_size: float = 10.0, threshold: float = -0.3):
        self.model_path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
        self.window_size = window_size
        self.threshold = threshold

        self.scanning = False
        self.risk_score = 0.0
        self.logs: list[str] = []
        self.scenario = "REAL"  # Always real — scenarios are mock-only
        self.current_metrics: dict = {}

        self._lock = threading.Lock()
        self._detector: Detector | None = None
        self._feature_engine: FeatureEngine | None = None

        # Tracked state for metrics
        self._last_alert: dict | None = None
        self._event_count = 0
        self._last_score = 0.0

    # ------------------------------------------------------------------
    # Public API (same interface as BackendMock)
    # ------------------------------------------------------------------

    def set_scenario(self, scenario_name: str) -> None:
        """No-op in real mode — scenarios are only for mock."""
        self.add_log(f"Scenario buttons disabled in real mode (ignored: {scenario_name})")

    def start_scan(self, watch_paths: list[str] | None = None) -> None:
        """Start the file-system monitor and detection engine."""
        if self.scanning:
            return

        if not self.model_path.exists():
            self.add_log(f"ERROR: Model file not found: {self.model_path}")
            logger.error("Model file not found: %s", self.model_path)
            return

        try:
            self._detector = Detector(
                model_path=self.model_path,
                window_size=self.window_size,
                threshold=self.threshold,
            )
            # Standalone feature engine for live metrics display
            self._feature_engine = FeatureEngine(window_size=self.window_size)

            self.scanning = True
            self._event_count = 0
            self._last_score = 0.0
            self._last_alert = None
            self.add_log("Real-time scan started. Behavioral monitoring active.")

            # Decide what to watch
            if watch_paths is None:
                watch_paths = [os.path.expanduser("~")]

            # Start the watchdog monitor (runs in a background thread)
            monitor_start(callback=self._on_event, paths=watch_paths)
            self.add_log(f"Monitoring: {', '.join(watch_paths)}")

        except Exception as exc:
            logger.exception("Failed to start scan")
            self.add_log(f"ERROR starting scan: {exc}")
            self.scanning = False

    def stop_scan(self) -> None:
        """Stop the monitor and reset state."""
        if not self.scanning:
            return

        try:
            monitor_stop()
        except Exception:
            logger.exception("Error stopping monitor")

        self.scanning = False
        self.risk_score = 0.0
        self._detector = None
        self._feature_engine = None
        self._last_alert = None
        self._event_count = 0
        self._last_score = 0.0
        self.add_log("Scan stopped.")

    def get_risk_and_metrics(self) -> tuple[float, dict]:
        """Return (risk_score, metrics_dict) matching the UI's expected format."""
        with self._lock:
            if not self.scanning:
                return 0.0, self._empty_metrics()

            metrics = self._build_metrics()
            return self.risk_score, metrics

    def get_recent_logs(self) -> list[str]:
        """Return the most recent log entries."""
        with self._lock:
            return self.logs[-50:]

    def add_log(self, message: str) -> None:
        """Append a timestamped log entry."""
        ts = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append(f"[{ts}] {message}")

    def clear_logs(self) -> None:
        """Clear the log buffer."""
        with self._lock:
            self.logs = []
        self.add_log("Logs cleared.")

    # ------------------------------------------------------------------
    # Internal: event callback from the monitor
    # ------------------------------------------------------------------

    def _on_event(self, event: FileEvent) -> None:
        """Called by kavach.monitor for every file-system event."""
        if not self.scanning or self._detector is None:
            return

        with self._lock:
            self._event_count += 1

            # Also feed the standalone feature engine for live metrics
            if self._feature_engine is not None:
                self._feature_engine.add_event(event)

        # Run through the detector (may return an alert or None)
        alert = self._detector.process_event(event)

        with self._lock:
            if alert is not None:
                # Detector returned an anomaly
                raw_score = alert["score"]  # negative = anomalous (sklearn)
                # Map to 0-1 scale:  score of -0.5 → risk 1.0,  score of +0.5 → risk 0.0
                self.risk_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)
                self._last_score = raw_score
                self._last_alert = alert

                pid = alert.get("pid")
                self.logs.append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"🚨 ANOMALY pid={pid}  score={raw_score:.4f}  risk={self.risk_score:.4f}"
                )
            else:
                # No anomaly — score drifts back toward safe
                # Use the detector's internal engine to get the latest score
                if self._detector._engine.event_count >= self._detector.min_events:
                    features = self._detector._engine.extract_features()
                    raw_score = self._detector._model.score(features)
                    self.risk_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)
                    self._last_score = raw_score
                else:
                    # Not enough events yet — keep low risk
                    self.risk_score = max(0.0, self.risk_score - 0.01)

    # ------------------------------------------------------------------
    # Internal: metrics construction
    # ------------------------------------------------------------------

    def _build_metrics(self) -> dict:
        """Build a metrics dict matching BackendMock's format for the UI."""
        if self._feature_engine is None:
            return self._empty_metrics()

        features = self._feature_engine.extract_features()

        # Map real feature names → UI metric keys
        metrics = {
            "files_modified_per_sec": round(features.get("files_modified_per_sec", 0.0), 2),
            "renames_per_sec": round(features.get("rename_rate", 0.0), 2),
            "entropy_change": round(features.get("entropy_change", 0.0), 3),
            "ext_change_rate": round(features.get("extension_change_rate", 0.0), 2),
            "unique_files_per_min": int(features.get("unique_files_touched", 0)),
            "mod_acc_ratio": 0.0,  # Not tracked by the real engine
            "cpu_usage": 0.0,      # Would require psutil process iteration
            "file_handles": 0,     # Would require psutil
            "scenario": "REAL",
        }

        # If there's a recent alert, populate threat details
        if self._last_alert and self.risk_score > 0.6:
            alert = self._last_alert
            pid = alert.get("pid")
            proc_info = None
            if pid is not None:
                proc_info = get_process_info(pid)

            metrics["scenario"] = "ATTACK"
            metrics["threat_details"] = {
                "source_process": proc_info.name if proc_info else "Unknown",
                "pid": pid or 0,
                "origin_path": proc_info.exe if proc_info else "N/A",
                "parent_process": "N/A",
                "hash": "N/A",
                "action_taken": "Flagged",
                "response_status": "MONITORING",
            }
        elif self.risk_score > 0.3:
            metrics["scenario"] = "WARNING"
        else:
            metrics["scenario"] = "IDLE"

        return metrics

    @staticmethod
    def _empty_metrics() -> dict:
        """Return zeroed-out metrics matching the UI's expected format."""
        return {
            "files_modified_per_sec": 0.0,
            "renames_per_sec": 0.0,
            "entropy_change": 0.0,
            "ext_change_rate": 0.0,
            "unique_files_per_min": 0,
            "mod_acc_ratio": 0.0,
            "cpu_usage": 0.0,
            "file_handles": 0,
            "scenario": "IDLE",
        }


def is_model_available(model_path: str | Path | None = None) -> bool:
    """Check if the trained model file exists."""
    path = Path(model_path) if model_path else _DEFAULT_MODEL_PATH
    return path.exists()
