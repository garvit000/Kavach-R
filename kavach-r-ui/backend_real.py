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

# Silence the detector's own logger — we handle logging in the UI ourselves
logging.getLogger("kavach.detector").setLevel(logging.CRITICAL)

# Default model path (repo root)
_DEFAULT_MODEL_PATH = _PROJECT_ROOT / "model.joblib"


class RealBackend:
    """Real detection backend that wraps the kavach ML pipeline.

    Provides the same public interface as BackendMock:
        scanning, start_scan, stop_scan, set_scenario,
        get_risk_and_metrics, get_recent_logs, clear_logs
    """

    def __init__(self, model_path: str | Path | None = None, window_size: float = 10.0, threshold: float = -0.5):
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
        self._smoothed_risk = 0.0  # EMA-smoothed risk score
        self._last_log_time = 0.0  # Throttle anomaly log spam
        self._flagged_processes: list[dict] = []  # Detailed process info for UI tab
        self._scan_start_time = 0.0  # For warm-up period

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
            self._smoothed_risk = 0.0
            self._last_alert = None
            self._last_log_time = 0.0
            self._scan_start_time = time.time()
            self.add_log("Real-time scan started. Behavioral monitoring active.")
            self.add_log("Warm-up: calibrating for 15 seconds...")

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
        self._smoothed_risk = 0.0
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

    def get_flagged_processes(self) -> list[dict]:
        """Return all flagged process records for the Processes tab."""
        with self._lock:
            return list(self._flagged_processes)

    # ------------------------------------------------------------------
    # Internal: event callback from the monitor
    # ------------------------------------------------------------------

    _EMA_ALPHA = 0.15          # Low alpha = very smooth risk transitions
    _LOG_THROTTLE_SEC = 10.0   # Min seconds between anomaly log lines
    _WARMUP_SEC = 15.0         # Seconds to ignore after scan starts
    _FLAG_RISK_THRESHOLD = 0.5 # Only flag process when smoothed risk > this

    def _on_event(self, event: FileEvent) -> None:
        """Called by kavach.monitor for every file-system event."""
        if not self.scanning or self._detector is None:
            return

        now = time.time()

        with self._lock:
            self._event_count += 1

            # Also feed the standalone feature engine for live metrics
            if self._feature_engine is not None:
                self._feature_engine.add_event(event)

        # During warm-up, only feed the engine — don't score or flag
        elapsed_since_start = now - self._scan_start_time
        if elapsed_since_start < self._WARMUP_SEC:
            # Still feed the detector so it has events in its window
            self._detector.process_event(event)
            return

        # Run through the detector (may return an alert or None)
        alert = self._detector.process_event(event)

        with self._lock:
            if alert is not None:
                raw_score = alert["score"]  # negative = anomalous (sklearn)
                self._last_score = raw_score

                # Map to 0-1 risk:  only scores well below threshold are dangerous
                # threshold=-0.5, score=-0.5 → risk=0.3, score=-1.0 → risk=0.8
                distance = self.threshold - raw_score  # positive when anomalous
                instant_risk = max(0.0, min(1.0, 0.3 + distance))
            else:
                # No anomaly — risk should drift toward safe
                instant_risk = 0.05  # baseline low risk

            # Apply EMA smoothing
            self._smoothed_risk = (
                self._EMA_ALPHA * instant_risk
                + (1 - self._EMA_ALPHA) * self._smoothed_risk
            )
            self.risk_score = round(max(0.0, min(1.0, self._smoothed_risk)), 4)

            # Only flag and log when smoothed risk is above meaningful threshold
            if alert is not None and self.risk_score > self._FLAG_RISK_THRESHOLD:
                self._last_alert = alert
                pid = alert.get("pid")

                # Record detailed process info for the Processes tab
                proc_info = None
                if pid is not None:
                    proc_info = get_process_info(pid)

                record = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "pid": pid or "N/A",
                    "name": proc_info.name if proc_info else "Unknown",
                    "exe": proc_info.exe if proc_info else "N/A",
                    "score": round(raw_score, 4),
                    "risk": self.risk_score,
                    "features": alert.get("features", {}),
                    "status": "Flagged",
                }
                self._flagged_processes.append(record)

                if now - self._last_log_time >= self._LOG_THROTTLE_SEC:
                    self._last_log_time = now
                    self.logs.append(
                        f"[{record['timestamp']}] "
                        f"⚠ Anomaly  score={raw_score:.4f}  risk={self.risk_score:.2f}"
                    )

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
