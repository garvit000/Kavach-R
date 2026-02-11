"""
detector.py — Real-time anomaly detection orchestrator for Kavach-R.

Combines the FeatureEngine and KavachModel into a stateful pipeline:
  1. Receive a FileEvent.
  2. Update the sliding window.
  3. Extract features.
  4. Score with the trained model.
  5. Return an alert dict if anomalous, else None.

This module does NOT perform any response actions (killing processes,
suspending PIDs, etc.).  Response logic belongs to the caller.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from kavach.events import FileEvent
from kavach.feature_engine import FeatureEngine
from kavach.model import KavachModel

logger = logging.getLogger(__name__)


class Detector:
    """Stateful real-time anomaly detector.

    Parameters:
        model_path:  Path to a previously trained model (joblib file).
        window_size: Sliding window duration in seconds.
        threshold:   Anomaly score threshold.  Scores **below** this value
                     are treated as anomalous (sklearn convention).
                     Default 0.0 matches the IsolationForest decision boundary.
    """

    def __init__(
        self,
        model_path: str | Path,
        window_size: float = 10.0,
        threshold: float = 0.0,
    ) -> None:
        self.threshold = threshold
        self._engine = FeatureEngine(window_size=window_size)
        self._model = KavachModel()
        self._model.load_model(model_path)
        logger.info(
            "Detector initialised (window=%.1fs, threshold=%.3f)",
            window_size,
            threshold,
        )

    def process_event(self, event: FileEvent) -> dict[str, Any] | None:
        """Ingest a single FileEvent and return an alert if anomalous.

        Returns:
            A dict with keys ``score``, ``features``, ``is_anomaly``, and
            ``pid`` if the event pushes the current window into anomaly
            territory.  Returns ``None`` otherwise.
        """
        self._engine.add_event(event)
        features = self._engine.extract_features()
        score = self._model.score(features)
        is_anomaly = score < self.threshold

        if is_anomaly:
            alert = {
                "score": score,
                "features": features,
                "is_anomaly": True,
                "pid": event.pid,
                "timestamp": event.timestamp,
            }
            logger.warning(
                "🚨 ANOMALY DETECTED  pid=%s  score=%.4f  features=%s",
                event.pid,
                score,
                features,
            )
            return alert

        return None
