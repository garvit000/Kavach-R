"""
model.py — Anomaly detection model for Kavach-R.

Thin wrapper around scikit-learn's IsolationForest that provides a clean
API for training on benign file-system behaviour, persisting the model,
and scoring new feature vectors at runtime.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from kavach.feature_engine import FEATURE_NAMES

logger = logging.getLogger(__name__)


class KavachModel:
    """IsolationForest-based anomaly scorer.

    Parameters:
        contamination: Expected fraction of anomalies in the training data.
                       Use a small value (default 0.05) when training on
                       mostly-benign samples.
        random_state:  Seed for reproducibility.
    """

    def __init__(
        self,
        contamination: float = 0.20,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self._model: IsolationForest | None = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, samples: list[dict[str, float]]) -> None:
        """Fit the model on a list of *normal-behaviour* feature vectors.

        Each sample should be a dict with keys matching ``FEATURE_NAMES``.

        Args:
            samples: List of feature dicts (e.g. from FeatureEngine.extract_features()).
        """
        matrix = self._dicts_to_matrix(samples)
        logger.info("Training IsolationForest on %d samples …", len(samples))
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        self._model.fit(matrix)
        logger.info("Training complete.")

    # ------------------------------------------------------------------
    # Scoring / Prediction
    # ------------------------------------------------------------------

    def score(self, features: dict[str, float]) -> float:
        """Return the anomaly score for a single feature vector.

        Scores follow the scikit-learn convention:
          • negative values → more anomalous
          • positive values → more normal
          • 0 ≈ decision boundary

        Raises:
            RuntimeError: If the model has not been trained or loaded.
        """
        self._ensure_fitted()
        row = self._dict_to_row(features)
        return float(self._model.score_samples(row)[0])  # type: ignore[union-attr]

    def predict(self, features: dict[str, float]) -> bool:
        """Return ``True`` if the feature vector is classified as anomalous.

        Uses the IsolationForest's built-in decision function (threshold ≈ 0).
        """
        self._ensure_fitted()
        row = self._dict_to_row(features)
        label = self._model.predict(row)[0]  # type: ignore[union-attr]
        return bool(label == -1)  # sklearn uses -1 for anomalies

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_model(self, path: str | Path) -> None:
        """Serialize the trained model to disk with joblib."""
        self._ensure_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, path)
        logger.info("Model saved to %s", path)

    def load_model(self, path: str | Path) -> None:
        """Load a previously saved model from disk."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        self._model = joblib.load(path)
        logger.info("Model loaded from %s", path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_fitted(self) -> None:
        if self._model is None:
            raise RuntimeError(
                "Model is not fitted. Call train() or load_model() first."
            )

    @staticmethod
    def _dict_to_row(features: dict[str, float]) -> np.ndarray:
        """Convert a feature dict to a (1, n_features) numpy array."""
        return np.array([[features[name] for name in FEATURE_NAMES]])

    @staticmethod
    def _dicts_to_matrix(samples: list[dict[str, float]]) -> np.ndarray:
        """Convert a list of feature dicts to a (n_samples, n_features) array."""
        return np.array(
            [[s[name] for name in FEATURE_NAMES] for s in samples]
        )
