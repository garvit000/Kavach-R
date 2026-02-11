#!/usr/bin/env python3
"""
kavach_main.py — CLI entry point for Kavach-R.

Sub-commands
------------
train   Collect benign file-system events for a configurable duration,
        then train and save the anomaly detection model.

detect  Load a trained model and start the real-time detection loop.
        When the detector flags an anomaly, log a warning with the PID
        and anomaly score.

Usage
-----
    # Train on 60 seconds of benign activity
    python -m kavach.kavach_main train --duration 60 --model-path model.joblib

    # Start detection
    python -m kavach.kavach_main detect --model-path model.joblib
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from kavach.detector import Detector
from kavach.events import FileEvent
from kavach.feature_engine import FeatureEngine
from kavach.model import KavachModel

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("kavach")


# ---------------------------------------------------------------------------
# Train sub-command
# ---------------------------------------------------------------------------

def cmd_train(args: argparse.Namespace) -> None:
    """Collect benign events via the monitor and train the model.

    This function imports ``kavach.monitor`` at call-time so that the
    detection layer doesn't hard-depend on the monitoring layer at import
    time.  If the monitor is not available yet, it falls back to a simple
    synthetic-data generator so the model file can still be created for
    testing.
    """
    model_path: Path = Path(args.model_path)
    duration: float = args.duration
    window_size: float = args.window_size

    logger.info("=== Kavach-R Training Mode ===")
    logger.info("Duration : %.0f s", duration)
    logger.info("Window   : %.1f s", window_size)
    logger.info("Output   : %s", model_path)

    engine = FeatureEngine(window_size=window_size)
    samples: list[dict[str, float]] = []

    # ------------------------------------------------------------------
    # Try to use the real monitor; fall back to synthetic data
    # ------------------------------------------------------------------
    try:
        from kavach.monitor import start as monitor_start  # type: ignore[import-not-found]

        logger.info("Monitor module found — collecting live events …")

        collecting = True

        def _on_event(event: FileEvent) -> None:
            if not collecting:
                return
            engine.add_event(event)
            features = engine.extract_features()
            samples.append(features)

        watch_paths = args.watch_paths or None
        monitor_start(callback=_on_event, paths=watch_paths)
        time.sleep(duration)
        collecting = False
        logger.info("Collection finished.  %d samples captured.", len(samples))

    except ImportError:
        logger.warning(
            "Monitor module not found — generating synthetic normal data for "
            "training.  Replace this with real collection once monitor.py is "
            "available."
        )
        samples = _generate_synthetic_normal(count=200)

    if not samples:
        logger.error("No samples collected. Cannot train.")
        sys.exit(1)

    # Train & save
    model = KavachModel(contamination=args.contamination)
    model.train(samples)
    model.save_model(model_path)
    logger.info("✅ Model saved to %s", model_path)


# ---------------------------------------------------------------------------
# Detect sub-command
# ---------------------------------------------------------------------------

def cmd_detect(args: argparse.Namespace) -> None:
    """Load the trained model and start real-time detection."""
    model_path: Path = Path(args.model_path)
    window_size: float = args.window_size
    threshold: float = args.threshold

    if not model_path.exists():
        logger.error("Model file not found: %s", model_path)
        sys.exit(1)

    logger.info("=== Kavach-R Detection Mode ===")
    logger.info("Model    : %s", model_path)
    logger.info("Window   : %.1f s", window_size)
    logger.info("Threshold: %.3f", threshold)

    detector = Detector(
        model_path=model_path,
        window_size=window_size,
        threshold=threshold,
    )

    # ------------------------------------------------------------------
    # Import the monitor and start a detection loop
    # ------------------------------------------------------------------
    try:
        from kavach.monitor import start as monitor_start  # type: ignore[import-not-found]
    except ImportError:
        logger.error(
            "Monitor module (kavach.monitor) not found.  "
            "Cannot start detection without the monitoring layer."
        )
        sys.exit(1)

    def _on_event(event: FileEvent) -> None:
        alert = detector.process_event(event)
        if alert:
            logger.warning(
                "🚨 HIGH-RISK ACTIVITY  pid=%s  score=%.4f",
                alert["pid"],
                alert["score"],
            )
            # NOTE: Response logic (kill, suspend, alert user) should be
            # implemented HERE by the integration layer — NOT inside the
            # detector.

    logger.info("Starting real-time detection …  Press Ctrl+C to stop.")
    try:
        watch_paths = args.watch_paths or None
        monitor_start(callback=_on_event, paths=watch_paths)
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Detection stopped by user.")


# ---------------------------------------------------------------------------
# Synthetic data helper (used only when monitor is unavailable)
# ---------------------------------------------------------------------------

def _generate_synthetic_normal(count: int = 200) -> list[dict[str, float]]:
    """Create synthetic 'normal' feature vectors for initial model training.

    These mimic low-activity desktop file operations.
    """
    import random

    rng = random.Random(42)
    samples: list[dict[str, float]] = []
    for _ in range(count):
        samples.append(
            {
                "files_modified_per_sec": rng.uniform(0.1, 2.0),
                "rename_rate": rng.uniform(0.0, 0.3),
                "unique_files_touched": rng.uniform(1, 10),
                "extension_change_rate": rng.uniform(0.0, 0.05),
                "entropy_change": rng.uniform(3.5, 5.5),
            }
        )
    return samples


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="kavach",
        description="Kavach-R — Behavioural ransomware early-warning system.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # -- train --
    train_p = sub.add_parser("train", help="Train the anomaly detection model.")
    train_p.add_argument(
        "--model-path",
        default="kavach_model.joblib",
        help="Output path for the trained model (default: kavach_model.joblib).",
    )
    train_p.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="Seconds to collect benign activity (default: 60).",
    )
    train_p.add_argument(
        "--window-size",
        type=float,
        default=10.0,
        help="Sliding window size in seconds (default: 10).",
    )
    train_p.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="IsolationForest contamination parameter (default: 0.05).",
    )
    train_p.add_argument(
        "--watch-paths",
        nargs="+",
        default=None,
        help="Directories to watch (default: home directory).",
    )

    # -- detect --
    detect_p = sub.add_parser("detect", help="Start real-time detection.")
    detect_p.add_argument(
        "--model-path",
        default="kavach_model.joblib",
        help="Path to the trained model (default: kavach_model.joblib).",
    )
    detect_p.add_argument(
        "--window-size",
        type=float,
        default=10.0,
        help="Sliding window size in seconds (default: 10).",
    )
    detect_p.add_argument(
        "--threshold",
        type=float,
        default=0.0,
        help="Anomaly score threshold (default: 0.0).",
    )
    detect_p.add_argument(
        "--watch-paths",
        nargs="+",
        default=None,
        help="Directories to watch (default: home directory).",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse CLI args and dispatch to the appropriate sub-command."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "train":
        cmd_train(args)
    elif args.command == "detect":
        cmd_detect(args)


if __name__ == "__main__":
    main()
