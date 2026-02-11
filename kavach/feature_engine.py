"""
feature_engine.py — Behavioral feature extraction for Kavach-R.

Maintains a sliding time-window of FileEvents and extracts statistical
features that characterise ransomware-like activity (high rename rates,
extension changes, entropy spikes, etc.).
"""

from __future__ import annotations

import math
import os
from collections import deque
from typing import Deque

from kavach.events import FileEvent


# ---------------------------------------------------------------------------
# Feature names (order matters — model training and scoring use this order)
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "files_modified_per_sec",
    "rename_rate",
    "unique_files_touched",
    "extension_change_rate",
    "entropy_change",
]


class FeatureEngine:
    """Sliding-window feature extractor.

    Parameters:
        window_size: Duration of the sliding window in seconds (default 10).
        entropy_sample_size: Bytes to read when computing file entropy (default 4096).
        max_entropy_files: Max number of recently-modified files to sample for
                          entropy calculation (keeps overhead bounded).
    """

    def __init__(
        self,
        window_size: float = 10.0,
        entropy_sample_size: int = 4096,
        max_entropy_files: int = 10,
    ) -> None:
        self.window_size = window_size
        self.entropy_sample_size = entropy_sample_size
        self.max_entropy_files = max_entropy_files
        self._buffer: Deque[FileEvent] = deque()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(self, event: FileEvent) -> None:
        """Push an event into the window and prune stale entries."""
        self._buffer.append(event)
        self._prune(event.timestamp)

    def extract_features(self) -> dict[str, float]:
        """Return a feature vector (dict) computed over the current window.

        If the window is empty or has zero elapsed time, all rates default
        to 0.0.
        """
        if not self._buffer:
            return {name: 0.0 for name in FEATURE_NAMES}

        events = list(self._buffer)
        elapsed = events[-1].timestamp - events[0].timestamp
        # Avoid division by zero and single-event spikes
        # (e.g. 1 event in 0.001s shouldn't be 1000 events/sec)
        elapsed = max(elapsed, 1.0)

        modify_count = sum(1 for e in events if e.event_type == "modify")
        rename_events = [e for e in events if e.event_type == "rename"]
        rename_count = len(rename_events)

        unique_files = len({e.file_path for e in events})

        # Extension-change rate: fraction of rename events where the
        # extension changed — e.g. report.docx → report.docx.locked
        ext_change_count = self._count_extension_changes(rename_events)
        ext_change_rate = (
            ext_change_count / rename_count if rename_count > 0 else 0.0
        )

        # Entropy of recently modified files (sampled)
        entropy = self._mean_entropy_of_recent_files(events)

        return {
            "files_modified_per_sec": modify_count / elapsed,
            "rename_rate": rename_count / elapsed,
            "unique_files_touched": float(unique_files),
            "extension_change_rate": ext_change_rate,
            "entropy_change": entropy,
        }

    @property
    def event_count(self) -> int:
        """Number of events currently in the sliding window."""
        return len(self._buffer)

    def clear(self) -> None:
        """Reset the internal buffer."""
        self._buffer.clear()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _prune(self, now: float) -> None:
        """Remove events older than *window_size* seconds from *now*."""
        cutoff = now - self.window_size
        while self._buffer and self._buffer[0].timestamp < cutoff:
            self._buffer.popleft()

    @staticmethod
    def _count_extension_changes(rename_events: list[FileEvent]) -> int:
        """Count rename events that changed the file extension.

        A rename event's ``file_path`` is expected to hold the *new* path.
        We heuristically check whether the extension differs from the stem's
        last known extension (i.e. we look for appended extensions like
        ``.locked``, ``.enc``, ``.cry``).  Since we only have the new
        path, we use a simple heuristic: if the path has two or more dots
        after the base name, treat it as an extension change.
        """
        count = 0
        for event in rename_events:
            base = os.path.basename(event.file_path)
            # e.g. "report.docx.locked" → parts = ["report", "docx", "locked"]
            parts = base.split(".")
            if len(parts) >= 3:
                count += 1
        return count

    def _mean_entropy_of_recent_files(
        self, events: list[FileEvent]
    ) -> float:
        """Compute mean Shannon entropy over a sample of recently modified files."""
        # Collect unique paths of recently modified files (most recent first)
        seen: set[str] = set()
        paths: list[str] = []
        for event in reversed(events):
            if event.event_type == "modify" and event.file_path not in seen:
                seen.add(event.file_path)
                paths.append(event.file_path)
                if len(paths) >= self.max_entropy_files:
                    break

        if not paths:
            return 0.0

        entropies = [
            _compute_file_entropy(p, self.entropy_sample_size) for p in paths
        ]
        # Filter out files we couldn't read (returned 0.0)
        valid = [e for e in entropies if e > 0.0]
        return sum(valid) / len(valid) if valid else 0.0


# -----------------------------------------------------------------------
# Standalone helper (module-level so it's easily testable)
# -----------------------------------------------------------------------

def _compute_file_entropy(path: str, sample_size: int = 4096) -> float:
    """Compute Shannon entropy of the first *sample_size* bytes of a file.

    Returns 0.0 if the file cannot be read or is empty.
    Entropy is measured in bits (log base 2).  Fully random bytes yield
    ≈ 8.0; plaintext is usually 4–5.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_size)
    except (OSError, PermissionError):
        return 0.0

    if not data:
        return 0.0

    length = len(data)
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy
