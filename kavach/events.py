"""
events.py — Shared event schema for Kavach-R.

Defines the canonical FileEvent dataclass that the monitoring layer emits
and the detection layer consumes.
"""

from dataclasses import dataclass


@dataclass
class FileEvent:
    """Represents a single file-system event captured by the monitor.

    Attributes:
        timestamp:  Unix epoch time when the event occurred.
        event_type: One of "modify", "rename", "create", "delete".
        file_path:  Absolute path of the affected file.
        pid:        PID of the process that triggered the event (if known).
    """

    timestamp: float
    event_type: str
    file_path: str
    pid: int | None = None
