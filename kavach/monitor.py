"""
monitor.py — File-system event monitor for Kavach-R.

Uses the ``watchdog`` library to watch directories for file changes and
converts raw events into ``FileEvent`` objects that are fed to the
detection layer via a callback.

Public API
----------
start(callback, paths, recursive)
    Begin watching the given paths.  Each file-system event is converted
    to a FileEvent and passed to *callback*.

stop()
    Stop the monitoring loop.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Callable

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from kavach.events import FileEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Mapping watchdog event types → Kavach event_type strings
# ---------------------------------------------------------------------------
_EVENT_MAP = {
    FileCreatedEvent: "create",
    FileModifiedEvent: "modify",
    FileDeletedEvent: "delete",
    FileMovedEvent: "rename",
}

# ---------------------------------------------------------------------------
# Global observer (so stop() can halt it from anywhere)
# ---------------------------------------------------------------------------
_observer: Observer | None = None


class _KavachHandler(FileSystemEventHandler):
    """Translates watchdog events into FileEvent callbacks."""

    def __init__(self, callback: Callable[[FileEvent], None]) -> None:
        super().__init__()
        self._callback = callback

    # Catch-all for the four event types we care about
    def on_any_event(self, event) -> None:  # noqa: ANN001
        if event.is_directory:
            return

        event_type = _EVENT_MAP.get(type(event))
        if event_type is None:
            return

        # For moved/renamed events, use the destination path
        file_path = getattr(event, "dest_path", None) or event.src_path

        # Try to determine the PID (best-effort; not always possible)
        pid = _guess_pid(file_path)

        fe = FileEvent(
            timestamp=time.time(),
            event_type=event_type,
            file_path=file_path,
            pid=pid,
        )
        try:
            self._callback(fe)
        except Exception:
            logger.exception("Callback raised an exception for event: %s", fe)


def _guess_pid(file_path: str) -> int | None:
    """Best-effort PID lookup — disabled for performance.

    The old implementation iterated every running process on each file event
    which caused severe performance issues.  PID resolution is now handled
    lazily by the backend when an attack is confirmed (using I/O-based
    process scanning instead of per-event open_files lookup).
    """
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start(
    callback: Callable[[FileEvent], None],
    paths: list[str] | None = None,
    recursive: bool = True,
) -> None:
    """Start watching *paths* for file-system events.

    Each event is converted to a :class:`FileEvent` and passed to
    *callback*.  This function **does not block** — it starts a
    background observer thread.

    Args:
        callback:  Function that receives a ``FileEvent``.
        paths:     Directories to watch.  Defaults to the user's home
                   directory if not specified.
        recursive: Watch subdirectories recursively (default ``True``).
    """
    global _observer  # noqa: PLW0603

    if paths is None:
        paths = [os.path.expanduser("~")]

    handler = _KavachHandler(callback)
    _observer = Observer()
    for path in paths:
        if not os.path.isdir(path):
            logger.warning("Path does not exist or is not a directory: %s", path)
            continue
        _observer.schedule(handler, path, recursive=recursive)
        logger.info("Watching: %s (recursive=%s)", path, recursive)

    _observer.daemon = True
    _observer.start()
    logger.info("Monitor started.")


def stop() -> None:
    """Stop the monitoring observer."""
    global _observer  # noqa: PLW0603
    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None
        logger.info("Monitor stopped.")
