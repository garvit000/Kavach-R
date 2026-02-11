"""
process_monitor.py — Process inspection & response utilities for Kavach-R.

Provides lightweight wrappers around ``psutil`` (optional) for looking up
process details and taking response actions (suspend / kill).

These utilities are meant to be called by the **integration layer**
(kavach_main.py) when the detector flags an anomaly — the detection layer
itself never calls these directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


@dataclass
class ProcessInfo:
    """Snapshot of a running process."""

    pid: int
    name: str = ""
    exe: str = ""
    cmdline: List[str] = field(default_factory=list)
    username: str = ""
    status: str = ""


def get_process_info(pid: int) -> ProcessInfo | None:
    """Return a :class:`ProcessInfo` for the given PID, or ``None``.

    Requires ``psutil``.  Returns ``None`` if the process doesn't exist
    or psutil is not installed.
    """
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("psutil not installed — cannot inspect process %d", pid)
        return None

    try:
        proc = psutil.Process(pid)
        return ProcessInfo(
            pid=proc.pid,
            name=proc.name(),
            exe=proc.exe(),
            cmdline=proc.cmdline(),
            username=proc.username(),
            status=proc.status(),
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.warning("Cannot inspect pid %d: %s", pid, exc)
        return None


def suspend_process(pid: int) -> bool:
    """Suspend (SIGSTOP) the process with the given PID.

    Returns ``True`` on success, ``False`` otherwise.
    """
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        logger.error("psutil not installed — cannot suspend process %d", pid)
        return False

    try:
        proc = psutil.Process(pid)
        proc.suspend()
        logger.info("Suspended process pid=%d (%s)", pid, proc.name())
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.error("Failed to suspend pid %d: %s", pid, exc)
        return False


def kill_process(pid: int) -> bool:
    """Kill the process with the given PID.

    Returns ``True`` on success, ``False`` otherwise.
    """
    try:
        import psutil  # type: ignore[import-not-found]
    except ImportError:
        logger.error("psutil not installed — cannot kill process %d", pid)
        return False

    try:
        proc = psutil.Process(pid)
        proc.kill()
        logger.info("Killed process pid=%d (%s)", pid, proc.name())
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        logger.error("Failed to kill pid %d: %s", pid, exc)
        return False
