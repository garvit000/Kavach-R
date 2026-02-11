"""Kavach-R utility functions."""

import os
import random
import string
import time


def generate_random_data(size: int = 256) -> str:
    """Generate a string of random printable characters."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=size))


def safe_sleep(seconds: float = 1.0) -> None:
    """Sleep wrapper that handles keyboard interrupts gracefully."""
    try:
        time.sleep(seconds)
    except KeyboardInterrupt:
        pass


def clear_terminal() -> None:
    """Clear the terminal screen (cross-platform)."""
    os.system("cls" if os.name == "nt" else "clear")


def timestamp() -> str:
    """Return a formatted timestamp string."""
    return time.strftime("%H:%M:%S")
