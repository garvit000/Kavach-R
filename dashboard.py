"""Kavach-R — Live CLI dashboard.

Displays a continuously updating risk score and system status in the
terminal. Uses colorama for cross-platform ANSI colours when available;
falls back to plain text otherwise.
"""

import random
import signal
import sys
import time
from typing import Callable, Optional

from utils import clear_terminal

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _Stub:
        def __getattr__(self, _):
            return ""

    Fore = _Stub()
    Style = _Stub()

_RUNNING = True


def _handle_sigint(sig, frame):
    global _RUNNING
    _RUNNING = False


try:
    signal.signal(signal.SIGINT, _handle_sigint)
except ValueError:
    pass  # not in main thread


def _status_label(score: float) -> str:
    if score >= 0.8:
        return f"{Fore.RED}██ CRITICAL ██{Style.RESET_ALL}"
    if score >= 0.5:
        return f"{Fore.YELLOW}▒▒ WARNING ▒▒{Style.RESET_ALL}"
    return f"{Fore.GREEN}░░  SAFE   ░░{Style.RESET_ALL}"


def _bar(score: float, width: int = 30) -> str:
    filled = int(score * width)
    empty = width - filled
    if score >= 0.8:
        colour = Fore.RED
    elif score >= 0.5:
        colour = Fore.YELLOW
    else:
        colour = Fore.GREEN
    return f"{colour}{'█' * filled}{'░' * empty}{Style.RESET_ALL}"


def _default_risk() -> float:
    return round(random.uniform(0.0, 1.0), 4)


def run_dashboard(
    get_risk_score: Optional[Callable[[], float]] = None,
    refresh_interval: float = 1.0,
) -> None:
    """Run the live CLI dashboard until Ctrl-C."""
    global _RUNNING
    _RUNNING = True
    score_fn = get_risk_score or _default_risk

    while _RUNNING:
        score = score_fn()
        clear_terminal()

        header = f"{Fore.CYAN}╔══════════════════════════════════════════╗{Style.RESET_ALL}"
        footer = f"{Fore.CYAN}╚══════════════════════════════════════════╝{Style.RESET_ALL}"

        print(header)
        print(f"{Fore.CYAN}║{Style.RESET_ALL}       K A V A C H - R   Dashboard       {Fore.CYAN}║{Style.RESET_ALL}")
        print(footer)
        print()
        print(f"  Risk Score  : {score:.4f}  {_bar(score)}")
        print(f"  Status      : {_status_label(score)}")
        print(f"  Timestamp   : {time.strftime('%H:%M:%S')}")
        print()
        print(f"  {Fore.CYAN}Press Ctrl+C to exit.{Style.RESET_ALL}")

        try:
            time.sleep(refresh_interval)
        except KeyboardInterrupt:
            break

    clear_terminal()
    print(f"{Fore.GREEN}Dashboard stopped.{Style.RESET_ALL}")


if __name__ == "__main__":
    run_dashboard()
