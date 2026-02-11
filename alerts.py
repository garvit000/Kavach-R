"""Kavach-R — Alert display module.

Provides clear, colour-free ASCII alerts for risk events, process
suspension, and safe-state notifications.
"""


def _banner(char: str = "=", width: int = 56) -> str:
    return char * width


def show_alert(risk_score: float) -> None:
    """Display a risk alert with the given score (0–1)."""
    level = "CRITICAL" if risk_score >= 0.9 else "HIGH" if risk_score >= 0.8 else "WARNING"
    print()
    print(_banner("!"))
    print(f"  [!] KAVACH-R ALERT  -  Threat Level: {level}")
    print(f"  Risk Score : {risk_score:.4f}")
    print(f"  Action     : Immediate investigation recommended")
    print(_banner("!"))
    print()


def show_process_suspended(pid: int) -> None:
    """Display a process-suspension notice."""
    print()
    print(_banner("-"))
    print(f"  [X] Process Suspended - PID {pid}")
    print(f"  Kavach-R has flagged this process as potentially malicious.")
    print(_banner("-"))
    print()


def show_safe_message() -> None:
    """Display a safe / all-clear notice."""
    print()
    print(_banner("="))
    print("  [OK] System Status: SAFE")
    print("  No ransomware activity detected.")
    print(_banner("="))
    print()


if __name__ == "__main__":
    print("--- Alert Demo ---")
    show_alert(0.92)
    show_process_suspended(12345)
    show_safe_message()
