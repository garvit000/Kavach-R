"""Kavach-R — Demo orchestrator.

Simulates the full attack ➜ detection ➜ alert pipeline:
1. Starts the live dashboard in a background thread.
2. Waits a few seconds so the user can watch the "safe" state.
3. Launches the simulator as a subprocess to mimic an attack.
4. Ramps the risk score up to simulate detection.
5. Fires alerts when the threshold is crossed.
"""

import os
import random
import subprocess
import sys
import threading
import time

from alerts import show_alert, show_process_suspended, show_safe_message
from utils import clear_terminal, safe_sleep, timestamp

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SIMULATOR_PATH = os.path.join(SCRIPT_DIR, "simulator.py")
TEST_FOLDER = os.path.join(SCRIPT_DIR, "test_folder")

THRESHOLD = 0.8
DEMO_DURATION = 20

_current_risk: float = 0.0
_lock = threading.Lock()
_demo_running = True


def _get_risk() -> float:
    with _lock:
        return _current_risk


def _set_risk(value: float) -> None:
    global _current_risk
    with _lock:
        _current_risk = round(min(max(value, 0.0), 1.0), 4)


def _run_dashboard_thread() -> None:
    from dashboard import run_dashboard
    run_dashboard(get_risk_score=_get_risk, refresh_interval=1.0)


def _ensure_test_files() -> None:
    """Create dummy files in test_folder if none exist."""
    os.makedirs(TEST_FOLDER, exist_ok=True)
    existing = [f for f in os.listdir(TEST_FOLDER) if not f.endswith(".locked")]
    if existing:
        return
    for name in ["document.txt", "photo.jpg", "spreadsheet.xlsx", "presentation.pptx", "notes.md"]:
        with open(os.path.join(TEST_FOLDER, name), "w") as fh:
            fh.write(f"Sample content for {name}\n")
    print(f"[DEMO] [{timestamp()}] Created dummy files in test_folder/")


def run_demo() -> None:
    """Run the full Kavach-R demonstration."""
    global _demo_running

    clear_terminal()
    print("=" * 56)
    print("  KAVACH-R  —  Behaviour-Based Ransomware Early Warning")
    print("  Demo Mode")
    print("=" * 56)
    print()

    _ensure_test_files()

    # Phase 1 — calm state
    print(f"[DEMO] [{timestamp()}] System is monitoring … risk is LOW")
    show_safe_message()
    safe_sleep(3)

    # Phase 2 — start dashboard in background thread
    print(f"[DEMO] [{timestamp()}] Starting live dashboard …")
    dash_thread = threading.Thread(target=_run_dashboard_thread, daemon=True)
    dash_thread.start()
    safe_sleep(5)

    # Phase 3 — launch simulator subprocess
    print(f"[DEMO] [{timestamp()}] Launching ransomware simulator …")
    sim_proc = subprocess.Popen(
        [sys.executable, SIMULATOR_PATH, TEST_FOLDER],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Phase 4 — ramp up risk score over ~8 seconds to simulate detection
    print(f"[DEMO] [{timestamp()}] Detection engine analysing behaviour …")
    ramp_steps = 16
    for i in range(1, ramp_steps + 1):
        noise = random.uniform(-0.03, 0.05)
        new_score = (i / ramp_steps) + noise
        _set_risk(new_score)

        risk = _get_risk()
        if risk >= THRESHOLD:
            show_alert(risk)
            show_process_suspended(sim_proc.pid)
            break

        safe_sleep(0.5)

    # Collect simulator output
    sim_out, _ = sim_proc.communicate(timeout=10)
    print()
    print("-" * 56)
    print("  Simulator Output")
    print("-" * 56)
    print(sim_out)

    # Phase 5 — cool-down
    print(f"[DEMO] [{timestamp()}] Threat neutralised. Returning to safe state.")
    _set_risk(0.0)
    safe_sleep(2)
    show_safe_message()

    _demo_running = False
    print("=" * 56)
    print("  Demo complete.")
    print("=" * 56)


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n[DEMO] Interrupted.")
