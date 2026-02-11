#!/usr/bin/env python3
"""
simulator.py — Ransomware behaviour simulator for Kavach-R testing.

Creates a temporary directory and rapidly performs file operations that
mimic ransomware activity:
  • Mass file creation
  • Rapid modification with high-entropy (random) content
  • Renaming files with suspicious extension changes (.locked, .enc, .cry)
  • Rapid deletion

This is meant to be run **alongside** the detection pipeline to verify
that the detector correctly flags the anomalous burst of activity.

Usage
-----
    # Simulate an attack in a temp directory (watched by the monitor)
    python -m kavach.simulator --target-dir /tmp/kavach_test --duration 10

    # Or use the default (creates its own temp dir)
    python -m kavach.simulator
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import shutil
import tempfile
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("kavach.simulator")

# Suspicious extensions ransomware might append
_RANSOM_EXTENSIONS = [".locked", ".enc", ".cry", ".encrypted", ".pays", ".rnsmw"]


def simulate_attack(
    target_dir: str,
    num_files: int = 50,
    duration: float = 10.0,
) -> None:
    """Simulate ransomware-like file activity in *target_dir*.

    1. Create *num_files* text files with normal content.
    2. Rapidly modify each file with high-entropy (random bytes) content.
    3. Rename files with a suspicious extension appended.
    4. Optionally delete some files.

    The operations are spread across *duration* seconds so they overlap
    with the monitor's sliding window.

    Args:
        target_dir: Directory to perform operations in.
        num_files:  Number of victim files to create.
        duration:   Total time budget for the attack simulation.
    """
    os.makedirs(target_dir, exist_ok=True)
    logger.info("🎯 Starting simulated attack in: %s", target_dir)
    logger.info("   Files: %d  |  Duration: %.1f s", num_files, duration)

    # ---- Phase 1: Create victim files ----
    file_paths: list[str] = []
    for i in range(num_files):
        ext = random.choice([".txt", ".docx", ".pdf", ".xlsx", ".csv", ".py"])
        name = f"document_{i:03d}{ext}"
        path = os.path.join(target_dir, name)
        with open(path, "w") as f:
            f.write(f"This is a normal document #{i}.\n" * 20)
        file_paths.append(path)
    logger.info("Phase 1: Created %d files.", len(file_paths))

    # Small pause to let the monitor register the baseline
    time.sleep(1.0)

    # ---- Phase 2: Rapid encryption (overwrite with random bytes) ----
    delay = max(duration * 0.4 / num_files, 0.01)
    logger.info("Phase 2: Encrypting files (random bytes overwrite) …")
    for path in file_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "wb") as f:
                f.write(os.urandom(4096))  # High-entropy content
        except OSError:
            pass
        time.sleep(delay)

    # ---- Phase 3: Rename with ransomware extension ----
    renamed_paths: list[str] = []
    logger.info("Phase 3: Renaming files with suspicious extensions …")
    delay = max(duration * 0.3 / num_files, 0.01)
    for path in file_paths:
        if not os.path.exists(path):
            continue
        ext = random.choice(_RANSOM_EXTENSIONS)
        new_path = path + ext
        try:
            os.rename(path, new_path)
            renamed_paths.append(new_path)
        except OSError:
            renamed_paths.append(path)
        time.sleep(delay)

    # ---- Phase 4: Delete some files (optional cleanup) ----
    delete_count = num_files // 3
    logger.info("Phase 4: Deleting %d files …", delete_count)
    delay = max(duration * 0.1 / max(delete_count, 1), 0.01)
    for path in renamed_paths[:delete_count]:
        try:
            os.remove(path)
        except OSError:
            pass
        time.sleep(delay)

    # ---- Ransom note ----
    note_path = os.path.join(target_dir, "README_RANSOM.txt")
    with open(note_path, "w") as f:
        f.write(
            "YOUR FILES HAVE BEEN ENCRYPTED!\n"
            "This is a SIMULATION by Kavach-R.\n"
            "No real harm was done.\n"
        )

    logger.info("✅ Simulated attack complete. Ransom note at: %s", note_path)


def simulate_normal(
    target_dir: str,
    num_files: int = 20,
    duration: float = 30.0,
) -> None:
    """Simulate normal (benign) file activity for baseline training.

    Creates files slowly, modifies a few with low-entropy text, and does
    minimal renaming — mimicking a regular user workflow.

    Args:
        target_dir: Directory to perform operations in.
        num_files:  Number of files to create.
        duration:   Total time budget.
    """
    os.makedirs(target_dir, exist_ok=True)
    logger.info("📝 Starting normal activity simulation in: %s", target_dir)

    delay = duration / max(num_files * 2, 1)
    file_paths: list[str] = []

    for i in range(num_files):
        ext = random.choice([".txt", ".md", ".log"])
        name = f"note_{i:03d}{ext}"
        path = os.path.join(target_dir, name)

        # Create
        with open(path, "w") as f:
            f.write(f"Meeting notes for item {i}.\n")
        file_paths.append(path)
        time.sleep(delay)

        # Occasionally modify
        if random.random() < 0.3 and os.path.exists(path):
            with open(path, "a") as f:
                f.write("Added a follow-up note.\n")
            time.sleep(delay)

    logger.info("✅ Normal activity simulation complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="kavach-simulator",
        description="Simulate ransomware or normal file activity for testing.",
    )
    parser.add_argument(
        "mode",
        choices=["attack", "normal"],
        help="'attack' = ransomware-like burst; 'normal' = benign activity.",
    )
    parser.add_argument(
        "--target-dir",
        default=None,
        help="Directory to operate in (default: auto-created temp dir).",
    )
    parser.add_argument(
        "--num-files",
        type=int,
        default=50,
        help="Number of files to create (default: 50).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        help="Simulation duration in seconds (default: 10).",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove the target directory after simulation.",
    )

    args = parser.parse_args()

    target = args.target_dir or tempfile.mkdtemp(prefix="kavach_sim_")

    try:
        if args.mode == "attack":
            simulate_attack(target, args.num_files, args.duration)
        else:
            simulate_normal(target, args.num_files, args.duration)
    finally:
        if args.cleanup and os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)
            logger.info("Cleaned up: %s", target)
        else:
            logger.info("Files remain in: %s", target)


if __name__ == "__main__":
    main()
