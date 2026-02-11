"""Kavach-R — Safe ransomware behaviour simulator.

Iterates over files in test_folder/, overwrites contents with random data,
and renames each file with a .locked extension to mimic encryption behaviour.
No real encryption is performed.
"""

import os
import sys
import time

from utils import generate_random_data, timestamp

TEST_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_folder")


def simulate_encryption(target_dir: str = TEST_FOLDER, delay: float = 0.3) -> int:
    """Simulate ransomware encryption on every file in *target_dir*.

    Returns the number of files processed.
    """
    if not os.path.isdir(target_dir):
        print(f"[SIMULATOR] Target directory not found: {target_dir}")
        return 0

    files = [
        f for f in os.listdir(target_dir)
        if os.path.isfile(os.path.join(target_dir, f)) and not f.endswith(".locked")
    ]

    if not files:
        print("[SIMULATOR] No files to encrypt.")
        return 0

    print(f"[SIMULATOR] Found {len(files)} file(s) in {target_dir}")
    print("=" * 50)

    count = 0
    for filename in files:
        filepath = os.path.join(target_dir, filename)

        with open(filepath, "w") as fh:
            fh.write(generate_random_data(512))

        locked_path = filepath + ".locked"
        os.rename(filepath, locked_path)

        print(f"[SIMULATOR] [{timestamp()}] Encrypted {filename}")
        count += 1
        time.sleep(delay)

    print("=" * 50)
    print(f"[SIMULATOR] Finished — {count} file(s) encrypted.")
    return count


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else TEST_FOLDER
    simulate_encryption(target)
