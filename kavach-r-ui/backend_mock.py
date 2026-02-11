import random
import time
from datetime import datetime

class BackendMock:
    def __init__(self):
        self.scanning = False
        self.risk_score = 0.0
        self.logs = []
        self.scenario = "IDLE"  # IDLE, UNZIP, SOFTWARE_UPDATE, ATTACK
        self.current_metrics = {}

    def set_scenario(self, scenario_name):
        self.scenario = scenario_name
        self.add_log(f"Simulating Scenario: {scenario_name.replace('_', ' ')}")

    def start_scan(self):
        self.scanning = True
        self.add_log("Scan started by user. Behavioral monitoring active.")

    def stop_scan(self):
        self.scanning = False
        self.risk_score = 0.0
        self.add_log("Scan stopped.")

    def get_current_risk_score(self):
        if not self.scanning:
            return 0.0
        
        metrics = self.get_activity_metrics()
        
        # Corrected Logic for Accuracy & False Positive Reduction:
        # 1. Extension changes carry the most weight, BUT we filter for suspicious ones.
        # 2. Entropy is a secondary multiplier.
        # 3. High write activity (without extension change/entropy) is treated as Benign.
        
        # Base malicious indicators
        malicious_weight = 0.0
        
        # High Extension Change Rate (e.g. .locked, .crypto, .v3, random hex)
        # Note: In our mock, ext_change_rate is only high in the ATTACK scenario.
        malicious_weight += metrics["ext_change_rate"] * 0.7
        
        # High Entropy (Indicates encryption)
        normalized_entropy = min(1.0, metrics["entropy_change"] / 4.0)
        malicious_weight += normalized_entropy * 0.25
        
        # Activity Factor (CPU, Writes, Handles)
        # We only consider high activity as "malicious" if at least some extension changes are happening.
        activity_intensity = (metrics["files_modified_per_sec"] / 60.0) + (metrics["cpu_usage"] / 100.0)
        
        if metrics["ext_change_rate"] > 0.4:
            # High extension renaming + High activity = VERY LIKELY RANSOMWARE
            malicious_weight += (activity_intensity * 0.2)
        else:
            # HIGH ACTIVITY + LOW/ZERO EXT CHANGE = Likely Benign (Unzip, Update, Indexing)
            # We actually reduce the weight or keep it very low to prevent False Positives.
            malicious_weight += (activity_intensity * 0.02)

        self.risk_score = round(min(1.0, malicious_weight), 4)
        return self.risk_score

    def get_activity_metrics(self):
        if not self.scanning:
            return {
                "files_modified_per_sec": 0.0,
                "renames_per_sec": 0.0,
                "entropy_change": 0.0,
                "ext_change_rate": 0.0,
                "unique_files_per_min": 0,
                "mod_acc_ratio": 0.0,
                "cpu_usage": 0.0,
                "file_handles": 0
            }
        
        if self.scenario == "IDLE":
            res = {
                "files_modified_per_sec": round(random.uniform(0.1, 1.5), 2),
                "renames_per_sec": round(random.uniform(0.0, 0.2), 2),
                "entropy_change": round(random.uniform(0.0, 0.1), 3),
                "ext_change_rate": 0.0,
                "unique_files_per_min": random.randint(1, 5),
                "mod_acc_ratio": round(random.uniform(0.05, 0.15), 2),
                "cpu_usage": round(random.uniform(0.5, 3.0), 1),
                "file_handles": random.randint(10, 50)
            }
        elif self.scenario == "UNZIP":
            res = {
                "files_modified_per_sec": round(random.uniform(25.0, 55.0), 2),
                "renames_per_sec": round(random.uniform(8.0, 20.0), 2),
                "entropy_change": round(random.uniform(0.1, 0.3), 3),
                "ext_change_rate": 0.0,
                "unique_files_per_min": random.randint(150, 450),
                "mod_acc_ratio": 0.9,
                "cpu_usage": round(random.uniform(10.0, 25.0), 1),
                "file_handles": random.randint(50, 150)
            }
        elif self.scenario == "SOFTWARE_UPDATE":
            # Very high activity, high CPU, renames happening, but NO extension randomization
            res = {
                "files_modified_per_sec": round(random.uniform(30.0, 80.0), 2),
                "renames_per_sec": round(random.uniform(15.0, 40.0), 2),
                "entropy_change": round(random.uniform(0.2, 0.6), 3),
                "ext_change_rate": 0.0, # Software updates rename to .tmp/.old, not random junk
                "unique_files_per_min": random.randint(300, 800),
                "mod_acc_ratio": 0.85,
                "cpu_usage": round(random.uniform(40.0, 85.0), 1),
                "file_handles": random.randint(400, 1200)
            }
        else: # ATTACK
            res = {
                "files_modified_per_sec": round(random.uniform(40.0, 100.0), 2),
                "renames_per_sec": round(random.uniform(20.0, 60.0), 2),
                "entropy_change": round(random.uniform(3.0, 5.5), 3),
                "ext_change_rate": round(random.uniform(0.75, 1.0), 2),
                "unique_files_per_min": random.randint(400, 1500),
                "mod_acc_ratio": 0.98,
                "cpu_usage": round(random.uniform(50.0, 98.0), 1),
                "file_handles": random.randint(800, 3000)
            }
        
        self.current_metrics = res
        return res

    def get_recent_logs(self):
        if self.scanning and random.random() > 0.6:
            if self.scenario == "UNZIP":
                files = ["install.pkg", "assets/", "data.bin", "config.xml"]
                actions = ["Inflating", "Writing", "Extracting"]
            elif self.scenario == "SOFTWARE_UPDATE":
                files = ["kernel32.dll.bak", "service.exe.tmp", "patch_v2.bin"]
                actions = ["Updating", "Patching", "Verified Integrity"]
            elif self.scenario == "ATTACK":
                files = ["keys.txt.locked", "wallet.dat.crypto", "backup.sql.v3"]
                actions = ["Encrypting", "Deleting...", "Overwrite"]
            else:
                files = ["system_idle", "network_monitor", "io_poll"]
                actions = ["Checking", "Monitoring"]
                
            msg = f"{random.choice(actions)}: {random.choice(files)}"
            self.add_log(msg)
        return self.logs[-50:]

    def add_log(self, message):
        ts = datetime.now().strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] {message}")

    def clear_logs(self):
        self.logs = []
        self.add_log("Logs cleared.")

backend = BackendMock()
