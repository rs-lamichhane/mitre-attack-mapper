# MITRE ATT&CK Mapping Engine

A heuristic inference engine designed to map raw Linux system audit logs (`/var/log/auth.log`, `syslog`) directly to the **MITRE ATT&CK Framework**. 

## Project Context
This tool was developed as an exploratory foundation for building autonomous Threat-Informed Defence capabilities. By structuring unstructured log data into recognized Tactics and Techniques, SOC analysts can move from reactive alert triage to proactive behavioral analysis.

## Core Capabilities
* **Heuristic Signatures:** Uses regex pattern matching against known adversarial footprints (e.g., Reverse Shells, Cron Job manipulation, SSH Brute Forcing).
* **Automated Tagging:** Enriches log data with exact Technique IDs (e.g., `T1110`, `T1053`) and overarching Tactics (e.g., `Credential Access`, `Execution`).

## Usage
```bash
python3 src/mapper.py
```
