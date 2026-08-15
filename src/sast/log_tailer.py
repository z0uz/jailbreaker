"""
Live Log Stream Monitor & MITRE ATT&CK Threat Mapper.
Parses and monitors log files for real-time security events, mapping anomalies
to standardized MITRE ATT&CK Technique IDs (e.g. T1059, T1110, T1078).
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# MITRE ATT&CK Ruleset Definitions
MITRE_ATTACK_RULES = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactics": ["Credential Access"],
        "pattern": r"(failed password|authentication failure|invalid user|login failed|unauthorized access attempt)",
        "severity": "WARNING",
        "cwe_id": "CWE-307",
        "description": "Repeated authentication failures detected. Potential brute force attack."
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactics": ["Execution"],
        "pattern": r"(cmd\.exe|/bin/sh|/bin/bash|python -c|exec\(|eval\(|os\.system|subprocess)",
        "severity": "ERROR",
        "cwe_id": "CWE-78",
        "description": "Suspicious shell command execution attempt detected in log trace."
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactics": ["Defense Evasion", "Persistence"],
        "pattern": r"(sudo:\s+session opened|root login|elevated privilege|su:\s+auth)",
        "severity": "INFO",
        "cwe_id": "CWE-250",
        "description": "Privileged session or administrative account escalation logged."
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"],
        "pattern": r"(SELECT.*FROM|UNION.*SELECT|<script>|onload=|/etc/passwd|\.\./\.\./)",
        "severity": "ERROR",
        "cwe_id": "CWE-89",
        "description": "Web vulnerability payload (SQLi / XSS / Path Traversal) detected in request URI or log payload."
    },
    {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "tactics": ["Credential Access"],
        "pattern": r"(api_key=|secret_key=|password=|auth_token=|Bearer\s+gsk_|Bearer\s+sk-)",
        "severity": "ERROR",
        "cwe_id": "CWE-532",
        "description": "Plaintext credential or sensitive API key exposure detected in log output."
    }
]

class MITRELogMonitor:
    """Monitors system/application logs and correlates events with MITRE ATT&CK techniques."""

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path) if log_path else None

    def analyze_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze a target log file against MITRE ATT&CK threat patterns."""
        p = Path(file_path)
        if not p.exists():
            logger.error(f"Log file does not exist: {file_path}")
            return []

        findings = []
        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
            for line_no, line in enumerate(content.splitlines(), 1):
                if not line.strip():
                    continue

                for rule in MITRE_ATTACK_RULES:
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append({
                            "check_id": f"mitre.{rule['technique_id'].lower()}",
                            "technique_id": rule["technique_id"],
                            "technique_name": rule["technique_name"],
                            "tactics": rule["tactics"],
                            "cwe_id": rule["cwe_id"],
                            "file_path": str(p),
                            "start_line": line_no,
                            "end_line": line_no,
                            "severity": rule["severity"],
                            "message": f"[{rule['technique_id']} - {rule['technique_name']}] {rule['description']}",
                            "explanation": f"Log Line {line_no}: '{line.strip()}' matched threat pattern '{rule['pattern']}'.",
                            "raw_log": line.strip()
                        })
        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {e}")

        return findings
