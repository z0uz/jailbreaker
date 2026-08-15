# MITRE ATT&CK Threat Log Monitor

The MITRE Log Monitor parses system logs and correlates security anomalies against standard MITRE ATT&CK Technique IDs.

---

## Mapped Techniques

- `T1110` (Brute Force): Authentication failures and login brute-force attempts.
- `T1059` (Command and Scripting Interpreter): Unsanitized shell script executions.
- `T1078` (Valid Accounts): Administrative session escalations.
- `T1190` (Exploit Public-Facing Application): SQLi, XSS, and Path Traversal URI payloads.
- `T1552` (Unsecured Credentials): Plaintext credential or API key exposures in log files.

---

## Execution

Run log audit via `run_objective.py`:
```bash
python3 run_objective.py --objective "audit logs with mitre" --log-file sample.log
```
