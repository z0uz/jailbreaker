# Software Composition Analysis (SCA)

The SCA Scanner identifies security vulnerabilities in third-party dependencies.

---

## Capabilities

- Scans `requirements.txt` (Python) and `package.json` (Node.js) manifests.
- Queries the **OSV (Open Source Vulnerabilities)** API in real-time.
- Reports CVE identifier, vulnerable version, CWE classification, and recommended upgrade version.

---

## Execution

Run SCA scan via `run_objective.py`:
```bash
python3 run_objective.py --objective "scan dependencies" --target .
```
