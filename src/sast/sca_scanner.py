"""
Software Composition Analysis (SCA) Scanner.
Scans project dependency manifests (e.g. requirements.txt, package.json)
for known CVE vulnerabilities using the Open Source Vulnerabilities (OSV) API.
"""

import os
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"

class SCAScanner:
    """Scans project dependency files for known security vulnerabilities (CVEs)."""

    def __init__(self, target_path: str = "."):
        self.target_path = Path(target_path)

    def scan_dependencies(self) -> List[Dict[str, Any]]:
        """Find and scan all dependency manifests in target path."""
        findings = []

        # 1. Python requirements.txt
        req_files = list(self.target_path.glob("**/requirements*.txt")) if self.target_path.is_dir() else ([self.target_path] if "requirements" in self.target_path.name else [])
        for req_file in req_files:
            findings.extend(self._scan_requirements_file(req_file))

        # 2. Node.js package.json / package-lock.json
        pkg_files = list(self.target_path.glob("**/package.json")) if self.target_path.is_dir() else ([self.target_path] if "package.json" in self.target_path.name else [])
        for pkg_file in pkg_files:
            findings.extend(self._scan_package_json(pkg_file))

        return findings

    def _scan_requirements_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse Python requirements.txt file and query OSV API."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            for line_no, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Parse package==version or package>=version
                pkg_name, version = self._parse_requirement_line(line)
                if pkg_name and version:
                    cves = self._query_osv("PyPI", pkg_name, version)
                    for cve in cves:
                        findings.append({
                            "check_id": f"sca.cve.{cve['id']}",
                            "cwe_id": cve.get("cwe", "CWE-937"),
                            "package": pkg_name,
                            "version": version,
                            "ecosystem": "PyPI",
                            "file_path": str(file_path),
                            "start_line": line_no,
                            "end_line": line_no,
                            "severity": cve.get("severity", "WARNING"),
                            "message": f"Vulnerable dependency '{pkg_name}=={version}': {cve['summary']}",
                            "explanation": cve.get("details", cve['summary']),
                            "remediation_patch": f"Upgrade {pkg_name} to version {cve.get('fixed_version', 'latest')}"
                        })
        except Exception as e:
            logger.error(f"Error reading requirement file {file_path}: {e}")

        return findings

    def _scan_package_json(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse Node.js package.json dependencies."""
        findings = []
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}

            for pkg_name, version_str in deps.items():
                clean_ver = version_str.strip("^~>=<")
                if clean_ver and clean_ver[0].isdigit():
                    cves = self._query_osv("npm", pkg_name, clean_ver)
                    for cve in cves:
                        findings.append({
                            "check_id": f"sca.cve.{cve['id']}",
                            "cwe_id": cve.get("cwe", "CWE-937"),
                            "package": pkg_name,
                            "version": clean_ver,
                            "ecosystem": "npm",
                            "file_path": str(file_path),
                            "start_line": 1,
                            "end_line": 1,
                            "severity": cve.get("severity", "WARNING"),
                            "message": f"Vulnerable dependency '{pkg_name}@{clean_ver}': {cve['summary']}",
                            "explanation": cve.get("details", cve['summary']),
                            "remediation_patch": f"Upgrade {pkg_name} to version {cve.get('fixed_version', 'latest')}"
                        })
        except Exception as e:
            logger.error(f"Error parsing package.json {file_path}: {e}")

        return findings

    def _parse_requirement_line(self, line: str) -> tuple[Optional[str], Optional[str]]:
        """Parse package name and pinned version from a requirement line."""
        for op in ("==", ">=", "~=", "<="):
            if op in line:
                parts = line.split(op)
                return parts[0].strip(), parts[1].split(";")[0].strip()
        return None, None

    def _query_osv(self, ecosystem: str, package_name: str, version: str) -> List[Dict[str, Any]]:
        """Query OSV API for vulnerabilities matching package and version."""
        payload = json.dumps({
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            },
            "version": version
        }).encode("utf-8")

        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"}
        )

        vulnerabilities = []
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    res_data = json.loads(response.read().decode("utf-8"))
                    vuln_list = res_data.get("vulns", [])

                    for v in vuln_list:
                        fixed_ver = "latest"
                        for affected in v.get("affected", []):
                            for ranges in affected.get("ranges", []):
                                for event in ranges.get("events", []):
                                    if "fixed" in event:
                                        fixed_ver = event["fixed"]

                        summary = v.get("summary", v.get("details", "Vulnerability detected"))
                        vulnerabilities.append({
                            "id": v.get("id", "CVE-Unknown"),
                            "summary": summary[:120],
                            "details": v.get("details", summary),
                            "severity": "ERROR" if "HIGH" in str(v.get("database_specific", {})) else "WARNING",
                            "fixed_version": fixed_ver,
                            "cwe": "CWE-937"
                        })
        except Exception as e:
            logger.debug(f"OSV API lookup skipped for {package_name}: {e}")

        return vulnerabilities
