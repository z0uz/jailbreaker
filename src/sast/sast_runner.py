"""
SAST Runner module for candidate vulnerability extraction.
Runs fast deterministic scanning using Semgrep (or Python AST fallback).
"""

import json
import ast
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class SASTRunner:
    """Deterministic SAST engine for isolating candidate security findings."""
    
    def __init__(self, semgrep_config: str = "auto", use_ast_fallback: bool = True):
        self.semgrep_config = semgrep_config
        self.use_ast_fallback = use_ast_fallback
    
    def scan_target(self, target_path: str) -> List[Dict[str, Any]]:
        """
        Scan target file or directory with Semgrep, falling back to AST rules if needed.
        """
        path = Path(target_path)
        if not path.exists():
            logger.error(f"Target path does not exist: {target_path}")
            return []
            
        results = self._run_semgrep(target_path)
        if results is not None:
            return results
            
        if self.use_ast_fallback and (path.suffix == '.py' or path.is_dir()):
            logger.info("Semgrep unvailable or failed. Falling back to AST scanning.")
            return self._run_ast_scan(target_path)
            
        return []

    def _run_semgrep(self, target_path: str) -> Optional[List[Dict[str, Any]]]:
        """Run semgrep command line scan."""
        try:
            cmd = ["semgrep", "scan"]
            
            # Support comma-separated configs or multiple configs
            if "," in self.semgrep_config:
                for cfg in self.semgrep_config.split(","):
                    cmd.append(f"--config={cfg.strip()}")
            else:
                cmd.append(f"--config={self.semgrep_config}")
            
            rules_dir = Path("rules")
            if rules_dir.exists() and rules_dir.is_dir():
                cmd.append(f"--config={rules_dir}")
                
            cmd.extend(["--json", target_path])
            
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if res.returncode in (0, 1) and res.stdout:
                try:
                    data = json.loads(res.stdout)
                    raw_results = data.get("results", [])
                    
                    standardized = []
                    for r in raw_results:
                        standardized.append({
                            "check_id": r.get("check_id", "semgrep-finding"),
                            "path": r.get("path", target_path),
                            "start_line": r.get("start", {}).get("line", 1),
                            "end_line": r.get("end", {}).get("line", 1),
                            "message": r.get("extra", {}).get("message", "Potential issue detected"),
                            "severity": r.get("extra", {}).get("severity", "WARNING"),
                            "raw_finding": r
                        })
                    return standardized
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"Semgrep execution failed: {e}")
            
        return None

    def _run_ast_scan(self, target_path: str) -> List[Dict[str, Any]]:
        """Enhanced AST pattern scanner for Python target files."""
        path = Path(target_path)
        files = [path] if path.is_file() else list(path.glob("**/*.py"))
        
        findings = []
        for file_p in files:
            if file_p.name.startswith('.'):
                continue
            try:
                content = file_p.read_text(encoding="utf-8")
                tree = ast.parse(content, filename=str(file_p))
                
                for node in ast.walk(tree):
                    # Rule 1: eval() / exec() usage
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        if node.func.id in ('eval', 'exec'):
                            findings.append({
                                "check_id": "python.lang.security.audit.eval-exec-use",
                                "path": str(file_p),
                                "start_line": node.lineno,
                                "end_line": getattr(node, 'end_lineno', node.lineno),
                                "message": f"Use of unsafe function '{node.func.id}' detected.",
                                "severity": "ERROR",
                                "raw_finding": {"func": node.func.id}
                            })
                        elif node.func.id == 'open':
                            # Check for un-sanitized file opens with variable path
                            if node.args and not isinstance(node.args[0], ast.Constant):
                                findings.append({
                                    "check_id": "python.lang.security.audit.dynamic-file-open",
                                    "path": str(file_p),
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, 'end_lineno', node.lineno),
                                    "message": "Dynamic file open detected. Potential path traversal vulnerability.",
                                    "severity": "WARNING",
                                    "raw_finding": {"func": "open"}
                                })

                    # Rule 2: Attribute calls (subprocess, os.system, hashlib, deserialization)
                    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        func_attr = node.func.attr
                        
                        # Subprocess shell=True
                        if func_attr in ('run', 'Popen', 'call', 'check_output'):
                            for kw in node.keywords:
                                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    findings.append({
                                        "check_id": "python.lang.security.audit.subprocess-shell-true",
                                        "path": str(file_p),
                                        "start_line": node.lineno,
                                        "end_line": getattr(node, 'end_lineno', node.lineno),
                                        "message": "Subprocess call with shell=True detected.",
                                        "severity": "WARNING",
                                        "raw_finding": {"attr": func_attr}
                                    })
                        # os.system
                        elif func_attr == 'system' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                            findings.append({
                                "check_id": "python.lang.security.audit.os-system-use",
                                "path": str(file_p),
                                "start_line": node.lineno,
                                "end_line": getattr(node, 'end_lineno', node.lineno),
                                "message": "Use of os.system detected; consider subprocess without shell.",
                                "severity": "WARNING",
                                "raw_finding": {"attr": "system"}
                            })
                        # Insecure deserialization (pickle.loads / yaml.unsafe_load / marshal.loads)
                        elif func_attr in ('loads', 'load', 'unsafe_load'):
                            val_name = getattr(node.func.value, 'id', '')
                            if val_name in ('pickle', 'marshal') or (val_name == 'yaml' and func_attr == 'unsafe_load'):
                                findings.append({
                                    "check_id": "python.lang.security.audit.insecure-deserialization",
                                    "path": str(file_p),
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, 'end_lineno', node.lineno),
                                    "message": f"Insecure deserialization via {val_name}.{func_attr} detected.",
                                    "severity": "ERROR",
                                    "raw_finding": {"module": val_name, "attr": func_attr}
                                })
                        # Weak hashes (hashlib.md5, hashlib.sha1)
                        elif func_attr in ('md5', 'sha1'):
                            val_name = getattr(node.func.value, 'id', '')
                            if val_name == 'hashlib':
                                findings.append({
                                    "check_id": "python.lang.security.audit.weak-hash",
                                    "path": str(file_p),
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, 'end_lineno', node.lineno),
                                    "message": f"Weak cryptographic hash algorithm hashlib.{func_attr} detected.",
                                    "severity": "WARNING",
                                    "raw_finding": {"attr": func_attr}
                                })

                    # Rule 3: Hardcoded secret assignment detection
                    elif isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                var_name = target.id.lower()
                                if any(s in var_name for s in ('api_key', 'secret_key', 'auth_token', 'private_key')):
                                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                        if len(node.value.value) > 4:
                                            findings.append({
                                                "check_id": "python.lang.security.audit.hardcoded-secret",
                                                "path": str(file_p),
                                                "start_line": node.lineno,
                                                "end_line": getattr(node, 'end_lineno', node.lineno),
                                                "message": f"Potential hardcoded secret assigned to variable '{target.id}'.",
                                                "severity": "ERROR",
                                                "raw_finding": {"variable": target.id}
                                            })
            except Exception as e:
                logger.debug(f"Failed to AST parse {file_p}: {e}")
                
        return findings

