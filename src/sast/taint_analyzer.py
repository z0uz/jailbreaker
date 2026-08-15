"""
Interprocedural AST Taint & Control-Flow Analyzer.
Performs multi-file static analysis to trace untrusted user input sources
across function invocations and module boundaries down to vulnerable sinks.
"""

import ast
import logging
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple

logger = logging.getLogger(__name__)

# Known untrusted input sources
DEFAULT_TAINT_SOURCES = {
    "request.args", "request.form", "request.json", "request.values",
    "request.data", "request.GET", "request.POST", "sys.argv",
    "input", "os.environ"
}

# Known security sinks
DEFAULT_TAINT_SINKS = {
    "eval": ("CWE-95", "Code Injection", "ERROR"),
    "exec": ("CWE-95", "Code Injection", "ERROR"),
    "os.system": ("CWE-78", "Command Injection", "ERROR"),
    "subprocess.Popen": ("CWE-78", "Command Injection", "ERROR"),
    "subprocess.run": ("CWE-78", "Command Injection", "ERROR"),
    "subprocess.call": ("CWE-78", "Command Injection", "ERROR"),
    "sqlite3.connect": ("CWE-89", "SQL Injection", "WARNING"),
    "cursor.execute": ("CWE-89", "SQL Injection", "ERROR"),
    "pickle.loads": ("CWE-502", "Insecure Deserialization", "ERROR"),
    "open": ("CWE-22", "Path Traversal", "WARNING")
}

class InterproceduralTaintAnalyzer:
    """Multi-file AST Taint and Dataflow Analyzer."""

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.function_definitions: Dict[str, ast.FunctionDef] = {}
        self.tainted_variables: Set[str] = set()

    def analyze(self) -> List[Dict[str, Any]]:
        """Run interprocedural taint analysis across target directory."""
        findings = []
        files = [self.target_path] if self.target_path.is_file() else list(self.target_path.glob("**/*.py"))

        # Step 1: Build Function Definition Registry across all files
        for file_p in files:
            if file_p.name.startswith('.'):
                continue
            self._index_file_functions(file_p)

        # Step 2: Trace Taint Dataflow from Sources to Sinks
        for file_p in files:
            if file_p.name.startswith('.'):
                continue
            findings.extend(self._analyze_file_taint(file_p))

        return findings

    def _index_file_functions(self, file_path: Path):
        """Parse AST and store function signatures in global registry."""
        try:
            content = file_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_key = f"{file_path.stem}.{node.name}"
                    self.function_definitions[func_key] = node
                    self.function_definitions[node.name] = node
        except Exception as e:
            logger.debug(f"Failed to index functions in {file_path}: {e}")

    def _analyze_file_taint(self, file_path: Path) -> List[Dict[str, Any]]:
        """Analyze individual file for source-to-sink taint flows."""
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file_path))

            # Track variable assignments
            for node in ast.walk(tree):
                # Trace Assign: var = input_source
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            var_name = target.id
                            if self._is_node_tainted(node.value):
                                self.tainted_variables.add(var_name)

                # Trace Sinks: func(tainted_var)
                elif isinstance(node, ast.Call):
                    func_name = self._get_call_name(node.func)
                    if func_name in DEFAULT_TAINT_SINKS:
                        # Check if any argument is tainted
                        for arg in node.args:
                            if self._is_node_tainted(arg):
                                cwe, title, severity = DEFAULT_TAINT_SINKS[func_name]
                                findings.append({
                                    "check_id": f"taint.interprocedural.{func_name.replace('.', '-')}",
                                    "cwe_id": cwe,
                                    "file_path": str(file_path),
                                    "start_line": node.lineno,
                                    "end_line": getattr(node, 'end_lineno', node.lineno),
                                    "severity": severity,
                                    "message": f"Untrusted input flows into dangerous sink '{func_name}' ({title}).",
                                    "explanation": f"Variable dataflow analysis identified untrusted input passed directly into sink '{func_name}' at line {node.lineno}.",
                                    "remediation_patch": f"# Sanitize or validate input before passing to {func_name}()"
                                })
        except Exception as e:
            logger.debug(f"Error during taint scan of {file_path}: {e}")

        return findings

    def _is_node_tainted(self, node: ast.AST) -> bool:
        """Recursively check if an AST node contains a tainted variable or source."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables or node.id in DEFAULT_TAINT_SOURCES
        elif isinstance(node, ast.Attribute):
            full_attr = f"{getattr(node.value, 'id', '')}.{node.attr}"
            return full_attr in DEFAULT_TAINT_SOURCES or node.attr in self.tainted_variables
        elif isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name in DEFAULT_TAINT_SOURCES:
                return True
            # Interprocedural check: if calling an indexed function, check its return node
            if func_name in self.function_definitions:
                target_func = self.function_definitions[func_name]
                for body_node in ast.walk(target_func):
                    if isinstance(body_node, ast.Return) and body_node.value:
                        if self._is_node_tainted(body_node.value):
                            return True
        elif isinstance(node, ast.BinOp):
            return self._is_node_tainted(node.left) or self._is_node_tainted(node.right)
        elif isinstance(node, ast.JoinedStr):  # f-strings
            return any(self._is_node_tainted(value) for value in node.values if isinstance(value, ast.FormattedValue))
        return False

    def _get_call_name(self, node: ast.AST) -> str:
        """Extract full string identifier from Call func AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val_name = self._get_call_name(node.value)
            return f"{val_name}.{node.attr}" if val_name else node.attr
        return ""
