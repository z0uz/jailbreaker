"""
Unit tests for advanced defensive security modules.
"""

import pytest
from pathlib import Path

from src.sast.sca_scanner import SCAScanner
from src.sast.taint_analyzer import InterproceduralTaintAnalyzer
from src.sast.log_tailer import MITRELogMonitor
from src.evaluation.output_safety import LLMOutputSafetyEvaluator

def test_sca_requirement_parser():
    scanner = SCAScanner()
    pkg, ver = scanner._parse_requirement_line("requests==2.25.1; python_version >= '3.6'")
    assert pkg == "requests"
    assert ver == "2.25.1"

def test_taint_analyzer(tmp_path):
    # Create test Python file with dataflow: input() -> eval()
    test_file = tmp_path / "vulnerable_app.py"
    test_file.write_text("""
def handle_request():
    user_data = input("Enter payload: ")
    eval(user_data)
""")

    analyzer = InterproceduralTaintAnalyzer(str(test_file))
    findings = analyzer.analyze()

    assert len(findings) >= 1
    assert findings[0]["check_id"] == "taint.interprocedural.eval"
    assert findings[0]["cwe_id"] == "CWE-95"

def test_mitre_log_monitor(tmp_path):
    log_file = tmp_path / "auth_audit.log"
    log_file.write_text("""
2026-08-15 10:00:00 [ERROR] Authentication failure: failed password for invalid user admin
2026-08-15 10:01:00 [INFO] User executed command: /bin/sh -c 'whoami'
""")

    monitor = MITRELogMonitor(str(log_file))
    findings = monitor.analyze_log_file(str(log_file))

    assert len(findings) >= 2
    technique_ids = [f["technique_id"] for f in findings]
    assert "T1110" in technique_ids  # Brute force
    assert "T1059" in technique_ids  # Command execution

def test_output_safety_evaluator():
    evaluator = LLMOutputSafetyEvaluator()

    # Test hazardous XSS output detection
    res = evaluator.evaluate_output_safety("Here is the script: <script>alert(1)</script>")
    assert res["is_safe"] is False
    assert len(res["findings"]) >= 1
    assert res["findings"][0]["cwe_id"] == "CWE-79"

    # Test safe output
    res_safe = evaluator.evaluate_output_safety("Here is a clean response explaining Python syntax.")
    assert res_safe["is_safe"] is True

def test_tool_call_safety_evaluator():
    evaluator = LLMOutputSafetyEvaluator()

    # Test path traversal in tool arguments
    tool_res = evaluator.evaluate_tool_call_safety(
        tool_name="read_file",
        tool_args={"path": "../../../etc/passwd"}
    )
    assert tool_res["is_safe"] is False
    assert tool_res["findings"][0]["cwe_id"] == "CWE-22"
