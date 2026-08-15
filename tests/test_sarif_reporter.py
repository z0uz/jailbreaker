"""
Unit test for standalone SARIF report generator function.
"""

import json
import unittest
from src.sast.sarif_exporter import generate_sarif_report

class TestSARIFReporter(unittest.TestCase):

    def test_generate_sarif_report(self):
        sample_findings = [
            {
                "rule_id": "CWE-89",
                "title": "SQL Injection",
                "description": "Unsanitized input passed directly to database query execution.",
                "severity": "error",
                "message": "Potential SQL injection vulnerability in query string.",
                "file_path": "src/database/db.py",
                "line_number": 42
            }
        ]

        report_json = generate_sarif_report(sample_findings, tool_name="TestScanner")
        data = json.loads(report_json)

        self.assertEqual(data["version"], "2.1.0")
        self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "TestScanner")
        self.assertEqual(len(data["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(data["runs"][0]["tool"]["driver"]["rules"][0]["id"], "CWE-89")
        self.assertEqual(len(data["runs"][0]["results"]), 1)
        self.assertEqual(data["runs"][0]["results"][0]["ruleId"], "CWE-89")
        self.assertEqual(data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/database/db.py")

if __name__ == '__main__':
    unittest.main()
