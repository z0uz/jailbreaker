"""
Unit tests for SAST + LLM Hybrid Vulnerability Scanner.
"""

import json
import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path
import tempfile

from src.sast.sast_runner import SASTRunner
from src.sast.llm_verifier import LLMVerifier
from src.sast.sarif_exporter import SARIFExporter
from src.sast.pipeline import HybridSASTPipeline

class TestSASTPipeline(unittest.TestCase):

    def setUp(self):
        self.mock_model = MagicMock()
        self.mock_model.generate_response = AsyncMock(return_value={
            "content": json.dumps({
                "is_true_positive": True,
                "cwe_id": "CWE-95",
                "confidence": "HIGH",
                "explanation": "Dangerous use of eval() function found.",
                "remediation_patch": "# Replace eval with ast.literal_eval"
            })
        })

    def test_sast_runner_ast(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vulnerable_file = Path(tmp_dir) / "vulnerable.py"
            vulnerable_file.write_text("x = eval('1 + 1')\n", encoding="utf-8")

            runner = SASTRunner(use_ast_fallback=True)
            findings = runner._run_ast_scan(str(vulnerable_file))

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["check_id"], "python.lang.security.audit.eval-exec-use")
            self.assertEqual(findings[0]["start_line"], 1)

    def test_llm_verifier(self):
        async def run_test():
            verifier = LLMVerifier(model=self.mock_model)
            finding = {
                "check_id": "eval-use",
                "path": "test.py",
                "start_line": 1,
                "end_line": 1,
                "message": "eval detected"
            }
            file_content = "eval('2 + 2')"

            result = await verifier.verify_finding(finding, file_content)

            self.assertTrue(result["is_true_positive"])
            self.assertEqual(result["cwe_id"], "CWE-95")
            self.assertEqual(result["confidence"], "HIGH")
            self.assertIn("eval()", result["explanation"])

        asyncio.run(run_test())

    def test_sarif_exporter(self):
        exporter = SARIFExporter()
        findings = [{
            "check_id": "eval-use",
            "cwe_id": "CWE-95",
            "file_path": "vulnerable.py",
            "start_line": 1,
            "end_line": 1,
            "message": "Unsafe eval",
            "confidence": "HIGH",
            "explanation": "eval is dangerous",
            "remediation_patch": "ast.literal_eval"
        }]

        sarif = exporter.generate_sarif(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "eval-use")

    def test_pipeline(self):
        async def run_test():
            with tempfile.TemporaryDirectory() as tmp_dir:
                vulnerable_file = Path(tmp_dir) / "app.py"
                vulnerable_file.write_text("import subprocess\nsubprocess.run('ls', shell=True)\n", encoding="utf-8")
                sarif_output = Path(tmp_dir) / "out.sarif"

                pipeline = HybridSASTPipeline(model=self.mock_model)
                summary = await pipeline.run_pipeline(
                    target_path=str(vulnerable_file),
                    output_path=str(sarif_output),
                    output_format="sarif"
                )

                self.assertGreaterEqual(summary["candidates_found"], 1)
                self.assertEqual(summary["verified_true_positives"], summary["candidates_found"])
                self.assertTrue(sarif_output.exists())

        asyncio.run(run_test())

if __name__ == '__main__':
    unittest.main()

