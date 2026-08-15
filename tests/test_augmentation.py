"""
Unit tests for Data Augmentation and Pipeline Stress Testing.
"""

import json
import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from pathlib import Path
import tempfile

from src.utils.data_augmentation import InputAugmenter
from src.sast.stress_tester import PipelineStressTester
from src.sast.llm_verifier import LLMVerifier
from src.sast.sast_runner import SASTRunner

class TestDataAugmentation(unittest.TestCase):

    def test_input_augmenter_transformations(self):
        text = "def test_func():\n    x = 1\n"
        variants = InputAugmenter.apply_augmentations(text)

        self.assertIn("original", variants)
        self.assertIn("unicode_nfd", variants)
        self.assertIn("whitespace_shift", variants)
        self.assertIn("zero_width_noise", variants)
        self.assertIn("html_encode", variants)

        # Verify whitespace shift converted 4 spaces to tab
        self.assertIn("\tx = 1", variants["whitespace_shift"])


    def test_stress_tester(self):
        async def run_test():
            mock_verifier = MagicMock()
            mock_verifier.verify_finding = AsyncMock(return_value={
                "is_true_positive": True,
                "confidence": "HIGH"
            })
            mock_runner = MagicMock()

            stress_tester = PipelineStressTester(verifier=mock_verifier, runner=mock_runner)

            with tempfile.TemporaryDirectory() as tmp_dir:
                file_p = Path(tmp_dir) / "sample.py"
                file_p.write_text("eval('1+1')", encoding="utf-8")

                finding = {
                    "check_id": "eval-check",
                    "start_line": 1,
                    "end_line": 1,
                    "message": "eval check"
                }

                result = await stress_tester.evaluate_stress_test(finding, str(file_p))

                self.assertEqual(result["finding_id"], "eval-check")
                self.assertEqual(result["persistence_rate"], 1.0)
                self.assertGreater(result["variants_tested"], 1)

        asyncio.run(run_test())

if __name__ == '__main__':
    unittest.main()
