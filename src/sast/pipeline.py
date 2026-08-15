"""
SAST + LLM Hybrid Pipeline Orchestrator.
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from .sast_runner import SASTRunner
from .llm_verifier import LLMVerifier
from .sarif_exporter import SARIFExporter
from .stress_tester import PipelineStressTester
from ..models.base_model import BaseModel

logger = logging.getLogger(__name__)

class HybridSASTPipeline:
    """Orchestrates SAST candidate retrieval -> LLM Verification -> Stress Testing -> SARIF Report Generation."""
    
    def __init__(self, model: BaseModel, semgrep_config: str = "auto", confidence_threshold: str = "MEDIUM"):
        self.runner = SASTRunner(semgrep_config=semgrep_config)
        self.verifier = LLMVerifier(model=model, confidence_threshold=confidence_threshold)
        self.stress_tester = PipelineStressTester(verifier=self.verifier, runner=self.runner)
        self.exporter = SARIFExporter()
        
    async def run_pipeline(
        self,
        target_path: str,
        output_path: Optional[str] = None,
        output_format: str = "sarif",
        enable_stress_test: bool = False
    ) -> Dict[str, Any]:
        """Execute full hybrid scan pipeline on a file or folder."""
        logger.info(f"Step 1: Running SAST candidate scan on {target_path}...")
        candidates = self.runner.scan_target(target_path)
        logger.info(f"Found {len(candidates)} candidate findings.")
        
        verified_findings = []
        stress_test_results = []
        
        logger.info("Step 2: Verifying candidates using LLM security judge...")
        for candidate in candidates:
            file_p = Path(candidate["path"])
            if not file_p.exists():
                continue
                
            try:
                content = file_p.read_text(encoding="utf-8")
                verification = await self.verifier.verify_finding(candidate, content)
                
                if verification.get("is_true_positive"):
                    logger.info(f"Confirmed True Positive: {candidate['check_id']} in {candidate['path']}:L{candidate['start_line']}")
                    
                    if enable_stress_test:
                        logger.info(f"Running data augmentation stress test on finding {candidate['check_id']}...")
                        st_res = await self.stress_tester.evaluate_stress_test(candidate, str(file_p))
                        verification["stress_test"] = st_res
                        stress_test_results.append(st_res)
                        
                    verified_findings.append(verification)
                else:
                    logger.info(f"Filtered False Positive: {candidate['check_id']} in {candidate['path']}")
            except Exception as e:
                logger.error(f"Error reading/verifying {candidate['path']}: {e}")
                
        summary = {
            "target": target_path,
            "candidates_found": len(candidates),
            "verified_true_positives": len(verified_findings),
            "stress_testing_enabled": enable_stress_test,
            "findings": verified_findings
        }

        
        if output_path:
            if output_format.lower() == "sarif":
                self.exporter.export_sarif_file(verified_findings, output_path)
                logger.info(f"SARIF report exported to {output_path}")
            else:
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(summary, f, indent=2)
                logger.info(f"JSON report exported to {output_path}")
                
        return summary
