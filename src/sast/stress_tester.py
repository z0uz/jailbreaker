"""
Pipeline Stress Tester module.
Evaluates finding persistence across input data augmentations.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..utils.data_augmentation import InputAugmenter
from .llm_verifier import LLMVerifier
from .sast_runner import SASTRunner

logger = logging.getLogger(__name__)

class PipelineStressTester:
    """Stress tests SAST findings and LLM verifier robustness using data augmentation."""
    
    def __init__(self, verifier: LLMVerifier, runner: SASTRunner):
        self.verifier = verifier
        self.runner = runner

    async def evaluate_stress_test(self, finding: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """
        Runs data augmentation on target file content and verifies if finding persists across variants.
        """
        path = Path(file_path)
        if not path.exists():
            return {"persistence_rate": 0.0, "variants_tested": 0, "variant_results": {}}
            
        original_content = path.read_text(encoding="utf-8")
        variants = InputAugmenter.apply_augmentations(original_content)
        
        variant_results = {}
        persisted_count = 0
        
        for variant_name, augmented_content in variants.items():
            try:
                verification = await self.verifier.verify_finding(finding, augmented_content)
                is_tp = verification.get("is_true_positive", False)
                variant_results[variant_name] = {
                    "is_true_positive": is_tp,
                    "confidence": verification.get("confidence", "LOW")
                }
                if is_tp:
                    persisted_count += 1
            except Exception as e:
                logger.error(f"Error during stress test variant {variant_name}: {e}")
                variant_results[variant_name] = {"is_true_positive": False, "error": str(e)}

        total_variants = len(variants)
        persistence_rate = (persisted_count / total_variants) if total_variants > 0 else 0.0
        
        return {
            "finding_id": finding.get("check_id"),
            "file_path": file_path,
            "persistence_rate": round(persistence_rate, 2),
            "variants_tested": total_variants,
            "variants_persisted": persisted_count,
            "variant_results": variant_results
        }
