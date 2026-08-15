"""
CLI entry point for Hybrid SAST + LLM Vulnerability Scanner.
"""

import sys
import argparse
import asyncio
import yaml
import logging
from pathlib import Path

from src.models.openai_model import OpenAIModel
from src.models.ollama_model import OllamaModel
from src.sast.pipeline import HybridSASTPipeline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sast_scan")

def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if path.exists():
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    return {}

async def main():
    parser = argparse.ArgumentParser(description="Hybrid SAST + LLM Vulnerability Detection Scanner")
    parser.add_argument("--target", "-t", required=True, help="Target file or directory path to scan")
    parser.add_argument("--output", "-o", default="sast_report.sarif", help="Output report file path")
    parser.add_argument("--format", "-f", choices=["sarif", "json"], default="sarif", help="Output report format")
    parser.add_argument("--model", "-m", choices=["openai", "ollama", "groq"], default="openai", help="LLM verifier model choice")
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file path")
    parser.add_argument("--stress-test", action="store_true", help="Enable data augmentation stress testing on findings")

    args = parser.parse_args()

    config = load_config(args.config)
    
    # Setup LLM model
    if args.model == "openai":
        model_config = config.get("models", {}).get("openai", {"model": "gpt-3.5-turbo"})
        model = OpenAIModel(model_config)
    elif args.model == "groq":
        model_config = config.get("models", {}).get("groq", {"model": "llama-3.1-8b-instant"})
        model = OpenAIModel(model_config)
    else:
        model_config = config.get("models", {}).get("ollama", {"model": "deepseek-coder"})
        model = OllamaModel(model_config)

    pipeline = HybridSASTPipeline(
        model=model,
        semgrep_config=config.get("sast", {}).get("semgrep", {}).get("config", "auto"),
        confidence_threshold=config.get("sast", {}).get("verifier", {}).get("confidence_threshold", "MEDIUM")
    )

    logger.info(f"Starting Hybrid SAST scan on target: {args.target}")
    summary = await pipeline.run_pipeline(
        target_path=args.target,
        output_path=args.output,
        output_format=args.format,
        enable_stress_test=args.stress_test
    )


    print("\n=== Scan Summary ===")
    print(f"Target: {summary['target']}")
    print(f"Candidates Found: {summary['candidates_found']}")
    print(f"Verified True Positives: {summary['verified_true_positives']}")
    print(f"Report exported to: {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
