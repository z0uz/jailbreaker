"""
CLI entrypoint to run security evaluation tasks using plain-text objective instructions.
"""

import argparse
import asyncio
import json
import yaml
import logging
from pathlib import Path

from src.sast.routines import default_router
from src.sast.sast_runner import SASTRunner
from src.sast.llm_verifier import LLMVerifier
from src.sast.sarif_exporter import SARIFExporter
from src.models.openai_model import OpenAIModel
from src.models.ollama_model import OllamaModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("run_objective")

def load_config(config_path: str = "config.yaml") -> dict:
    path = Path(config_path)
    if path.exists():
        with open(path, 'r') as f:
            return yaml.safe_load(f)
    return {}

async def main():
    parser = argparse.ArgumentParser(description="Instruction-conditioned objective runner")
    parser.add_argument("--objective", "-o", required=True, help="Plain text instruction/objective (e.g. 'run static scan and stress test')")
    parser.add_argument("--target", "-t", default=".", help="Target file or folder path")
    parser.add_argument("--target-url", "-u", help="Target API URL for DAST red teaming (e.g. http://localhost:8000/api/chat)")
    parser.add_argument("--log-file", "-l", help="Path to system or security logs for AI auditing")
    parser.add_argument("--model", "-m", choices=["openai", "ollama", "groq"], default="openai", help="Model verifier choice")
    parser.add_argument("--config", "-c", default="config.yaml", help="Configuration file path")
    parser.add_argument("--output", help="Save the findings to a standard SARIF file (e.g. results.sarif)")

    args = parser.parse_args()
    config = load_config(args.config)

    if args.model == "openai":
        model_config = config.get("models", {}).get("openai", {"model": "gpt-3.5-turbo"})
        model = OpenAIModel(model_config)
    elif args.model == "groq":
        model_config = config.get("models", {}).get("groq", {"model": "llama-3.1-8b-instant"})
        model = OpenAIModel(model_config)
    else:
        model_config = config.get("models", {}).get("ollama", {"model": "deepseek-coder"})
        model = OllamaModel(model_config)

    runner = SASTRunner()
    verifier = LLMVerifier(model=model)

    context = {
        "runner": runner,
        "verifier": verifier,
        "model_name": args.model,
        "log_file": args.log_file,
        "target_url": args.target_url
    }

    logger.info(f"Routing instruction: '{args.objective}' for target: '{args.target}'")
    execution_result = await default_router.execute_instruction(
        instruction=args.objective,
        target_path=args.target,
        context=context
    )

    print("\n=== Objective Execution Summary ===")
    print(f"Instruction: {execution_result['instruction']}")
    print(f"Routines Executed: {', '.join(execution_result['routines_executed'])}")
    print("\n=== Result Summary ===")
    print(json.dumps(execution_result['results'], indent=2))

    with open("run_summary.txt", "w", encoding="utf-8") as f:
        f.write("=== Objective Execution Summary ===\n")
        f.write(f"Instruction: {execution_result['instruction']}\n")
        f.write(f"Routines Executed: {', '.join(execution_result['routines_executed'])}\n")
        f.write("\n=== Result Summary ===\n")
        json.dump(execution_result['results'], f, indent=2)
    logger.info("Automatically saved execution log to run_summary.txt")

    if args.output:
        all_findings = []
        for routine_name, routine_data in execution_result['results'].items():
            if 'findings' in routine_data:
                all_findings.extend(routine_data['findings'])
            if 'log_findings' in routine_data:
                all_findings.extend(routine_data['log_findings'])
        
        exporter = SARIFExporter()
        exporter.export_sarif_file(all_findings, args.output)
        logger.info(f"Successfully exported {len(all_findings)} findings to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
