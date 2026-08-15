"""
Registered evaluation routines for task router.
"""

from typing import Dict, Any
from .task_router import ObjectiveTaskRouter
from .sast_runner import SASTRunner
from .stress_tester import PipelineStressTester
from .llm_verifier import LLMVerifier
from ..evaluation.metrics import SecurityMetrics
from .log_analyzer import LogAnalyzer
from ..attacks.red_teamer import RedTeamer

# Global router instance
default_router = ObjectiveTaskRouter()

@default_router.register_routine(
    name="sast_scan",
    keywords=["sast", "static analysis", "scan", "code audit", "vulnerability"],
    description="Deterministic static analysis scan to isolate code vulnerabilities."
)
async def sast_scan_routine(target_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
    runner = context.get("runner") or SASTRunner()
    findings = runner.scan_target(target_path)
    return {
        "routine": "sast_scan",
        "candidates_found": len(findings),
        "findings": findings
    }

@default_router.register_routine(
    name="stress_test",
    keywords=["stress", "augmentation", "noise", "resilience", "robustness", "boundary"],
    description="Data augmentation and input normalization stress testing."
)
async def stress_test_routine(target_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
    verifier = context.get("verifier")
    runner = context.get("runner") or SASTRunner()
    
    if not verifier:
        return {"routine": "stress_test", "status": "skipped", "reason": "No LLM verifier supplied in context."}
        
    tester = PipelineStressTester(verifier=verifier, runner=runner)
    candidates = runner.scan_target(target_path)
    
    stress_results = []
    for candidate in candidates:
        res = await tester.evaluate_stress_test(candidate, candidate["path"])
        stress_results.append(res)
        
    return {
        "routine": "stress_test",
        "tested_findings": len(stress_results),
        "results": stress_results
    }

@default_router.register_routine(
    name="metrics_evaluation",
    keywords=["metric", "score", "report", "summary", "stats"],
    description="Evaluates robustness metrics and score summaries."
)
async def metrics_routine(target_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
    metrics = SecurityMetrics()
    all_results = context.get("findings", [])
    report = metrics.generate_report(all_results, context.get("model_name", "standard_verifier"))
    return {
        "routine": "metrics_evaluation",
        "report": report
    }

@default_router.register_routine(
    name="audit_logs",
    keywords=["log", "audit logs", "anomaly", "soc", "compliance"],
    description="Analyzes system logs for security anomalies and credentials using LLM."
)
async def audit_logs_routine(target_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
    log_file = context.get("log_file")
    if not log_file:
        return {"routine": "audit_logs", "status": "skipped", "reason": "No log file provided in context."}
        
    model = context.get("verifier").model if context.get("verifier") else None
    if not model:
        return {"routine": "audit_logs", "status": "skipped", "reason": "No model supplied in context."}
        
    log_analyzer = LogAnalyzer(model=model)
    findings = await log_analyzer.analyze_logs(log_file)
    
    return {
        "routine": "audit_logs",
        "findings_count": len(findings),
        "log_findings": findings
    }

@default_router.register_routine(
    name="red_team",
    keywords=["jailbreak", "red team", "dast", "dynamic", "attack"],
    description="Dynamic Application Security Testing (DAST) for prompt injection and jailbreaks."
)
async def red_team_routine(target_path: str, context: Dict[str, Any]) -> Dict[str, Any]:
    target_url = context.get("target_url")
    if not target_url:
        return {"routine": "red_team", "status": "skipped", "reason": "No target_url provided in context."}
        
    verifier = context.get("verifier")
    if not verifier:
        return {"routine": "red_team", "status": "skipped", "reason": "No LLM verifier supplied in context to grade attacks."}
        
    teamer = RedTeamer(target_url=target_url, verifier=verifier)
    findings = await teamer.execute_attacks()
    
    return {
        "routine": "red_team",
        "successful_jailbreaks": len(findings),
        "findings": findings
    }
