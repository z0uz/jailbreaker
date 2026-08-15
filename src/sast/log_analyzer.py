"""
LLM Security Log Analyzer module.
Parses system and security logs for OWASP anomalies, credential exposures, and access issues.
"""

import json
import logging
from typing import Dict, Any, List
from pathlib import Path

from ..models.base_model import BaseModel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an AI Security Operations Center (SOC) Analyst. Analyze the following log snippet for potential security anomalies, credential exposure, unauthorized access attempts, or OWASP compliance issues.

Respond strictly in JSON matching this schema:
{
  "log_findings": [
    {
      "check_id": "LOG-SEC-001",
      "cwe_id": "CWE-532",
      "severity": "HIGH",
      "title": "Sensitive Information Disclosure in Logs",
      "explanation": "Detailed analysis of the issue found in logs.",
      "log_line_sample": "Exact line or snippet"
    }
  ]
}
"""

class LogAnalyzer:
    """Uses LLM API / Local Model to audit system logs."""
    
    def __init__(self, model: BaseModel):
        self.model = model
        
    async def analyze_logs(self, log_path: str) -> List[Dict[str, Any]]:
        """
        Reads a log file and sends its content to the LLM for security analysis.
        """
        path = Path(log_path)
        if not path.exists():
            logger.error(f"Log file not found: {log_path}")
            return []
            
        try:
            log_contents = path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read log file {log_path}: {e}")
            return []
            
        user_prompt = f"""
Logs to analyze:
```
{log_contents}
```
"""
        
        try:
            response = await self.model.generate_response(
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT,
                response_format={"type": "json_object"},
                temperature=0.0
            )
            
            content = response.get("content", "{}")
            analysis = self._parse_json(content)
            
            findings = analysis.get("log_findings", [])
            standardized_findings = []
            
            for finding in findings:
                standardized_findings.append({
                    "check_id": finding.get("check_id", "LOG-001"),
                    "cwe_id": finding.get("cwe_id", "CWE-Unknown"),
                    "file_path": str(path),
                    "start_line": 1,
                    "end_line": 1,
                    "confidence": finding.get("severity", "MEDIUM"),
                    "message": finding.get("title", "Log Security Anomaly"),
                    "explanation": f"{finding.get('explanation', '')}\n\nSample: {finding.get('log_line_sample', '')}"
                })
                
            return standardized_findings
            
        except Exception as e:
            logger.error(f"Failed to analyze logs via LLM: {e}")
            return []
            
    def _parse_json(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON object from model output text."""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if "```" in text:
                cleaned = text.split("```")[1]
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:]
                return json.loads(cleaned.strip())
            logger.error(f"Raw output failed JSON decode: {text}")
            raise
