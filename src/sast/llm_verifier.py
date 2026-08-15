"""
LLM Verifier module for candidate findings.
Acts as a security judge to validate findings, assign CWE IDs, and generate patches.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from ..models.base_model import BaseModel

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert Application Security Auditor and SAST Judge.
Your task is to analyze candidate static analysis security findings against the target source code.

Perform step-by-step Chain-of-Thought reasoning before making your classification:
1. Identify the Source: Where does user input or dynamic data enter?
2. Trace Dataflow & Sanitizers: Is the input sanitized, validated, parameterized, or escaped before reaching the target sink?
3. Evaluate Sink Impact: Is the flagged operation executed safely or is it exploitably vulnerable?
4. Determine Final Result: True Positive or False Positive.

Respond strictly in JSON format matching this schema:
{
  "chain_of_thought": "Step-by-step taint and control-flow evaluation...",
  "is_true_positive": true/false,
  "cwe_id": "CWE-XXX",
  "confidence": "HIGH/MEDIUM/LOW",
  "explanation": "Clear explanation of vulnerability mechanisms or why it is safe...",
  "remediation_patch": "Corrected code snippet fixing the issue securely"
}
"""

class LLMVerifier:
    """Uses LLM API / Local Model as a verifier and patch generator."""
    
    def __init__(self, model: BaseModel, confidence_threshold: str = "MEDIUM"):
        self.model = model
        self.confidence_threshold = confidence_threshold

    @staticmethod
    def extract_focused_context(file_content: str, start_line: int, end_line: int, context_lines: int = 30) -> str:
        """Extract code window with line numbers and trigger markers."""
        lines = file_content.splitlines()
        total_lines = len(lines)
        
        ctx_start = max(1, start_line - context_lines)
        ctx_end = min(total_lines, end_line + context_lines)
        
        formatted_lines = []
        for i in range(ctx_start, ctx_end + 1):
            line_str = lines[i - 1] if i <= total_lines else ""
            marker = ">>> " if (start_line <= i <= end_line) else "    "
            formatted_lines.append(f"{marker}{i:4d} | {line_str}")
            
        return "\n".join(formatted_lines)
        
    async def verify_finding(self, finding: Dict[str, Any], file_content: str) -> Dict[str, Any]:
        """
        Send finding context to LLM for validation.
        """
        rule_id = finding.get("check_id")
        message = finding.get("message")
        start_line = finding.get("start_line", 1)
        end_line = finding.get("end_line", 1)
        file_path = finding.get("path")
        
        snippet = self.extract_focused_context(file_content, start_line, end_line)
        
        user_prompt = f"""
Analyze the following potential security finding:
Rule Triggered: {rule_id}
File Path: {file_path}
Message: {message}
Flagged Line Range: {start_line} to {end_line}

Target Source Code Context ('>>>' indicates flagged line range):
```
{snippet}
```
"""
        try:
            response = await self.model.generate_response(
                prompt=user_prompt,
                system_prompt=SYSTEM_PROMPT,
                response_format={"type": "json_object"},
                temperature=0.1
            )
            
            content = response.get("content", "{}")
            analysis = self._parse_json(content)
            
            return {
                "check_id": rule_id,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "message": message,
                "chain_of_thought": analysis.get("chain_of_thought", ""),
                "is_true_positive": analysis.get("is_true_positive", False),
                "cwe_id": analysis.get("cwe_id", "CWE-Unknown"),
                "confidence": analysis.get("confidence", "LOW"),
                "explanation": analysis.get("explanation", "No explanation provided."),
                "remediation_patch": analysis.get("remediation_patch", "")
            }
        except Exception as e:
            logger.error(f"Failed to verify finding {rule_id}: {e}")
            return {
                "check_id": rule_id,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "message": message,
                "chain_of_thought": f"Verification error: {str(e)}",
                "is_true_positive": False,
                "cwe_id": "CWE-Unknown",
                "confidence": "LOW",
                "explanation": f"LLM verification error: {str(e)}",
                "remediation_patch": ""
            }

    def _parse_json(self, text: str) -> Dict[str, Any]:
        """Extract and parse JSON object from model output text."""
        if not text or not text.strip():
            return {}
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            pass
            
        # Fallback 1: Codeblock extraction
        if "```" in text:
            for chunk in text.split("```"):
                chunk = chunk.strip()
                if chunk.startswith("json"):
                    chunk = chunk[4:].strip()
                if chunk.startswith("{") and chunk.endswith("}"):
                    try:
                        return json.loads(chunk)
                    except json.JSONDecodeError:
                        pass

        # Fallback 2: Regex extraction for first '{' ... '}' structure
        import re
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
                
        logger.warning(f"Could not parse JSON response from model output: {text[:200]}")
        return {}


