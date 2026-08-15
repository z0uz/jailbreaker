"""
SARIF Exporter module for generating OASIS SARIF v2.1.0 JSON reports.
"""

import json
from typing import List, Dict, Any

class SARIFExporter:
    """Exports verified SAST findings into standard SARIF v2.1.0 format."""
    
    def __init__(self, tool_name: str = "Jailbreaker-Hybrid-SAST", tool_version: str = "1.0.0"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        
    def generate_sarif(self, verified_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert verified findings list into SARIF schema object."""
        rules = []
        rule_indices = {}
        results = []
        
        for finding in verified_findings:
            rule_id = finding.get("check_id") or finding.get("rule_id", "rule-unknown")
            cwe_id = finding.get("cwe_id", "CWE-Unknown")
            
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {
                        "text": f"Security check: {rule_id}"
                    },
                    "fullDescription": {
                        "text": finding.get("explanation", finding.get("message", "Potential issue detected"))
                    },
                    "properties": {
                        "cwe": [cwe_id]
                    }
                })
            
            rule_index = rule_indices[rule_id]
            file_path = finding.get("file_path") or finding.get("path", "src/main.py")
            start_line = finding.get("start_line", finding.get("line_number", 1))
            end_line = finding.get("end_line", start_line)
            
            level = "error" if finding.get("severity", "").upper() == "ERROR" or finding.get("confidence") == "HIGH" else "warning"
            
            sarif_result = {
                "ruleId": rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": f"[{cwe_id}] {finding.get('message')}\n\nExplanation: {finding.get('explanation', 'Candidate vulnerability isolated by AST scanner.')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(file_path).lstrip("./")
                            },
                            "region": {
                                "startLine": start_line,
                                "endLine": end_line
                            }
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.get("confidence", "MEDIUM"),
                    "remediation_patch": finding.get("remediation_patch", "")
                }
            }
            results.append(sarif_result)
            
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }
        
        return sarif_doc

    def export_sarif_file(self, verified_findings: List[Dict[str, Any]], output_file: str):
        """Save SARIF data to specified file path."""
        sarif_data = self.generate_sarif(verified_findings)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)


def generate_sarif_report(findings: List[Dict[str, Any]], tool_name: str = "AIShield-Scanner") -> str:
    """
    Formats a list of code security findings into standard SARIF JSON format.
    """
    sarif_structure = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    rules_map = {}
    
    for finding in findings:
        rule_id = finding.get("rule_id", "SEC001")
        
        # Add rule metadata if not present
        if rule_id not in rules_map:
            rule_entry = {
                "id": rule_id,
                "shortDescription": {"text": finding.get("title", "Security Vulnerability")},
                "fullDescription": {"text": finding.get("description", "")},
                "defaultConfiguration": {"level": finding.get("severity", "warning").lower()}
            }
            sarif_structure["runs"][0]["tool"]["driver"]["rules"].append(rule_entry)
            rules_map[rule_id] = True

        # Construct result entry
        result_entry = {
            "ruleId": rule_id,
            "message": {"text": finding.get("message", "")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("file_path", "unknown")},
                        "region": {
                            "startLine": finding.get("line_number", 1)
                        }
                    }
                }
            ]
        }
        sarif_structure["runs"][0]["results"].append(result_entry)

    return json.dumps(sarif_structure, indent=2)

