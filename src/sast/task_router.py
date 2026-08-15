"""
Modular Objective Task Router.
Maps natural language objective instructions to evaluation routines.
"""

import logging
from typing import Dict, Any, Callable, List, Optional

logger = logging.getLogger(__name__)

class ObjectiveTaskRouter:
    """Registry and dispatcher for security evaluation routines."""
    
    def __init__(self):
        self._routines: Dict[str, Dict[str, Any]] = {}
        
    def register_routine(self, name: str, keywords: List[str], description: str):
        """Decorator or method to register an evaluation routine."""
        def decorator(func: Callable):
            self._routines[name] = {
                "func": func,
                "keywords": [k.lower() for k in keywords],
                "description": description
            }
            return func
        return decorator

    def list_routines(self) -> List[Dict[str, Any]]:
        """Return list of registered evaluation routines."""
        return [
            {"name": name, "keywords": info["keywords"], "description": info["description"]}
            for name, info in self._routines.items()
        ]

    def route_instruction(self, instruction: str) -> List[str]:
        """
        Analyze plain text instruction and return matching routine names.
        """
        instruction_lower = instruction.lower()
        matched_routines = []
        
        for name, info in self._routines.items():
            for kw in info["keywords"]:
                if kw in instruction_lower:
                    matched_routines.append(name)
                    break
                    
        # Default to SAST scan if no explicit match found
        if not matched_routines and "sast_scan" in self._routines:
            matched_routines.append("sast_scan")
            
        return matched_routines

    async def execute_instruction(self, instruction: str, target_path: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Route and execute evaluation routines for a given instruction.
        """
        matched = self.route_instruction(instruction)
        logger.info(f"Instruction: '{instruction}' mapped to routines: {matched}")
        
        results = {}
        ctx = context or {}
        
        for routine_name in matched:
            routine_fn = self._routines[routine_name]["func"]
            try:
                res = await routine_fn(target_path, ctx)
                results[routine_name] = res
            except Exception as e:
                logger.error(f"Error executing routine {routine_name}: {e}")
                results[routine_name] = {"error": str(e)}
                
        return {
            "instruction": instruction,
            "target": target_path,
            "routines_executed": matched,
            "results": results
        }
