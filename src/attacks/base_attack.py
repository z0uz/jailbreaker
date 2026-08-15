"""
Base class for attack patterns used in AI security testing.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseAttack(ABC):
    """Abstract base class for attack patterns."""
    
    def __init__(self, name: str, description: str, severity: str = "medium"):
        self.name = name
        self.description = description
        self.severity = severity  # low, medium, high, critical
        self.success_count = 0
        self.total_attempts = 0
        
    @abstractmethod
    def generate_prompts(self, target_behavior: str) -> List[str]:
        """
        Generate attack prompts for testing specific behavior.
        
        Args:
            target_behavior: The behavior we're trying to elicit
            
        Returns:
            List of attack prompts
        """
        pass
    
    @abstractmethod
    def evaluate_success(self, prompt: str, response: str) -> bool:
        """
        Evaluate if the attack was successful.
        
        Args:
            prompt: The attack prompt used
            response: The model's response
            
        Returns:
            True if attack succeeded, False otherwise
        """
        pass
    
    async def execute_attack(self, model, target_behavior: str) -> Dict[str, Any]:
        """
        Execute the attack against a model.
        
        Args:
            model: The target model
            target_behavior: The behavior to test
            
        Returns:
            Attack results and metrics
        """
        prompts = self.generate_prompts(target_behavior)
        results = []
        
        for prompt in prompts:
            self.total_attempts += 1
            
            try:
                response = await model.generate_response(prompt)
                success = self.evaluate_success(prompt, response.get('content', ''))
                
                if success:
                    self.success_count += 1
                    
                result = {
                    'prompt': prompt,
                    'response': response.get('content', ''),
                    'success': success,
                    'attack_type': self.name,
                    'timestamp': datetime.now().isoformat(),
                    'model': model.name,
                    'target_behavior': target_behavior
                }
                
                results.append(result)
                
            except Exception as e:
                logger.error(f"Attack execution failed: {e}")
                results.append({
                    'prompt': prompt,
                    'response': '',
                    'success': False,
                    'error': str(e),
                    'attack_type': self.name,
                    'timestamp': datetime.now().isoformat()
                })
        
        return {
            'attack_name': self.name,
            'total_attempts': len(prompts),
            'successful_attacks': sum(1 for r in results if r.get('success', False)),
            'success_rate': self.success_count / self.total_attempts if self.total_attempts > 0 else 0,
            'results': results
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get attack statistics."""
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'success_count': self.success_count,
            'total_attempts': self.total_attempts,
            'success_rate': self.success_count / self.total_attempts if self.total_attempts > 0 else 0
        }
