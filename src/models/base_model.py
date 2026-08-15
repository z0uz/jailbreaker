"""
Base interface for AI model wrappers used in security testing.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class BaseModel(ABC):
    """Abstract base class for AI model interfaces."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = config.get('name', 'unknown')
        self.model_type = config.get('type', 'unknown')
        
    @abstractmethod
    async def generate_response(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """
        Generate a response from the model.
        
        Args:
            prompt: The input prompt to send to the model
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
            
        Returns:
            Dictionary containing response and metadata
        """
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and capabilities."""
        pass
    
    def validate_response(self, response: Dict[str, Any]) -> bool:
        """Validate that response contains required fields."""
        required_fields = ['content', 'finish_reason']
        return all(field in response for field in required_fields)
    
    def log_interaction(self, prompt: str, response: Dict[str, Any], 
                        attack_type: str = "unknown") -> None:
        """Log model interactions for analysis."""
        logger.info(f"Model: {self.name}, Attack: {attack_type}")
        logger.debug(f"Prompt: {prompt[:100]}...")
        logger.debug(f"Response: {response.get('content', '')[:100]}...")
