"""
Groq API model wrapper for fast inference security testing.
"""

import os
import openai
import asyncio
import logging
from typing import Dict, Any
from .base_model import BaseModel

logger = logging.getLogger(__name__)

class GroqModel(BaseModel):
    """Groq API wrapper for security evaluation."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        api_key = config.get('api_key')
        if not api_key or api_key.startswith("${"):
            api_key = os.getenv("GROQ_API_KEY", "dummy-key-for-offline")

        base_url = config.get('base_url', 'https://api.groq.com/openai/v1')
        
        self.client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=base_url
        )
        self.model_name = config.get('model', 'llama-3.1-8b-instant')
        
    async def generate_response(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate response using Groq API."""
        try:
            messages = []
            if 'system_prompt' in kwargs:
                messages.append({"role": "system", "content": kwargs.pop('system_prompt')})
            messages.append({"role": "user", "content": prompt})

            api_params = {
                'model': self.model_name,
                'messages': messages,
                'temperature': kwargs.get('temperature', self.config.get('temperature', 0.7)),
                'max_tokens': kwargs.get('max_tokens', self.config.get('max_tokens', 1000))
            }

            if 'response_format' in kwargs:
                api_params['response_format'] = kwargs.pop('response_format')

            for k, v in kwargs.items():
                if k not in api_params and k not in ['temperature', 'max_tokens']:
                    api_params[k] = v

            response = await self.client.chat.completions.create(**api_params)

            return {
                'content': response.choices[0].message.content,
                'finish_reason': response.choices[0].finish_reason,
                'usage': {
                    'prompt_tokens': response.usage.prompt_tokens if response.usage else 0,
                    'completion_tokens': response.usage.completion_tokens if response.usage else 0,
                    'total_tokens': response.usage.total_tokens if response.usage else 0
                },
                'model': self.model_name,
                'timestamp': asyncio.get_event_loop().time()
            }
            
        except Exception as e:
            logger.error(f"Groq API call error: {e}")
            return {
                'content': f"Error: {str(e)}",
                'finish_reason': 'error',
                'error': str(e),
                'model': self.model_name
            }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get Groq model information."""
        return {
            'name': self.model_name,
            'provider': 'Groq',
            'type': 'chat_completion',
            'capabilities': ['fast_text_generation', 'conversation'],
            'safety_features': ['groq_cloud_guardrails']
        }
