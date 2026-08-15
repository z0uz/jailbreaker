"""
OpenAI model wrapper for security testing.
"""

import openai
from typing import Dict, Any
import asyncio
from .base_model import BaseModel

class OpenAIModel(BaseModel):
    """OpenAI API wrapper for security research."""
    
    def __init__(self, config: Dict[str, Any]):
        import os
        api_key = config.get('api_key')
        if not api_key or api_key.startswith("${"):
            env_var = api_key[2:-1] if (api_key and api_key.startswith("${") and api_key.endswith("}")) else "OPENAI_API_KEY"
            api_key = os.getenv(env_var) or os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY") or "dummy-key-for-offline"

        self.client = openai.AsyncOpenAI(
            api_key=api_key,
            base_url=config.get('base_url')
        )
        self.model_name = config.get('model', 'gpt-3.5-turbo')
        
    async def generate_response(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate response using OpenAI API."""
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

            # Pass remaining extra kwargs
            for k, v in kwargs.items():
                if k not in api_params and k not in ['temperature', 'max_tokens']:
                    api_params[k] = v

            response = await self.client.chat.completions.create(**api_params)

            
            result = {
                'content': response.choices[0].message.content,
                'finish_reason': response.choices[0].finish_reason,
                'usage': {
                    'prompt_tokens': response.usage.prompt_tokens,
                    'completion_tokens': response.usage.completion_tokens,
                    'total_tokens': response.usage.total_tokens
                },
                'model': self.model_name,
                'timestamp': asyncio.get_event_loop().time()
            }
            
            return result
            
        except Exception as e:
            return {
                'content': f"Error: {str(e)}",
                'finish_reason': 'error',
                'error': str(e),
                'model': self.model_name
            }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get OpenAI model information."""
        return {
            'name': self.model_name,
            'provider': 'OpenAI',
            'type': 'chat_completion',
            'capabilities': ['text_generation', 'conversation'],
            'safety_features': ['content_filtering', 'usage_monitoring']
        }
