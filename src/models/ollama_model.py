"""
Ollama model wrapper for security testing.
"""

import aiohttp
import json
from typing import Dict, Any
import asyncio
from .base_model import BaseModel

class OllamaModel(BaseModel):
    """Ollama API wrapper for security research."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get('base_url', 'http://localhost:11434')
        self.model_name = config.get('model', 'deepseek-coder')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
        
    async def generate_response(self, prompt: str, **kwargs) -> Dict[str, Any]:
        """Generate response using Ollama API."""
        url = f"{self.base_url}/api/generate"
        
        system_prompt = kwargs.get('system_prompt')
        full_prompt = f"System: {system_prompt}\nUser: {prompt}" if system_prompt else prompt

        payload = {
            "model": self.model_name,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.get('temperature', self.config.get('temperature', 0.7)),
                "num_predict": kwargs.get('max_tokens', self.config.get('max_tokens', 1000))
            }
        }

        if kwargs.get('format') == 'json' or kwargs.get('response_format', {}).get('type') == 'json_object':
            payload["format"] = "json"

        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                headers = {'Content-Type': 'application/json'}
                async with session.post(url, json=payload, headers=headers) as response:
                    if response.status == 200:
                        # Handle both JSON and plain text responses
                        content_type = response.headers.get('content-type', '').lower()
                        
                        if 'application/json' in content_type:
                            data = await response.json()
                        else:
                            text = await response.text()
                            # Try to parse as JSON if it looks like JSON
                            if text.strip().startswith('{'):
                                try:
                                    data = json.loads(text)
                                except json.JSONDecodeError:
                                    # If it's not JSON, create a simple response structure
                                    data = {'response': text, 'done': True}
                            else:
                                data = {'response': text, 'done': True}
                        
                        result = {
                            'content': data.get('response', ''),
                            'finish_reason': data.get('done', True) and 'stop' or 'length',
                            'usage': {
                                'prompt_tokens': data.get('prompt_eval_count', 0),
                                'completion_tokens': data.get('eval_count', 0),
                                'total_tokens': data.get('prompt_eval_count', 0) + data.get('eval_count', 0)
                            },
                            'model': self.model_name,
                            'timestamp': asyncio.get_event_loop().time(),
                            'raw_response': data
                        }
                        
                        return result
                    else:
                        error_text = await response.text()
                        return {
                            'content': f"HTTP Error {response.status}: {error_text}",
                            'finish_reason': 'error',
                            'error': f"HTTP {response.status}: {error_text}",
                            'model': self.model_name
                        }
                        
        except asyncio.TimeoutError:
            return {
                'content': "Request timed out",
                'finish_reason': 'error',
                'error': 'timeout',
                'model': self.model_name
            }
        except Exception as e:
            return {
                'content': f"Error: {str(e)}",
                'finish_reason': 'error',
                'error': str(e),
                'model': self.model_name
            }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get Ollama model information."""
        return {
            'name': self.model_name,
            'provider': 'Ollama',
            'type': 'local_llm',
            'capabilities': ['text_generation', 'conversation'],
            'safety_features': ['local_processing', 'no_external_filtering'],
            'base_url': self.base_url
        }
    
    async def check_connection(self) -> bool:
        """Check if Ollama is running and model is available."""
        try:
            url = f"{self.base_url}/api/tags"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model['name'] for model in data.get('models', [])]
                        return self.model_name in models
                    return False
        except:
            return False
