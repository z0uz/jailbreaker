# Configuration Guide

Configuration is managed via `config.yaml`.

---

## Complete `config.yaml` Reference

```yaml
models:
  openai:
    api_key: "${OPENAI_API_KEY}"       # Evaluated from environment variable
    model: "gpt-4o-mini"
    base_url: "https://api.openai.com/v1"
  
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-3-sonnet-20240229"
    base_url: "https://api.anthropic.com"
  
  groq:
    api_key: "${GROQ_API_KEY}"
    model: "llama-3.1-8b-instant"
    base_url: "https://api.groq.com/openai/v1"
  
  ollama:
    api_key: ""
    model: "llama3.2:latest"            # Local model tag
    base_url: "http://localhost:11434"
    timeout: 60

sast:
  semgrep:
    enabled: true
    config: "auto"                     # Can be comma-separated: "p/python,p/security-audit"
  ast_fallback: true
  verifier:
    model: "openai"                    # Model key used for SAST verifier
    confidence_threshold: "MEDIUM"     # HIGH, MEDIUM, LOW
  output:
    default_format: "sarif"            # sarif or json
```
