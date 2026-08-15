# Welcome to the Jailbreaker Wiki

`Jailbreaker` is an enterprise-grade automated security auditing and evaluation framework designed to evaluate source code, security logs, and AI model guardrails.

---

## Navigation Pages

1. **[Getting Started](Getting-Started)**
   - Prerequisites, installation steps, and environment configuration.

2. **[Hybrid SAST Pipeline](Hybrid-SAST-Pipeline)**
   - How static analysis (Semgrep/AST) integrates with Chain-of-Thought LLM verification to eliminate false positives and generate patches.

3. **[LLM Red-Teaming & Guardrails](LLM-Red-Teaming-&-Guardrails)**
   - Automated adversarial testing (Prompt Injection, Role-Play, Hypothetical Scenarios) and DAST API evaluation.

4. **[AI Log Auditing](AI-Log-Auditing)**
   - Parsing application and server logs for OWASP compliance violations, credential leaks, and anomalies.

5. **[Configuration Guide](Configuration-Guide)**
   - Complete reference for `config.yaml`, environment variables, model choices (OpenAI, Ollama, Groq), and SARIF reporting.

---

## Quick Architecture Overview

```mermaid
flowchart TD
    A[Target Code / Logs / API] --> B[Deterministic Scan\nSemgrep / AST Rules]
    B -->|Candidates| C[LLM Verification Judge\nChain-of-Thought Evaluation]
    C --> D{Is True Positive?}
    D -->|Yes| E[Verified SARIF Finding + Remediation Patch]
    D -->|No| F[Filtered False Positive]
    E --> G[CI/CD Integration\nGitHub / GitLab / Azure DevOps]
```
