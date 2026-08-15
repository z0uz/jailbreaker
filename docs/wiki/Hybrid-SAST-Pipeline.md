# Hybrid SAST Pipeline 🔍

The Hybrid SAST Engine combines the speed of deterministic static analysis with the contextual understanding of Large Language Models.

---

## 🏗️ Architecture

```
[Target Source Code]
        │
        ▼
[SAST Candidate Scanner] ──(Semgrep / AST Rules)──> [Candidate Findings]
                                                            │
                                                            ▼
[LLM Verification Judge] <──(Context & Line Window)─────────┘
        │
        ├─(Chain-of-Thought: Source -> Sanitizer -> Sink)
        │
        ├─► [True Positive]  ──> Generate Remediation Patch & Export SARIF
        └─► [False Positive] ──> Filter Out Finding
```

---

## 1. Candidate Extraction (Step 1)
- Uses **Semgrep** static rulesets (`p/python`, `p/security-audit`, `p/secrets`) or a multi-pattern Python **AST fallback visitor**.
- Isolates potential vulnerabilities:
  - Dynamic file opens & Path traversal (`open(var)`)
  - Insecure deserialization (`pickle.loads`, `marshal.loads`, `yaml.unsafe_load`)
  - Hardcoded secrets and API keys
  - Weak cryptographic algorithms (`hashlib.md5`, `hashlib.sha1`)
  - Dangerous system calls (`os.system`, `subprocess(shell=True)`)

## 2. Chain-of-Thought LLM Verification (Step 2)
- Formats code context around candidate findings with line numbers and trigger markers (`>>>`).
- Evaluates code using structured reasoning:
  1. **Source Identification**: Where does untrusted dynamic data enter?
  2. **Taint Tracking**: Is the data sanitized, escaped, or validated before reaching the sink?
  3. **Sink Impact**: Is the flagged line exploitably vulnerable or safe?
- Generates a remediation patch for verified True Positives.

## 3. OASIS SARIF v2.1.0 Export
- Exports findings into standard SARIF format for GitHub Security, GitLab, and Azure DevOps integration.
