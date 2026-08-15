# LLM Red-Teaming & Guardrails 🎯

`Jailbreaker` evaluates LLM guardrails, system prompt integrity, and adversarial resistance.

---

## ⚡ Attack Strategies (`src/attacks/`)

1. **Prompt Injection (`prompt_injection.py`)**:
   - Tests direct and indirect prompt overrides (e.g. instruction hijacking, delimiter insertion).

2. **Role-Play Jailbreaks (`role_play.py`)**:
   - Persona adoption (DAN, opposite assistant, hypothetical researcher) to bypass safety filters.

3. **Hypothetical Scenarios (`hypothetical.py`)**:
   - Academic framing, obfuscation, and reverse psychology.

---

## 🚀 Running Red-Teaming Evaluations

### 1. Model Security Evaluation
Benchmark a target LLM model against all attack categories:
```bash
python3 -m src.main
```

### 2. Live DAST Chatbot Red-Teaming
Start the test target endpoint:
```bash
python3 live_chatbot_api.py
```

Execute dynamic API red-teaming:
```bash
python3 run_objective.py --objective "run red team attack" --target-url "http://localhost:8000/api/chat"
```
