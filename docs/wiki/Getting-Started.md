# Getting Started 🚀

This guide walks you through installing and executing your first security scan with `Jailbreaker`.

---

## 📋 Prerequisites

- **Python 3.9+** installed.
- **Git** installed.
- **Semgrep** (Optional, recommended for full static rule coverage).
- **Ollama** (Optional, for offline local LLM verification).

---

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/z0uz/jailbreaker.git
   cd jailbreaker
   ```

2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Semgrep** (optional):
   ```bash
   pip install semgrep
   ```

---

## 🚀 Running Your First Scan

### Option A: Local Offline Scan (Zero Keys Needed)
If you have Ollama running locally:
```bash
python3 sast_scan.py --target ./src --model ollama
```

### Option B: Scan with Cloud LLM (OpenAI / Groq)
Set your environment variable and run the scanner:
```bash
export GROQ_API_KEY="gsk_..."
python3 sast_scan.py --target ./src --model groq
```

### Option C: Plain-Text Objective Execution
Execute scans using natural language objectives:
```bash
python3 run_objective.py --objective "run static scan" --target ./src
```
