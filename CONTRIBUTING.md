# Contributing to Jailbreaker

Thank you for your interest in contributing!

## Development Workflow

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/z0uz/jailbreaker.git
   cd jailbreaker
   ```

2. **Set Up Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Run Unit Tests**:
   Ensure all unit tests pass before submitting a pull request:
   ```bash
   python3 -m pytest
   ```

4. **Submit Pull Request**:
   - Create a feature branch (`git checkout -b feature/my-feature`).
   - Commit clean, self-contained changes.
   - Push to your fork and submit a PR against `main`.
