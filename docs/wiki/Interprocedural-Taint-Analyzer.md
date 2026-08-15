# Interprocedural Taint Analyzer

The Interprocedural Taint Analyzer tracks untrusted dataflow across multiple Python modules and function calls.

---

## Capabilities

- Multi-file AST control flow and call graph indexing.
- Traces untrusted input sources (`request.args`, `input()`, `sys.argv`, `os.environ`).
- Flags untrusted data reaching hazardous sinks (`eval()`, `exec()`, `os.system()`, `sqlite3.connect()`, `pickle.loads()`).

---

## Execution

Run interprocedural taint analysis via `run_objective.py`:
```bash
python3 run_objective.py --objective "trace taint" --target ./src
```
