# Contributing to ITSA Network OS — Developer Conventions & Review Rules

> **Document ID:** DOC-DEV-001  
> **Status:** Active Baseline  
> **Version:** 1.0.0  
> **Last Updated:** 2026-10-19  

---

## 1. Development Principles

1. **Investigate Before Acting:** Never modify or delete existing code without inspecting its purpose and dependencies.
2. **Smallest Safe Changes:** Prefer small, testable, verifiable changes over large speculative rewrites.
3. **Traceability:** Every functional change must map to a stable requirement ID (e.g. `REQ-NET-001`) and task ID (e.g. `TASK-004`).
4. **Preserve Working Code:** Do not refactor functional, tested code merely for stylistic differences.

---

## 2. Environment Setup

### 2.1 Linux Development Environment
```bash
# Ensure Python 3.10+ (Debian 13 includes Python 3.13)
python3 -m venv .venv
source .venv/bin/activate

# Install package in editable development mode
pip install -e .

# Install development & test dependencies
pip install pytest pytest-cov PySide6
```

---

## 3. Coding Conventions

### 3.1 Type Annotations
All new functions, methods, and classes must include static type annotations (`typing`, `dataclasses`, `enum`).
```python
def benchmark_target(host: str, port: int = 443, count: int = 4) -> LatencyBenchmarkResult:
    ...
```

### 3.2 Immutability & Data Modeling
Prefer frozen dataclasses (`@dataclass(frozen=True)`) for data structures representing diagnostic results, evidence records, and hardware state.

### 3.3 Defensive Execution & Subprocesses
- Never pass untrusted user input directly into shell execution (`subprocess.run(..., shell=True)` is prohibited).
- Always validate IP addresses, CIDRs, hostnames, and interface names through `InputValidator` before execution.

---

## 4. Git Commit & Review Workflow

### 4.1 Commit Message Format
Follow Conventional Commits:
```
<type>(<scope>): <short description> [REQ-XXX-YYY]

[Detailed description of what changed and why]
[Limitations and unverified areas]
```
- `feat:` New feature or capability.
- `fix:` Bug fix or security remediation.
- `refactor:` Code reorganization without behavioral change.
- `test:` Adding or updating tests.
- `docs:` Documentation updates.

### 4.2 Pull Request Quality Gate
Before submitting:
1. Run `.venv/bin/pytest -v` (all tests must pass).
2. Check that no new dependencies were introduced unless documented in `DECISIONS.md`.
3. Update `CHANGELOG.md` with verified modifications.
