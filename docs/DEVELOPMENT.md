# Development Guide — ITSA Network OS

## Prerequisites
- **Python**: 3.10 or higher.
- **Debian**: 12 or 13 (or compatible Linux / cross-platform development environment).
- **Git** (optional, recommended for version control).

## Environment Setup

### 1. Create and Activate Virtual Environment
```bash
cd itsa-network-os
python3 -m venv .venv
source .venv/bin/activate  # On Linux / macOS
# On Windows PowerShell: .venv\Scripts\Activate.ps1
```

### 2. Install in Editable Mode
```bash
pip install -e .
# Or install development testing tools:
pip install pytest pytest-cov
```

## Running the Application
```bash
# Display general status and health check
python3 -m itsa_network_os.main --health

# Calculate IPv4 subnet parameters
python3 -m itsa_network_os.main --calc-subnet 192.168.10.0/24

# List network interfaces (safe mock data by default)
python3 -m itsa_network_os.main --list-interfaces

# Display application version
python3 -m itsa_network_os.main --version
```

## Running Automated Tests
```bash
# Using pytest
pytest

# Or using the built-in test runner script (no external dependencies required)
python3 scripts/run_tests.py
```

## Coding Conventions
- **Typing**: Use static type annotations on all function signatures (`typing`, `dataclasses`).
- **Safety**: Do not invoke system calls with shell execution without strict sanitation.
- **Testing**: Every new network or core feature must be accompanied by unit tests.
