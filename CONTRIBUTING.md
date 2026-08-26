# Contributing to GitRisk

Thank you for your interest in contributing to GitRisk! This document explains how to get involved.

## Development Setup

```bash
git clone https://github.com/gitrisk/gitrisk.git
cd gitrisk
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .[dev]
```

## Running Tests

```bash
pytest
pytest --cov=gitrisk tests/
```

## Code Style

We use `ruff` for linting and formatting:

```bash
ruff check src/
ruff format src/
```

## Adding a Scanner

1. Create a new file in `src/gitrisk/scanners/your_scanner/scanner.py`
2. Subclass `BaseScanner` from `gitrisk.core.base`
3. Implement the `scan()` method — it must return a `list[Finding]`
4. Register your scanner in `src/gitrisk/scanners/__init__.py`
5. Add tests in `tests/scanners/test_your_scanner.py`

## Finding IDs

Each finding must have a unique ID using the format `CAT-NNN`, e.g.:
- `SEC-001` — Secrets scanner findings
- `DEP-001` — Dependency scanner findings
- `ENV-001` — Environment file findings
- `GHA-001` — GitHub Actions findings
- `GIT-001` — Git configuration findings
- `SEN-001` — Sensitive file findings
- `CFG-001` — Configuration findings
- `OUT-001` — Outdated dependency findings
- `POL-001` — Policy/documentation findings
- `HRD-001` — Hardcoding findings

## Pull Request Guidelines

- Keep PRs focused on a single change
- Add tests for new scanners
- Update docs if you add new commands or change behavior
- Scanners must never upload or transmit repository data

## Reporting Bugs

Open a GitHub Issue with a reproduction case.
