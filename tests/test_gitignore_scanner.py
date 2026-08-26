"""Tests for the gitignore scanner."""

from __future__ import annotations

from pathlib import Path

from gitrisk.scanners.gitignore.scanner import GitIgnoreScanner
from gitrisk.core.models import Severity, FixType


def test_detects_missing_gitignore(tmp_path: Path):
    scanner = GitIgnoreScanner(tmp_path)
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "GIT-001" in ids


def test_no_finding_when_gitignore_exists_with_patterns(tmp_path: Path):
    (tmp_path / ".gitignore").write_text(".env\n*.key\n*.pem\n*.p12\n*.pfx\n")
    scanner = GitIgnoreScanner(tmp_path)
    findings = scanner.scan()
    assert findings == []


def test_detects_missing_patterns_in_gitignore(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("__pycache__/\n*.pyc\n")
    scanner = GitIgnoreScanner(tmp_path)
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "GIT-002" in ids


def test_auto_fix_creates_gitignore(tmp_path: Path):
    scanner = GitIgnoreScanner(tmp_path)
    findings = scanner.scan()
    # Apply the auto fix
    for f in findings:
        if f.auto_fix and f.id == "GIT-001":
            f.auto_fix(tmp_path)
    assert (tmp_path / ".gitignore").exists()
    content = (tmp_path / ".gitignore").read_text()
    assert ".env" in content
