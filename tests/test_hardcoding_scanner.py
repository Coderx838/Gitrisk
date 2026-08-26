"""Tests for the hardcoding scanner."""

from __future__ import annotations

from pathlib import Path

from gitrisk.scanners.hardcoding.scanner import HardcodingScanner
from gitrisk.core.models import Severity


def test_detects_hardcoded_password(tmp_path: Path):
    (tmp_path / "db.py").write_text('password = "mysecretpassword"\n')
    scanner = HardcodingScanner(tmp_path)
    findings = scanner.scan()
    assert any("HRD-002" in f.id for f in findings)


def test_detects_connection_string(tmp_path: Path):
    (tmp_path / "config.py").write_text('DB_URL = "postgres://user:password123@localhost:5432/mydb"\n')
    scanner = HardcodingScanner(tmp_path)
    findings = scanner.scan()
    assert any("HRD-001" in f.id for f in findings)


def test_no_false_positive_clean_code(tmp_path: Path):
    (tmp_path / "main.py").write_text("""
DEBUG = True
NAME = "myapp"
VERSION = "1.0.0"
""")
    scanner = HardcodingScanner(tmp_path)
    findings = scanner.scan()
    # Should be clean
    critical_high = [f for f in findings if f.severity.value >= 3]
    assert critical_high == []


def test_detects_internal_ip(tmp_path: Path):
    (tmp_path / "deploy.py").write_text('SERVER = "192.168.1.100"\n')
    scanner = HardcodingScanner(tmp_path)
    findings = scanner.scan()
    assert any("HRD-004" in f.id for f in findings)
