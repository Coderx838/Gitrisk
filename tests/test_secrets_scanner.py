"""Tests for the secrets scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from gitrisk.scanners.secrets.scanner import SecretsScanner
from gitrisk.core.models import Severity


def test_detects_aws_key(tmp_path: Path):
    (tmp_path / "config.py").write_text('ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    assert any("SEC-001" in f.id for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_detects_github_token(tmp_path: Path):
    (tmp_path / "deploy.sh").write_text('export TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"\n')
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    assert any("SEC-003" in f.id for f in findings)


def test_detects_private_key(tmp_path: Path):
    (tmp_path / "key.pem").write_text('-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n')
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    assert any("SEC-010" in f.id for f in findings)


def test_no_false_positive_clean_file(tmp_path: Path):
    (tmp_path / "main.py").write_text("print('Hello, GitRisk!')\n")
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    assert findings == []


def test_skips_node_modules(tmp_path: Path):
    node_mod = tmp_path / "node_modules" / "lib"
    node_mod.mkdir(parents=True)
    (node_mod / "config.js").write_text('const key = "AKIAIOSFODNN7EXAMPLE"')
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    # Should not find the key in node_modules
    assert all("node_modules" not in str(f.file) for f in findings)


def test_evidence_is_redacted(tmp_path: Path):
    (tmp_path / "app.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    scanner = SecretsScanner(tmp_path)
    findings = scanner.scan()
    for f in findings:
        if f.evidence:
            # Evidence should be partially redacted
            assert "*" in f.evidence
