"""Tests for the security policy scanner."""

from __future__ import annotations

from pathlib import Path

from gitrisk.scanners.security_policy.scanner import SecurityPolicyScanner


def test_detects_missing_security_md(tmp_path: Path):
    scanner = SecurityPolicyScanner(tmp_path)
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "POL-001" in ids


def test_no_finding_when_security_md_exists(tmp_path: Path):
    (tmp_path / "SECURITY.md").write_text("# Security Policy\n")
    scanner = SecurityPolicyScanner(tmp_path)
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "POL-001" not in ids


def test_auto_fix_creates_security_md(tmp_path: Path):
    scanner = SecurityPolicyScanner(tmp_path)
    findings = scanner.scan()
    for f in findings:
        if f.auto_fix and f.id == "POL-001":
            f.auto_fix(tmp_path)
    assert (tmp_path / "SECURITY.md").exists()
    content = (tmp_path / "SECURITY.md").read_text()
    assert "Reporting a Vulnerability" in content


def test_detects_missing_readme(tmp_path: Path):
    (tmp_path / "SECURITY.md").write_text("# Security\n")
    scanner = SecurityPolicyScanner(tmp_path)
    findings = scanner.scan()
    ids = [f.id for f in findings]
    assert "POL-002" in ids
