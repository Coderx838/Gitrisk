"""Tests for core data models."""

from __future__ import annotations

from pathlib import Path

import pytest

from gitrisk.core.models import Finding, Severity, FixType, ScanResults, CategoryScore


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO


def test_severity_emoji():
    assert Severity.CRITICAL.emoji == "💀"
    assert Severity.HIGH.emoji == "🔴"
    assert Severity.MEDIUM.emoji == "🟡"
    assert Severity.LOW.emoji == "🟢"


def test_severity_color():
    assert Severity.HIGH.color == "red"
    assert Severity.MEDIUM.color == "yellow"


def test_finding_to_dict():
    finding = Finding(
        id="SEC-001",
        scanner="secrets",
        title="Test finding",
        description="A test finding description.",
        severity=Severity.HIGH,
        fix_type=FixType.MANUAL,
        remediation="Fix it manually.",
        file=Path("/repo/src/main.py"),
        line=42,
        evidence="AKIA*****",
        references=["https://example.com"],
    )
    d = finding.to_dict()
    assert d["id"] == "SEC-001"
    assert d["severity"] == "HIGH"
    assert d["fix_type"] == "MANUAL"
    assert d["line"] == 42
    assert d["evidence"] == "AKIA*****"


def test_scan_results_counts():
    from gitrisk.core.models import Finding, Severity, FixType
    findings = [
        Finding("C-001", "s", "c", "d", Severity.CRITICAL, FixType.MANUAL, "r"),
        Finding("H-001", "s", "h", "d", Severity.HIGH, FixType.MANUAL, "r"),
        Finding("H-002", "s", "h2", "d", Severity.HIGH, FixType.SAFE, "r"),
        Finding("M-001", "s", "m", "d", Severity.MEDIUM, FixType.REVIEW, "r"),
        Finding("L-001", "s", "l", "d", Severity.LOW, FixType.SAFE, "r"),
    ]
    results = ScanResults(
        repo_path=Path("/repo"),
        repo_name="test-repo",
        files_scanned=10,
        findings=findings,
        category_scores=[CategoryScore("test", 75)],
        overall_score=75,
    )
    assert results.critical_count == 1
    assert results.high_count == 2
    assert results.medium_count == 1
    assert results.low_count == 1
