"""Tests for the scoring engine."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.models import Finding, Severity, FixType
from gitrisk.scoring.scorer import compute_scores


def test_no_findings_perfect_score():
    _, overall = compute_scores([])
    assert overall == 100


def test_critical_finding_reduces_score():
    findings = [
        Finding("SEC-001", "secrets", "t", "d", Severity.CRITICAL, FixType.MANUAL, "r"),
    ]
    _, overall = compute_scores(findings)
    assert overall < 100


def test_multiple_critical_findings():
    findings = [
        Finding("SEC-001", "secrets", "t", "d", Severity.CRITICAL, FixType.MANUAL, "r"),
        Finding("SEC-002", "secrets", "t", "d", Severity.CRITICAL, FixType.MANUAL, "r"),
        Finding("SEC-003", "secrets", "t", "d", Severity.CRITICAL, FixType.MANUAL, "r"),
    ]
    _, overall = compute_scores(findings)
    # Score should be significantly reduced from 100
    assert overall <= 80


def test_score_bounded_between_0_and_100():
    findings = [
        Finding(f"SEC-{i:03d}", "secrets", "t", "d", Severity.CRITICAL, FixType.MANUAL, "r")
        for i in range(20)
    ]
    _, overall = compute_scores(findings)
    assert 0 <= overall <= 100


def test_category_scores_returned():
    findings = [
        Finding("SEC-001", "secrets", "t", "d", Severity.HIGH, FixType.MANUAL, "r"),
        Finding("DEP-001", "dependencies", "t", "d", Severity.MEDIUM, FixType.REVIEW, "r"),
    ]
    cat_scores, _ = compute_scores(findings)
    assert len(cat_scores) > 0
    names = [cs.name for cs in cat_scores]
    assert "Secrets" in names or "secrets" in [n.lower() for n in names]
