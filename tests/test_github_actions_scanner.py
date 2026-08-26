"""Tests for the GitHub Actions scanner."""

from __future__ import annotations

from pathlib import Path

from gitrisk.scanners.github_actions.scanner import GitHubActionsScanner


def test_no_findings_without_workflows(tmp_path: Path):
    scanner = GitHubActionsScanner(tmp_path)
    findings = scanner.scan()
    assert findings == []


def test_detects_write_all_permissions(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("""
name: CI
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    scanner = GitHubActionsScanner(tmp_path)
    findings = scanner.scan()
    assert any("GHA-001" in f.id for f in findings)


def test_detects_missing_permissions_block(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("""
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    scanner = GitHubActionsScanner(tmp_path)
    findings = scanner.scan()
    assert any("GHA-004" in f.id for f in findings)


def test_no_finding_with_read_permissions(tmp_path: Path):
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("""
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    scanner = GitHubActionsScanner(tmp_path)
    findings = scanner.scan()
    # GHA-001 and GHA-004 should NOT be present
    assert all(f.id not in ("GHA-001", "GHA-004") for f in findings)
