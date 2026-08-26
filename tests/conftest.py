"""Shared test fixtures for GitRisk."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def tmp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary Git repository for testing."""
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@test.com"], capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], capture_output=True)
    return tmp_path


@pytest.fixture
def clean_repo(tmp_git_repo: Path) -> Path:
    """A clean repository with no findings."""
    # Add a harmless README
    (tmp_git_repo / "README.md").write_text("# Test project\n")
    (tmp_git_repo / "SECURITY.md").write_text("# Security\nReport vulnerabilities via GitHub Security Advisories.\n")
    (tmp_git_repo / ".gitignore").write_text(".env\n*.key\n*.pem\n*.p12\n*.pfx\n__pycache__/\n")
    return tmp_git_repo
