"""Base scanner class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from gitrisk.core.models import Finding


class BaseScanner(ABC):
    """Abstract base class for all GitRisk scanners."""

    #: Short identifier used in Finding.scanner and CLI --scanners filter
    name: str = "base"
    #: Human-readable description shown in --help
    description: str = ""
    #: Category for scoring
    category: str = "general"

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Run the scanner and return a list of findings."""

    def _rel(self, path: Path) -> Path:
        """Return path relative to repo root for display."""
        try:
            return path.relative_to(self.repo_path)
        except ValueError:
            return path
