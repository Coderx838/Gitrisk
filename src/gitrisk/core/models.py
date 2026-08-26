"""Core data models for GitRisk."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Callable, Optional


class Severity(IntEnum):
    """Finding severity levels."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def emoji(self) -> str:
        return {
            Severity.INFO: "ℹ️ ",
            Severity.LOW: "🟢",
            Severity.MEDIUM: "🟡",
            Severity.HIGH: "🔴",
            Severity.CRITICAL: "💀",
        }[self]

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "dim",
            Severity.LOW: "green",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red",
        }[self]


class FixType(str, Enum):
    """How a finding should be remediated."""
    SAFE = "SAFE"        # Can be auto-applied
    REVIEW = "REVIEW"    # Show diff, user must approve
    MANUAL = "MANUAL"    # Human judgment required


@dataclass
class Finding:
    """A single security or health finding from a scanner."""

    id: str                        # e.g. "SEC-001"
    scanner: str                   # scanner name
    title: str                     # short human-readable title
    description: str               # full explanation
    severity: Severity
    fix_type: FixType
    remediation: str               # what to do
    file: Optional[Path] = None    # file where issue was found
    line: Optional[int] = None     # line number
    evidence: Optional[str] = None # snippet of evidence
    references: list[str] = field(default_factory=list)  # links
    auto_fix: Optional[Callable[[Path], None]] = None    # callable fix fn
    uid: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "uid": self.uid,
            "scanner": self.scanner,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "fix_type": self.fix_type.value,
            "remediation": self.remediation,
            "file": str(self.file) if self.file else None,
            "line": self.line,
            "evidence": self.evidence,
            "references": self.references,
        }


@dataclass
class CategoryScore:
    """Score for a single scanning category."""
    name: str
    score: int       # 0-100
    max_score: int = 100
    findings: int = 0


@dataclass
class ScanResults:
    """Aggregated results from a full GitRisk scan."""
    repo_path: Path
    repo_name: str
    files_scanned: int
    findings: list[Finding]
    category_scores: list[CategoryScore]
    overall_score: int
    elapsed_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
