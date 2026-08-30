"""Secret Lifecycle & Cross-Occurrence Correlator for GitRisk SEI.

Tracks secret fingerprints across working tree files and Git commit history
to determine true lifecycle status:
- Active in Working Tree
- Historical Leak (Committed then deleted)
- Documentation Mock / Shared Placeholder
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class LifecycleState(Enum):
    ACTIVE_COMMITTED = "active_committed"      # In working tree and tracked in Git
    HISTORICAL_LEAK = "historical_leak"        # Exists in past commits, removed in working tree
    LOCAL_UNTRACKED = "local_untracked"        # In working tree, untracked/gitignored
    DOC_EXAMPLE = "doc_example"                # Only found in documentation / mock files


@dataclass
class SecretOccurrence:
    file_path: Optional[Path]
    line_number: Optional[int]
    commit_hash: Optional[str]
    is_in_working_tree: bool
    is_git_tracked: bool
    evidence_snippet: str


@dataclass
class SecretLifecycleRecord:
    fingerprint_id: str
    rule_id: str
    title: str
    redacted_value: str
    occurrences: list[SecretOccurrence] = field(default_factory=list)

    @property
    def state(self) -> LifecycleState:
        has_active_tracked = any(o.is_in_working_tree and o.is_git_tracked for o in self.occurrences)
        has_historical = any(o.commit_hash is not None for o in self.occurrences)
        has_doc = all(
            o.file_path and o.file_path.suffix.lower() in (".md", ".txt", ".rst")
            for o in self.occurrences if o.file_path
        )

        if has_doc and not has_historical:
            return LifecycleState.DOC_EXAMPLE
        if has_active_tracked:
            return LifecycleState.ACTIVE_COMMITTED
        if has_historical and not any(o.is_in_working_tree for o in self.occurrences):
            return LifecycleState.HISTORICAL_LEAK
        return LifecycleState.LOCAL_UNTRACKED
