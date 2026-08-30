"""Git history scanner — powered by GitRisk SEI (Secret Intelligence Engine).

Analyzes commit history for exposed secrets using the unified SEI pipeline,
filtering out Base64 media data streams, doc mocks, and invalid candidates.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding
from gitrisk.sei.engine import SecretIntelligenceEngine
from gitrisk.sei.topology import analyze_file_topology

MAX_COMMITS = 100  # Scan depth


class GitHistoryScanner(BaseScanner):
    """Scanner: Scans recent Git commit history for exposed secrets using SEI."""

    name = "git_history"
    description = "Scans Git commit history for secrets using the SEI intelligence engine."
    category = "secrets"

    def __init__(self, repo_path: Path) -> None:
        super().__init__(repo_path)
        self._sei = SecretIntelligenceEngine(repo_path=repo_path)

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            return findings

        try:
            result = subprocess.run(
                ["git", "log", f"-{MAX_COMMITS}", "-p", "--no-merges",
                 "--diff-filter=A",
                 "--unified=0"],
                cwd=self.repo_path,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            log_output = result.stdout
        except Exception:
            return findings

        if not log_output:
            return findings

        seen: set[str] = set()
        current_commit = ""
        current_file = ""
        current_topology = None

        for line in log_output.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:12]
            elif line.startswith("+++ b/"):
                current_file = line[6:].strip()
                current_topology = analyze_file_topology(Path(current_file))
            elif line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                if not added_content.strip():
                    continue

                diff_findings = self._sei.evaluate_line(
                    line=added_content,
                    line_number=0,
                    filepath=Path(current_file),
                    topology=current_topology,
                    commit_hash=current_commit,
                )

                for f in diff_findings:
                    key = f"{current_commit}:{current_file}:{f.evidence}"
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(f)

        return findings
