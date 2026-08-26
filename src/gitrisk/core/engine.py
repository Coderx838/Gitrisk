"""GitRisk scan engine — orchestrates all scanners."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from gitrisk import __version__
from gitrisk.core.models import CategoryScore, Severity, ScanResults
from gitrisk.core.base import BaseScanner
from gitrisk.scanners import get_all_scanners
from gitrisk.scoring.scorer import compute_scores

console = Console()


class ScanEngine:
    """Orchestrates the full GitRisk scan lifecycle."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = repo_path.resolve()

    def _collect_files(self) -> list[Path]:
        """Collect all non-ignored files in the repository."""
        files = []
        for p in self.repo_path.rglob("*"):
            if p.is_file():
                # Skip hidden dirs like .git
                parts = p.relative_to(self.repo_path).parts
                if any(part.startswith(".") and part != ".env" and part != ".gitignore"
                       for part in parts[:-1]):
                    if not any(part in (".github",) for part in parts):
                        continue
                files.append(p)
        return files

    def run(self, scanner_filter: Optional[list[str]] = None) -> ScanResults:
        """Run all (or selected) scanners and return aggregated results."""
        start = time.monotonic()

        all_scanner_classes = get_all_scanners()

        if scanner_filter:
            scanner_classes = [
                cls for cls in all_scanner_classes
                if cls.name in scanner_filter
            ]
        else:
            scanner_classes = all_scanner_classes

        all_findings = []
        files = self._collect_files()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {self.repo_path.name}...[/]",
                total=len(scanner_classes),
            )
            for cls in scanner_classes:
                progress.update(task, description=f"[cyan]Running {cls.name} scanner...[/]")
                scanner: BaseScanner = cls(self.repo_path)
                try:
                    findings = scanner.scan()
                    all_findings.extend(findings)
                except Exception as exc:
                    console.print(f"[yellow]⚠ Scanner '{cls.name}' failed: {exc}[/]")
                progress.advance(task)

        # Sort: critical first
        all_findings.sort(key=lambda f: f.severity.value, reverse=True)

        repo_name = self.repo_path.name
        category_scores, overall_score = compute_scores(all_findings)
        elapsed = time.monotonic() - start

        return ScanResults(
            repo_path=self.repo_path,
            repo_name=repo_name,
            files_scanned=len(files),
            findings=all_findings,
            category_scores=category_scores,
            overall_score=overall_score,
            elapsed_seconds=elapsed,
        )
