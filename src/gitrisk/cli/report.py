"""GitRisk report command."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from gitrisk.core.engine import ScanEngine
from gitrisk.reporters.json_reporter import JSONReporter
from gitrisk.reporters.sarif import SARIFReporter

console = Console()


def report_command(path: Path, output: Path, fmt: str = "json") -> None:
    """Generate a report file."""
    engine = ScanEngine(repo_path=path)
    results = engine.run()

    if fmt == "sarif":
        reporter = SARIFReporter()
    else:
        reporter = JSONReporter()

    text = reporter.render(results)
    output.write_text(text, encoding="utf-8")
    console.print(f"[green]✓ Report written to [bold]{output}[/][/]")
