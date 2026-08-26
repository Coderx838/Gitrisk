"""GitRisk scan command implementation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from rich.console import Console

from gitrisk.core.engine import ScanEngine
from gitrisk.core.models import Severity
from gitrisk.reporters.terminal import TerminalReporter
from gitrisk.reporters.json_reporter import JSONReporter
from gitrisk.reporters.sarif import SARIFReporter

console = Console()


def scan_command(
    path: Path,
    fmt: str = "terminal",
    severity: Optional[str] = None,
    no_color: bool = False,
    output: Optional[Path] = None,
    quiet: bool = False,
    scanners: Optional[str] = None,
) -> None:
    """Run all scanners and report findings."""
    # Parse severity filter
    min_severity: Optional[Severity] = None
    if severity:
        try:
            min_severity = Severity[severity.upper()]
        except KeyError:
            console.print(f"[red]Unknown severity: {severity}[/]. Use CRITICAL, HIGH, MEDIUM, LOW, or INFO.")
            sys.exit(1)

    # Parse scanner filter
    scanner_filter: Optional[list[str]] = None
    if scanners:
        scanner_filter = [s.strip() for s in scanners.split(",")]

    # Run engine
    engine = ScanEngine(repo_path=path)
    results = engine.run(scanner_filter=scanner_filter)

    # Filter by severity
    if min_severity is not None:
        results.findings = [
            f for f in results.findings
            if f.severity.value >= min_severity.value
        ]

    # Choose reporter
    reporter_console = Console(no_color=no_color)
    if fmt == "json":
        reporter = JSONReporter()
    elif fmt == "sarif":
        reporter = SARIFReporter()
    else:
        reporter = TerminalReporter(console=reporter_console, quiet=quiet)

    # Output
    report_text = reporter.render(results)
    if output:
        output.write_text(report_text, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/]")
    else:
        if fmt in ("json", "sarif"):
            print(report_text)
        else:
            pass  # TerminalReporter already printed to console

    # Exit code: non-zero if HIGH or CRITICAL findings
    high_count = sum(1 for f in results.findings if f.severity.value >= Severity.HIGH.value)
    if high_count > 0:
        sys.exit(1)
