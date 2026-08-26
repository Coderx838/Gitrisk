"""GitRisk CLI — entry point."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from gitrisk import __version__
from gitrisk.cli.scan import scan_command
from gitrisk.cli.db import db_app
from gitrisk.cli.fix import fix_command
from gitrisk.cli.report import report_command

console = Console()

app = typer.Typer(
    name="gitrisk",
    help="🔍 GitRisk — Find the risks in your repo.",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

app.add_typer(db_app, name="db")


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]GitRisk[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """GitRisk — privacy-first, local-first security scanner for Git repositories."""


@app.command("scan")
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the Git repository to scan.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    format: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help="Output format: terminal, json, sarif.",
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO.",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable colored output.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write output to file instead of stdout.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Only print findings, no banner or summary.",
    ),
    scanners: Optional[str] = typer.Option(
        None,
        "--scanners",
        help="Comma-separated list of scanners to run (default: all).",
    ),
) -> None:
    """Scan a Git repository for security risks and health issues."""
    scan_command(
        path=path,
        fmt=format,
        severity=severity,
        no_color=no_color,
        output=output,
        quiet=quiet,
        scanners=scanners,
    )


@app.command("fix")
def fix(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the Git repository.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    interactive: bool = typer.Option(
        True,
        "--interactive/--auto",
        help="Interactively confirm each fix (default) or apply all SAFE fixes automatically.",
    ),
) -> None:
    """Apply safe remediations to findings."""
    fix_command(path=path, interactive=interactive)


@app.command("report")
def report(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the Git repository.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("gitrisk-report.json"),
        "--output",
        "-o",
        help="Output file path.",
    ),
    format: str = typer.Option(
        "json",
        "--format",
        "-f",
        help="Report format: json, sarif.",
    ),
) -> None:
    """Generate a report file from a scan."""
    report_command(path=path, output=output, fmt=format)


if __name__ == "__main__":
    app()
