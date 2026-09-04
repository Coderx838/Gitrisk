"""GitRisk CLI entry point."""
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
from gitrisk.cli.doc import doc_command
from gitrisk.cli.banner import print_banner, print_version_banner

console = Console()

app = typer.Typer(
    name="gitrisk",
    help="[bold cyan]GitRisk[/] [dim]v" + __version__ + "[/] — Find the risks in your repo.",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=False,
    invoke_without_command=True,
)

app.add_typer(db_app, name="db")


def version_callback(value: bool) -> None:
    if value:
        print_version_banner()
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context = typer.Option(None, hidden=True),
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
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("  Run [bold cyan]gitrisk scan .[/] to scan the current directory.")
        console.print("  Run [bold cyan]gitrisk --help[/] for all commands.")
        console.print()


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
    format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal, json, sarif."),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write output to file."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print findings."),
    scanners: Optional[str] = typer.Option(None, "--scanners", help="Comma-separated scanners to run."),
) -> None:
    """Scan a Git repository for security risks and health issues."""
    scan_command(path=path, fmt=format, severity=severity, no_color=no_color, output=output, quiet=quiet, scanners=scanners)


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
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Preview fixes without applying them."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Apply all safe fixes without confirmation (CI mode)."),
    level: str = typer.Option("ALL", "--level", "-l", help="Fix level to apply: ALL, AUTO, or ASSISTED."),
) -> None:
    """Preview and apply safe remediations with diff preview."""
    fix_command(path=path, dry_run=dry_run, yes=yes, level=level)


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
    output: Path = typer.Option(Path("gitrisk-report.json"), "--output", "-o", help="Output file path."),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json, sarif."),
) -> None:
    """Generate a report file from a scan."""
    report_command(path=path, output=output, fmt=format)


@app.command("doc")
def doc(
    rule_id: str = typer.Argument(None, help="Rule ID to look up, e.g. HRD-001 or SEC-020"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search rule descriptions by keyword"),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available rule IDs"),
) -> None:
    """Look up detailed documentation for a GitRisk finding code (e.g. gitrisk doc HRD-001)."""
    doc_command(rule_id=rule_id, search=search, list_all=list_all)



if __name__ == "__main__":
    app()
