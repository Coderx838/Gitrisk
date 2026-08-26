"""GitRisk fix command."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from gitrisk.core.engine import ScanEngine
from gitrisk.core.models import FixType

console = Console()


def fix_command(path: Path, interactive: bool = True) -> None:
    """Apply safe remediations interactively or automatically."""
    engine = ScanEngine(repo_path=path)
    results = engine.run()

    safe_findings = [f for f in results.findings if f.fix_type == FixType.SAFE]

    if not safe_findings:
        console.print("[green]No automatically fixable issues found.[/]")
        return

    console.print(f"Found [bold]{len(safe_findings)}[/] automatically fixable issue(s).\n")

    applied = 0
    for finding in safe_findings:
        console.print(f"[bold]{finding.title}[/]")
        console.print(f"  {finding.remediation}")

        if interactive:
            apply = Confirm.ask("  Apply this fix?", default=True)
        else:
            apply = True

        if apply and finding.auto_fix:
            try:
                finding.auto_fix(path)
                console.print("  [green]✓ Applied[/]")
                applied += 1
            except Exception as e:
                console.print(f"  [red]✗ Failed: {e}[/]")
        elif not finding.auto_fix:
            console.print("  [yellow]No auto-fix available for this finding.[/]")

    console.print(f"\n[green]Applied {applied} fix(es).[/]")
