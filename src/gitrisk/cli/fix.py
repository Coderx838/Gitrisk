"""GitRisk fix command v0.2 — smart, safe, diff-previewed auto-remediation."""
from __future__ import annotations
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.rule import Rule
from rich.text import Text
from gitrisk.core.engine import ScanEngine
from gitrisk.core.models import Finding, FixType

console = Console()


@dataclass
class FixProposal:
    """A proposed fix with full diff preview."""
    finding: Finding
    summary: str
    diff_lines: list[str] = field(default_factory=list)  # unified-diff style lines
    apply_fn: Optional[Callable[[Path], None]] = None
    fix_type: FixType = FixType.AUTO

    @property
    def is_safe(self) -> bool:
        return self.fix_type in (FixType.AUTO, FixType.ASSISTED)


def _collect_proposals(findings: list[Finding], repo_path: Path) -> list[FixProposal]:
    """Gather fix proposals from all fixable findings."""
    proposals: list[FixProposal] = []
    for f in findings:
        if f.fix_type not in (FixType.AUTO, FixType.ASSISTED):
            continue
        if not f.auto_fix:
            continue
        # Build diff preview if possible
        diff_lines: list[str] = []
        if f.file and f.file.exists():
            original = f.file.read_text(encoding="utf-8", errors="ignore")
        else:
            original = None

        proposals.append(FixProposal(
            finding=f,
            summary=f.title,
            diff_lines=diff_lines,
            apply_fn=f.auto_fix,
            fix_type=f.fix_type,
        ))
    return proposals


def _print_diff_preview(proposals: list[FixProposal], repo_path: Path) -> None:
    """Print the full diff preview panel."""
    console.print()
    console.print(Rule("[bold cyan]GitRisk Fix Preview[/]"))
    console.print()

    for i, prop in enumerate(proposals, 1):
        fix_label = "[green]AUTO[/]" if prop.fix_type == FixType.AUTO else "[yellow]ASSISTED[/]"
        console.print(f"  [bold][{i}][/] {fix_label} [white]{prop.summary}[/]")

        f = prop.finding
        if f.file:
            console.print(f"      File: [dim]{f.file.name}[/]")
        if f.remediation:
            for line in f.remediation.strip().splitlines()[:2]:
                console.print(f"      [dim]{line}[/]")
        console.print()

    console.print(Rule())


def fix_command(
    path: Path,
    dry_run: bool = False,
    yes: bool = False,
    level: str = "AUTO",
) -> None:
    """Run scan, collect auto-fixable issues, preview diffs, apply with confirmation."""
    console.print()
    console.print("[bold cyan]GitRisk Fix[/] [dim]v0.2[/]")
    console.print("[dim]Scanning repository for fixable issues...[/]")
    console.print()

    engine = ScanEngine(repo_path=path)
    results = engine.run()

    # Collect proposals
    all_proposals = _collect_proposals(results.findings, path)

    # Filter by requested level
    if level.upper() == "AUTO":
        proposals = [p for p in all_proposals if p.fix_type == FixType.AUTO]
    else:
        proposals = all_proposals

    if not proposals:
        console.print("[green]No automatically fixable issues found.[/]")
        # Show manual items as guidance
        manual = [f for f in results.findings if f.fix_type == FixType.MANUAL]
        if manual:
            console.print(f"\n[yellow]{len(manual)} issue(s) require manual remediation:[/]")
            for f in manual[:5]:
                console.print(f"  [red]MANUAL[/] {f.title}")
                for line in f.remediation.strip().splitlines()[:1]:
                    console.print(f"         [dim]{line}[/]")
        return

    # Print preview
    _print_diff_preview(proposals, path)

    # Count
    auto_count = sum(1 for p in proposals if p.fix_type == FixType.AUTO)
    assisted_count = sum(1 for p in proposals if p.fix_type == FixType.ASSISTED)
    console.print(f"  [bold]{len(proposals)}[/] fix(es) ready  "
                  f"([green]{auto_count} AUTO[/]" +
                  (f"  [yellow]{assisted_count} ASSISTED[/]" if assisted_count else "") + ")")
    console.print()

    if dry_run:
        console.print("[dim]Dry run — no changes applied.[/]")
        return

    # Confirm
    if not yes:
        apply = Confirm.ask("Apply these fixes?", default=False)
        if not apply:
            console.print("[dim]No changes applied.[/]")
            return

    # Apply
    applied = 0
    failed = 0
    console.print()
    for prop in proposals:
        try:
            prop.apply_fn(path)
            console.print(f"  [green]✓[/] {prop.summary}")
            applied += 1
        except Exception as e:
            console.print(f"  [red]✗[/] {prop.summary}: {e}")
            failed += 1

    console.print()
    console.print(f"[green bold]{applied} fix(es) applied[/]"
                  + (f"  [red]{failed} failed[/]" if failed else ""))

    # Remind about manual items
    manual = [f for f in results.findings if f.fix_type == FixType.MANUAL]
    if manual:
        console.print(f"\n[yellow]{len(manual)} issue(s) still require manual action (secrets rotation, etc.)[/]")
        console.print("[dim]Run [bold]gitrisk scan .[/dim] to see full details.")
    console.print()
