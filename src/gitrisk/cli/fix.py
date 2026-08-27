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
    """Gather fix proposals from all fixable findings, deduplicating identical fixes."""
    proposals: list[FixProposal] = []
    seen_targets: set[str] = set()

    for f in findings:
        if f.fix_type not in (FixType.AUTO, FixType.ASSISTED):
            continue
        if not f.auto_fix:
            continue

        # Deduplicate identical targets (e.g. multiple CVEs for same package)
        dedup_key = f"{f.scanner}:{f.file}:{f.evidence or f.title}"
        if dedup_key in seen_targets:
            continue
        seen_targets.add(dedup_key)

        proposals.append(FixProposal(
            finding=f,
            summary=f.title,
            diff_lines=[],
            apply_fn=f.auto_fix,
            fix_type=f.fix_type,
        ))
    return proposals


def _supports_unicode() -> bool:
    """Check if stdout can encode emojis and arrows."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "✓→".encode(encoding)
        return True
    except Exception:
        return False


def _print_diff_preview(proposals: list[FixProposal], repo_path: Path) -> None:
    """Print the formatted fix preview."""
    uni = _supports_unicode()
    arrow = "→" if uni else "->"
    check = "✓" if uni else "+"

    console.print()
    console.print(f"  [bold green]{len(proposals)} safe fix(es) available[/]\n")

    for i, prop in enumerate(proposals, 1):
        f = prop.finding
        fix_badge = "[green bold]AUTO[/]" if prop.fix_type == FixType.AUTO else "[yellow bold]ASSISTED[/]"

        if f.evidence and "==" in f.evidence:
            import re
            pkg, ver = f.evidence.split("==", 1)
            target = None
            if f.remediation:
                m = re.search(r">=\s*([0-9A-Za-z\.\-_]+)", f.remediation)
                if m:
                    target = m.group(1)
            target = target or "latest"
            console.print(f"  [bold cyan][{i}][/] {fix_badge} [bold white]{pkg}[/]")
            console.print(f"      [red]{ver}[/] {arrow} [green]{target}[/]")
            if f.file:
                console.print(f"      File: [dim]{f.file.name}[/]")
            console.print(f"      [dim]{check} Safe dependency update[/]")
        else:
            console.print(f"  [bold cyan][{i}][/] {fix_badge} [bold white]{prop.summary}[/]")
            if f.file:
                console.print(f"      File: [dim]{f.file.name}[/]")
            if f.remediation:
                first_line = f.remediation.strip().splitlines()[0]
                console.print(f"      [dim]{first_line}[/]")
        console.print()


def fix_command(
    path: Path,
    dry_run: bool = False,
    yes: bool = False,
    level: str = "ALL",
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

    # Filter by requested level if explicitly provided
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

    uni = _supports_unicode()
    dash = "—" if uni else "-"
    check = "✓" if uni else "[OK]"
    fail = "✗" if uni else "[FAIL]"

    if dry_run:
        console.print(f"[dim]Dry run complete {dash} no changes were applied.[/]")
        console.print()
        return

    # Confirm
    if not yes:
        apply = Confirm.ask("Apply these fixes?", default=True)
        if not apply:
            console.print("[dim]No changes applied.[/]")
            return

    # Apply
    applied = 0
    failed = 0
    console.print()
    for prop in proposals:
        try:
            if prop.apply_fn:
                prop.apply_fn(path)
                console.print(f"  [green]{check}[/] Applied: {prop.summary}")
                applied += 1
        except Exception as e:
            console.print(f"  [red]{fail}[/] Failed: {prop.summary} ({e})")
            failed += 1

    console.print()
    console.print(f"[green bold]{applied} fix(es) successfully applied[/]"
                  + (f"  [red]{failed} failed[/]" if failed else ""))

    # Remind about manual items
    manual = [f for f in results.findings if f.fix_type == FixType.MANUAL]
    if manual:
        console.print(f"\n[yellow]{len(manual)} issue(s) still require manual action (secrets rotation, etc.)[/]")
        console.print("[dim]Run [bold]gitrisk scan .[/bold] to see full details.[/dim]")
    console.print()
