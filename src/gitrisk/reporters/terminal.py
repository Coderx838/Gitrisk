"""Terminal reporter — rich, human-readable terminal output."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from gitrisk import __version__
from gitrisk.core.models import ScanResults, Severity, Finding


class TerminalReporter:
    """Render scan results to the terminal using Rich."""

    def __init__(self, console: Console | None = None, quiet: bool = False) -> None:
        self.console = console or Console()
        self.quiet = quiet

    def render(self, results: ScanResults) -> str:
        """Render scan results to the terminal and return empty string (side-effect output)."""
        if not self.quiet:
            self._print_banner(results)
        self._print_findings(results)
        if not self.quiet:
            self._print_summary(results)
        return ""

    def _print_banner(self, results: ScanResults) -> None:
        self.console.print()
        self.console.print(
            Panel(
                Text.from_markup(
                    f"[bold cyan]GitRisk[/] [dim]v{__version__}[/]\n"
                    f"[bold]Repository:[/] {results.repo_name}\n"
                    f"[bold]Path:[/]       {results.repo_path}\n"
                    f"[bold]Files:[/]      {results.files_scanned:,} scanned\n"
                    f"[bold]Scanned:[/]    {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                ),
                title="[cyan]>> GitRisk Scan[/]",
                border_style="cyan",
                expand=False,
            )
        )
        self.console.print()

    def _print_findings(self, results: ScanResults) -> None:
        if not results.findings:
            self.console.print("[green bold]✓ No findings. Repository looks clean![/]")
            return

        table = Table(
            show_header=True,
            header_style="bold",
            box=box.ROUNDED,
            expand=True,
            show_lines=False,
        )
        table.add_column("Sev", width=6, no_wrap=True)
        table.add_column("ID", width=10, no_wrap=True)
        table.add_column("Finding", ratio=3)
        table.add_column("Location", ratio=2)
        table.add_column("Fix", width=8, no_wrap=True)

        for finding in results.findings:
            sev_text = Text(finding.severity.label, style=finding.severity.color)
            loc_parts = []
            if finding.file:
                loc_parts.append(str(finding.file.name))
                if finding.line:
                    loc_parts.append(f":{finding.line}")
            location = "".join(loc_parts) if loc_parts else "-"

            fix_color = {"SAFE": "green", "REVIEW": "yellow", "MANUAL": "red"}.get(finding.fix_type.value, "white")
            fix_text = Text(finding.fix_type.value, style=fix_color)

            table.add_row(
                sev_text,
                finding.id,
                finding.title,
                location,
                fix_text,
            )

        self.console.print(table)
        self.console.print()

    def _print_summary(self, results: ScanResults) -> None:
        # Score panel
        score = results.overall_score
        if score >= 80:
            score_style = "green bold"
        elif score >= 60:
            score_style = "yellow bold"
        else:
            score_style = "red bold"

        score_lines = [f"[{score_style}]GITRISK SCORE: {score}/100[/]\n"]
        for cs in sorted(results.category_scores, key=lambda c: c.name):
            bar_width = cs.score // 5  # 0-20 chars
            bar = "█" * bar_width + "░" * (20 - bar_width)
            cs_style = "green" if cs.score >= 80 else ("yellow" if cs.score >= 60 else "red")
            score_lines.append(f"  [bold]{cs.name:<14}[/] [{cs_style}]{cs.score:>3}/100[/]  [dim]{bar}[/]")

        self.console.print(
            Panel(
                Text.from_markup("\n".join(score_lines)),
                title="📊 Score",
                border_style=score_style.split()[0],
                expand=False,
            )
        )

        # Finding counts
        self.console.print()
        total = len(results.findings)
        critical = results.critical_count
        high = results.high_count
        medium = results.medium_count
        low = results.low_count

        parts = []
        if critical:
            parts.append(f"[bold red]{critical} critical[/]")
        if high:
            parts.append(f"[red]{high} high[/]")
        if medium:
            parts.append(f"[yellow]{medium} medium[/]")
        if low:
            parts.append(f"[green]{low} low[/]")

        if parts:
            summary = " · ".join(parts)
            self.console.print(f"  {total} finding(s): {summary}")
        else:
            self.console.print(f"  [green]✓ {total} findings[/]")

        # Safe fixes available
        safe_count = sum(1 for f in results.findings if f.fix_type.value == "SAFE")
        if safe_count:
            self.console.print(f"  [green]{safe_count} fix(es) can be applied automatically[/] — run [bold]gitrisk fix .[/]")

        elapsed = results.elapsed_seconds
        self.console.print(f"  [dim]Completed in {elapsed:.2f}s[/]")
        self.console.print()