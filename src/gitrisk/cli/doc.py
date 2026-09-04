"""GitRisk doc command implementation."""

from __future__ import annotations
import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.text import Text
from rich import box

from gitrisk.rulebook.rules import RULES, RuleDoc
from gitrisk.core.models import Severity

console = Console()

def get_severity_color(sev: str) -> str:
    try:
        severity = Severity[sev.upper()]
        return severity.color
    except KeyError:
        return "white"

def list_all_rules() -> None:
    """List all available rule IDs grouped by category."""
    table = Table(title="GitRisk Rule Knowledge Base", box=box.ROUNDED, show_lines=True)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Category", style="magenta")
    table.add_column("Title")

    # Group by category
    categories = {}
    for rule in RULES.values():
        categories.setdefault(rule.category, []).append(rule)

    for cat in sorted(categories.keys()):
        for rule in sorted(categories[cat], key=lambda r: r.rule_id):
            color = get_severity_color(rule.severity)
            sev_text = f"[{color}]{rule.severity}[/{color}]"
            table.add_row(rule.rule_id, sev_text, rule.category, rule.title)

    console.print(table)
    console.print("\nRun [bold cyan]gitrisk doc <RULE_ID>[/] for details on a specific rule.")


def search_rules(keyword: str) -> None:
    """Fuzzy-search rules by keyword in title/description."""
    keyword_lower = keyword.lower()
    matches = []
    
    for rule in RULES.values():
        if keyword_lower in rule.title.lower() or keyword_lower in rule.description.lower() or keyword_lower in rule.rule_id.lower():
            matches.append(rule)

    if not matches:
        console.print(f"[red]No rules found matching '{keyword}'[/]")
        return

    table = Table(title=f"Search Results for '{keyword}'", box=box.ROUNDED)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("Title")

    for rule in sorted(matches, key=lambda r: r.rule_id):
        color = get_severity_color(rule.severity)
        sev_text = f"[{color}]{rule.severity}[/{color}]"
        table.add_row(rule.rule_id, sev_text, rule.title)

    console.print(table)


def doc_command(rule_id: str, search: Optional[str] = None, list_all: bool = False) -> None:
    """Look up detailed documentation for a GitRisk finding code."""
    if list_all:
        list_all_rules()
        return

    if search:
        search_rules(search)
        return

    if not rule_id:
        console.print("[red]Error: You must provide a RULE_ID, --search, or --list.[/]")
        sys.exit(1)

    rule_id_upper = rule_id.upper()
    rule = RULES.get(rule_id_upper)

    if not rule:
        console.print(f"[red]Rule '{rule_id}' not found.[/]")
        
        # Suggest categories
        categories = sorted(list(set(r.category for r in RULES.values())))
        console.print(f"\nAvailable categories: {', '.join(categories)}")
        console.print("Run [bold cyan]gitrisk doc --list[/] to see all rules.")
        return

    # Render Rule Document
    color = get_severity_color(rule.severity)
    
    # Header
    header = f"[{color} bold]{rule.severity}[/] | [magenta]{rule.category}[/]"
    console.print(Panel(f"[bold white]{rule.title}[/]\n{header}", title=f"[bold cyan]{rule.rule_id}[/]", border_style="cyan"))
    
    # Description
    console.print("\n[bold]Description[/]")
    console.print(rule.description)

    # Impact
    console.print("\n[bold]Impact[/]")
    console.print(rule.impact)

    # References Table
    if rule.cwe or rule.owasp:
        ref_table = Table(show_header=False, box=None, padding=(0, 2))
        if rule.cwe:
            ref_table.add_row("[bold cyan]CWE[/]", ", ".join(rule.cwe))
        if rule.owasp:
            ref_table.add_row("[bold cyan]OWASP[/]", ", ".join(rule.owasp))
        console.print("\n[bold]Classification[/]")
        console.print(ref_table)

    # Remediation
    console.print("\n[bold]Remediation Steps[/]")
    for i, step in enumerate(rule.remediation, 1):
        console.print(f"  {i}. {step}")

    # Examples
    if rule.examples:
        console.print("\n[bold]Examples[/]")
        if "bad" in rule.examples:
            console.print(Panel(rule.examples["bad"], title="[red]Vulnerable Code[/]", border_style="red"))
        if "good" in rule.examples:
            console.print(Panel(rule.examples["good"], title="[green]Secure Code[/]", border_style="green"))

    # External References
    if rule.references:
        console.print("\n[bold]External References[/]")
        for ref in rule.references:
            console.print(f"  • [link={ref}]{ref}[/link]")

    # Footer
    console.print("\n[dim]Run `gitrisk scan .` to check your repository[/dim]")
