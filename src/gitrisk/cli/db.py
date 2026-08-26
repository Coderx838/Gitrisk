"""GitRisk db sub-commands."""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console

from gitrisk.database.manager import DatabaseManager

db_app = typer.Typer(
    name="db",
    help="Manage the local vulnerability database.",
    no_args_is_help=True,
)

console = Console()


@db_app.command("update")
def db_update(
    ecosystem: Optional[str] = typer.Option(
        None,
        "--ecosystem",
        "-e",
        help="Update only a specific ecosystem (e.g. PyPI, npm). Default: all.",
    ),
) -> None:
    """Download or update the local OSV vulnerability database."""
    mgr = DatabaseManager()
    console.print("[cyan]Updating local vulnerability database...[/]")
    console.print("[dim]Only public OSV data is downloaded. No repository data is sent.[/]")
    mgr.update(ecosystem=ecosystem)
    console.print("[green]✓ Database updated successfully.[/]")


@db_app.command("status")
def db_status() -> None:
    """Show status of the local vulnerability database."""
    mgr = DatabaseManager()
    info = mgr.status()
    if info["exists"]:
        console.print(f"[bold]Local DB:[/] {info['path']}")
        console.print(f"[bold]Updated:[/]  {info['updated_at']}")
        console.print(f"[bold]Records:[/]  {info['record_count']:,}")
    else:
        console.print("[yellow]No local vulnerability database found.[/]")
        console.print("Run [bold cyan]gitrisk db update[/] to download it.")
