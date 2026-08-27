"""Script to write banner.py with pure ASCII art (Windows cp1252 safe)."""
import os

banner_content = '''\
"""GitRisk ASCII banner - pure ASCII art, Windows-safe."""
from __future__ import annotations
import os
from rich.console import Console
from gitrisk import __version__

# Pure ASCII art - cp1252 / legacy Windows console safe
ASCII_ART = [
    r"   ____ _ _   ____  _     _    ",
    r"  / ___(_) |_|  _ \\(_)___| | __",
    r" | |  _| | __| |_) | / __| |/ /",
    r" | |_| | | |_|  _ <| \\__ \\   < ",
    r"  \\____|_|\\__|_| \\_\\_|___/_|\\_\\",
]

BANNER_COLORS = [
    "bold cyan",
    "bold cyan",
    "bold blue",
    "bold blue",
    "bold magenta",
]


def _safe_console() -> Console:
    """Return a Rich Console that works on Windows legacy terminals."""
    return Console(highlight=False)


def print_banner(console: Console | None = None) -> None:
    """Print the full GitRisk v0.2 banner."""
    c = console or _safe_console()
    c.print()
    for line, color in zip(ASCII_ART, BANNER_COLORS):
        c.print(f"[{color}]{line}[/]")
    c.print()
    c.print(
        f"  [bold white]GitRisk[/] [bold cyan]v{__version__}[/]"
        "  [dim]|[/]  [italic]Find the risks in your repo.[/]"
    )
    c.print()
    c.print("  [green bold]>> LOCAL  [/]  All scanning runs on your machine  -  no server, no cloud")
    c.print("  [cyan bold]>> OFFLINE[/]  Works without internet after db update  -  zero latency")
    c.print("  [yellow bold]>> PRIVATE[/]  Zero code upload, zero account  -  your code stays yours")
    c.print("  [red bold]>> FAST   [/]  Sub-second scans on large codebases  -  pure local speed")
    c.print()
    c.print(
        "  [dim]Scan a repo:[/] [cyan]gitrisk scan .[/]  "
        "[dim]Fix issues:[/] [cyan]gitrisk fix .[/]  "
        "[dim]Update DB:[/] [cyan]gitrisk db update[/]"
    )
    c.print()
    c.print("  [dim]License: GPL-3.0-or-later  |  https://github.com/Coderx838/Gitrisk[/]")
    c.print()


def print_version_banner(console: Console | None = None) -> None:
    """Compact banner for --version flag."""
    c = console or _safe_console()
    c.print()
    c.print(r"  [bold cyan]   ____ _ _   ____  _     _    [/]")
    c.print(r"  [bold cyan]  / ___(_) |_|  _ \\(_)___| | __[/]")
    c.print(r"  [bold blue] | |  _| | __| |_) | / __| |/ /[/]")
    c.print(r"  [bold blue] | |_| | | |_|  _ <| \\__ \\   < [/]")
    c.print(r"  [bold magenta]  \\____|_|\\__|_| \\_\\_|___/_|\\_\\[/]")
    c.print()
    c.print(
        f"  [bold white]GitRisk[/] [bold cyan]v{__version__}[/]"
        "  [dim]Privacy-first security scanner for Git repositories[/]"
    )
    c.print("  [dim]License: GPL-3.0-or-later  |  https://github.com/Coderx838/Gitrisk[/]")
    c.print()
'''

with open(r'src\gitrisk\cli\banner.py', 'w', encoding='utf-8') as f:
    f.write(banner_content)

print("banner.py written successfully.")
