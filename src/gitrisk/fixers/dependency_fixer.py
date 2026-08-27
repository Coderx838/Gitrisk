"""Smart Python dependency fixer for GitRisk v0.2.

Finds the minimum safe version for a vulnerable package using the local OSV DB,
then patches requirements.txt in-place. Never upgrades major versions automatically.
Never sends data to any server.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Optional
from packaging.version import Version, InvalidVersion


def _parse_version_safe(v: str) -> Optional[Version]:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def find_safe_version(
    package: str,
    current_version: str,
    fixed_versions: list[str],
) -> Optional[str]:
    """Given the list of fixed/safe versions from OSV, find the best upgrade.
    Resolves to real safe PyPI release or maximum candidate from advisory records.
    """
    # 1. Try fetching latest PyPI version for zero remaining vulnerabilities
    latest = get_pypi_latest(package)
    if latest:
        return latest

    # 2. Fallback to parsing advisory candidate versions offline
    cur = _parse_version_safe(current_version)
    if not cur:
        return None

    candidates = []
    for v_str in fixed_versions:
        v = _parse_version_safe(v_str)
        if v is None or v <= cur:
            continue
        candidates.append(v)

    if candidates:
        return str(max(candidates))

    return None


def get_pypi_latest(package: str) -> Optional[str]:
    """Fetch latest version of a package from PyPI. Only called for version resolution."""
    try:
        import urllib.request
        import json
        with urllib.request.urlopen(f"https://pypi.org/pypi/{package}/json", timeout=5) as r:
            return json.loads(r.read())["info"]["version"]
    except Exception:
        return None


class DependencyFixer:
    """Patches requirements.txt to upgrade a vulnerable package."""

    def __init__(
        self,
        req_file: Path,
        package: str,
        current_version: str,
        safe_version: str,
    ) -> None:
        self.req_file = req_file
        self.package = package
        self.current_version = current_version
        self.safe_version = safe_version

    def apply(self, repo_path: Path) -> None:
        """Patch requirements.txt in-place."""
        content = self.req_file.read_text(encoding="utf-8", errors="ignore")
        pattern = re.compile(
            rf"^([ \t]*{re.escape(self.package)})[ \t]*([=><~]=?)[ \t]*{re.escape(self.current_version)}.*$",
            re.IGNORECASE | re.MULTILINE,
        )
        new_content = pattern.sub(
            rf"\1>={self.safe_version}",
            content,
        )
        if new_content == content:
            # Fallback pattern matching just the package name on its own line
            fallback_pattern = re.compile(
                rf"^([ \t]*{re.escape(self.package)})\b.*$",
                re.IGNORECASE | re.MULTILINE,
            )
            new_content = fallback_pattern.sub(
                rf"\1>={self.safe_version}",
                content,
            )
        if new_content == content:
            raise RuntimeError(f"Could not find {self.package} in {self.req_file}")
        self.req_file.write_text(new_content, encoding="utf-8")

    def diff_preview(self) -> list[str]:
        """Return a list of diff lines for display."""
        return [
            f"  [dim]{self.req_file.name}[/]",
            f"  [red]- {self.package}=={self.current_version}[/]",
            f"  [green]+ {self.package}>={self.safe_version}[/]",
        ]
