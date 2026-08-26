"""Outdated dependencies scanner — finds packages significantly behind current versions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a tuple for comparison."""
    try:
        return tuple(int(x) for x in re.findall(r"\d+", v)[:3])
    except Exception:
        return (0, 0, 0)


def _get_pypi_latest(package: str) -> Optional[str]:
    """Fetch the latest version of a PyPI package (requires internet)."""
    try:
        import urllib.request
        url = f"https://pypi.org/pypi/{package}/json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            return data["info"]["version"]
    except Exception:
        return None


class OutdatedDepsScanner(BaseScanner):
    """Scanner 8: Find packages significantly behind the latest published version."""

    name = "outdated"
    description = "Identifies dependencies that are significantly out of date."
    category = "dependencies"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        requirements_files = list(self.repo_path.rglob("requirements*.txt"))

        for req_file in requirements_files:
            try:
                content = req_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", "http", "git+")):
                    continue
                m = re.match(r"^([A-Za-z0-9_\-\.]+)==([A-Za-z0-9\.\-_]+)", line)
                if not m:
                    continue
                pkg, pinned_ver = m.group(1), m.group(2)
                latest = _get_pypi_latest(pkg)
                if not latest:
                    continue

                pinned_tuple = _parse_version(pinned_ver)
                latest_tuple = _parse_version(latest)

                # Flag if major version is behind
                if latest_tuple[0] > pinned_tuple[0]:
                    findings.append(Finding(
                        id="OUT-001",
                        scanner=self.name,
                        title=f"Outdated dependency: {pkg} (pinned {pinned_ver}, latest {latest})",
                        description=(
                            f"`{pkg}` is pinned at `{pinned_ver}` but the latest version is `{latest}`. "
                            f"This is a major version behind. Older versions may miss security patches and "
                            f"new features. Keeping dependencies up to date reduces the attack surface."
                        ),
                        severity=Severity.MEDIUM,
                        fix_type=FixType.REVIEW,
                        remediation=(
                            f"Update {pkg} in your requirements file:\n"
                            f"  {pkg}>={latest}\n"
                            f"Then run: pip install -r {req_file.name} --upgrade"
                        ),
                        file=req_file,
                        evidence=f"{pkg}=={pinned_ver} -> {latest}",
                        references=[f"https://pypi.org/project/{pkg}/"],
                    ))
                elif latest_tuple[:2] > pinned_tuple[:2]:
                    # Minor version behind
                    findings.append(Finding(
                        id="OUT-002",
                        scanner=self.name,
                        title=f"Outdated dependency: {pkg} (minor version behind)",
                        description=(
                            f"`{pkg}` is at `{pinned_ver}`, latest is `{latest}` (minor version ahead). "
                            f"Consider upgrading to get bug fixes and security patches."
                        ),
                        severity=Severity.LOW,
                        fix_type=FixType.REVIEW,
                        remediation=f"Update to `{pkg}>={latest}` in your requirements file.",
                        file=req_file,
                        evidence=f"{pkg}=={pinned_ver} -> {latest}",
                        references=[f"https://pypi.org/project/{pkg}/"],
                    ))

        return findings
