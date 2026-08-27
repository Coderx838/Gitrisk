"""Security files auto-fixer — creates SECURITY.md, dependabot.yml, etc."""
from __future__ import annotations
from pathlib import Path

SECURITY_MD_TEMPLATE = """
# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | YES       |

## Reporting a Vulnerability

Please report security vulnerabilities via [GitHub Security Advisories](
https://github.com/OWNER/REPO/security/advisories/new).

**Do NOT open a public GitHub Issue for security vulnerabilities.**

We aim to respond within 72 hours and provide a fix within 14 days for critical issues.

## Privacy Guarantee

This project does not collect or transmit any user data.
""".strip()

DEPENDABOT_TEMPLATE = """
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
""".strip()


class SecurityFilesFixer:
    """Creates SECURITY.md or .github/dependabot.yml."""

    def __init__(self, target: str = "SECURITY.md") -> None:
        self.target = target

    def apply(self, repo_path: Path) -> None:
        if self.target == "SECURITY.md":
            dest = repo_path / "SECURITY.md"
            if not dest.exists():
                dest.write_text(SECURITY_MD_TEMPLATE, encoding="utf-8")
        elif self.target == "dependabot.yml":
            dest = repo_path / ".github" / "dependabot.yml"
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not dest.exists():
                dest.write_text(DEPENDABOT_TEMPLATE, encoding="utf-8")
