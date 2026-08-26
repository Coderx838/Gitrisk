"""Security policy scanner — checks for SECURITY.md and code of conduct."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

SECURITY_MD_TEMPLATE = """
# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| x.x.x   | :white_check_mark: |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a GitHub Security Advisory.
Do NOT open a public GitHub Issue for security vulnerabilities.

We aim to respond within 72 hours and provide a fix within 14 days for critical issues.
""".strip()


class SecurityPolicyScanner(BaseScanner):
    """Scanner 9: Check for security policy and project metadata."""

    name = "security_policy"
    description = "Checks for SECURITY.md, README.md, and other project health files."
    category = "policy"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check for SECURITY.md
        security_md_locations = [
            self.repo_path / "SECURITY.md",
            self.repo_path / ".github" / "SECURITY.md",
            self.repo_path / "docs" / "SECURITY.md",
        ]
        has_security_md = any(p.exists() for p in security_md_locations)

        if not has_security_md:
            findings.append(Finding(
                id="POL-001",
                scanner=self.name,
                title="No SECURITY.md found",
                description=(
                    "This repository has no SECURITY.md file. Without a security policy, "
                    "security researchers and users don't know how to report vulnerabilities responsibly. "
                    "GitHub also highlights repositories with a security policy in its security features."
                ),
                severity=Severity.LOW,
                fix_type=FixType.SAFE,
                remediation="Create a SECURITY.md file at the repository root describing your security policy and how to report vulnerabilities.",
                references=[
                    "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
                ],
                auto_fix=self._create_security_md,
            ))

        # Check for README
        readme_locations = [
            self.repo_path / "README.md",
            self.repo_path / "README.rst",
            self.repo_path / "README.txt",
            self.repo_path / "README",
        ]
        has_readme = any(p.exists() for p in readme_locations)
        if not has_readme:
            findings.append(Finding(
                id="POL-002",
                scanner=self.name,
                title="No README file found",
                description=(
                    "This repository has no README. A README helps contributors understand the project, "
                    "its purpose, and how to use it safely."
                ),
                severity=Severity.INFO,
                fix_type=FixType.MANUAL,
                remediation="Create a README.md describing the project's purpose, installation, usage, and contributing guidelines.",
            ))

        # Check for CONTRIBUTING.md
        contributing_path = self.repo_path / "CONTRIBUTING.md"
        if not contributing_path.exists() and (self.repo_path / ".github").exists():
            findings.append(Finding(
                id="POL-003",
                scanner=self.name,
                title="No CONTRIBUTING.md found",
                description="No CONTRIBUTING.md was found. A contributing guide helps new contributors understand how to participate safely.",
                severity=Severity.INFO,
                fix_type=FixType.MANUAL,
                remediation="Create a CONTRIBUTING.md describing contribution guidelines, code style, and PR process.",
            ))

        return findings

    def _create_security_md(self, repo_path: Path) -> None:
        """Auto-fix: create a SECURITY.md template."""
        (repo_path / "SECURITY.md").write_text(SECURITY_MD_TEMPLATE, encoding="utf-8")
