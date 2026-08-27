"""GitIgnore scanner — checks for missing or weak .gitignore rules."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Essential patterns every repo should ignore
ESSENTIAL_PATTERNS = [
    ".env",
    "*.pyc",
    "__pycache__",
    "node_modules",
    ".DS_Store",
    "*.log",
    "*.key",
    "*.pem",
]

SECRET_PATTERNS = [
    ".env",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
]


class GitIgnoreScanner(BaseScanner):
    """Scanner 5: Detect missing or weak .gitignore configuration."""

    name = "gitignore"
    description = "Checks for missing or insufficient .gitignore rules."
    category = "git"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        gitignore_path = self.repo_path / ".gitignore"

        if not gitignore_path.exists():
            findings.append(Finding(
                id="GIT-001",
                scanner=self.name,
                title="No .gitignore file found",
                description=(
                    "This repository has no .gitignore file. Without a .gitignore, common "
                    "sensitive files (.env, private keys, IDE configs, build artifacts) may "
                    "be accidentally committed."
                ),
                severity=Severity.MEDIUM,
                fix_type=FixType.AUTO,
                remediation=(
                    "Create a .gitignore file appropriate for your project's language and framework.\n"
                    "Use gitignore.io or GitHub's template collection as a starting point."
                ),
                references=[
                    "https://www.toptal.com/developers/gitignore",
                    "https://github.com/github/gitignore",
                ],
                auto_fix=self._generate_gitignore,
            ))
            return findings

        content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
        missing_secrets = [p for p in SECRET_PATTERNS if p not in content]

        if missing_secrets:
            findings.append(Finding(
                id="GIT-002",
                scanner=self.name,
                title=".gitignore is missing critical security patterns",
                description=(
                    f"The .gitignore file is missing patterns for sensitive file types: "
                    f"{', '.join(missing_secrets)}. These file types can contain private keys, "
                    f"certificates, or other credentials that should never be committed."
                ),
                severity=Severity.LOW,
                fix_type=FixType.AUTO,
                remediation=(
                    f"Add the following to .gitignore:\n"
                    + "\n".join(missing_secrets)
                ),
                file=gitignore_path,
                evidence="Missing: " + ", ".join(missing_secrets),
                references=["https://www.toptal.com/developers/gitignore"],
                auto_fix=lambda rp: self._add_missing_patterns(rp, missing_secrets),
            ))

        return findings

    def _generate_gitignore(self, repo_path: Path) -> None:
        """Generate a basic .gitignore."""
        content = """# GitRisk generated .gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
.venv/
venv/

# Node
node_modules/

# Secrets & credentials
.env
.env.*
!.env.example
*.key
*.pem
*.p12
*.pfx
*.crt
*.cer
credentials.json

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db

# IDE
.idea/
.vscode/
*.suo
*.user
"""
        (repo_path / ".gitignore").write_text(content, encoding="utf-8")

    def _add_missing_patterns(self, repo_path: Path, patterns: list[str]) -> None:
        """Append missing patterns to existing .gitignore."""
        gi = repo_path / ".gitignore"
        with gi.open("a", encoding="utf-8") as f:
            f.write("\n# GitRisk: added missing security patterns\n")
            for p in patterns:
                f.write(f"{p}\n")
