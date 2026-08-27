"""Env file scanner — detects .env and similar sensitive files tracked by Git."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Files that should never be committed
SENSITIVE_ENV_PATTERNS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.test",
    ".envrc",
]


def _is_tracked_by_git(repo_path: Path, file_path: Path) -> bool:
    """Check if a file is tracked by Git."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", str(file_path)],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def _add_to_gitignore(repo_path: Path) -> None:
    """Auto-fix: add .env patterns to .gitignore."""
    gitignore = repo_path / ".gitignore"
    to_add = [p for p in SENSITIVE_ENV_PATTERNS]
    if gitignore.exists():
        existing = gitignore.read_text(encoding="utf-8")
        to_add = [p for p in to_add if p not in existing]
    if to_add:
        with gitignore.open("a", encoding="utf-8") as f:
            f.write("\n# GitRisk: sensitive env files\n")
            for p in to_add:
                f.write(f"{p}\n")


class EnvFileScanner(BaseScanner):
    """Scanner 3: Detect .env files committed to Git."""

    name = "env"
    description = "Detects sensitive environment files tracked by Git."
    category = "configuration"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in SENSITIVE_ENV_PATTERNS:
            for env_file in self.repo_path.rglob(pattern):
                if not env_file.is_file():
                    continue
                # Check if actually tracked by Git
                if not _is_tracked_by_git(self.repo_path, env_file):
                    continue
                findings.append(Finding(
                    id="ENV-001",
                    scanner=self.name,
                    title=f"Environment file tracked by Git: {self._rel(env_file)}",
                    description=(
                        f"`{self._rel(env_file)}` is tracked by Git. Environment files often contain "
                        f"API keys, database credentials, and other secrets. Once committed, these "
                        f"values are part of the repository history even if the file is later deleted."
                    ),
                    severity=Severity.HIGH,
                    fix_type=FixType.AUTO,
                    remediation=(
                        f"1. Add `{env_file.name}` to .gitignore.\n"
                        f"2. Remove the file from Git tracking: `git rm --cached {env_file.name}`\n"
                        f"3. Commit the .gitignore update.\n"
                        f"4. Rotate any secrets contained in the file.\n"
                        f"5. Consider cleaning Git history if secrets were exposed."
                    ),
                    file=env_file,
                    references=[
                        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                    ],
                    auto_fix=lambda rp: _add_to_gitignore(rp),
                ))
        return findings
