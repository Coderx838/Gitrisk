"""Git config scanner — checks for risky repository configuration."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity


class GitConfigScanner(BaseScanner):
    """Scanner 7: Detect risky Git repository configuration."""

    name = "git_config"
    description = "Checks for risky Git configuration settings."
    category = "git"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        git_config = self.repo_path / ".git" / "config"

        if not git_config.exists():
            findings.append(Finding(
                id="GIT-010",
                scanner=self.name,
                title="Not a Git repository or .git/config not found",
                description="No .git/config found. GitRisk is designed to scan Git repositories.",
                severity=Severity.INFO,
                fix_type=FixType.MANUAL,
                remediation="Run `git init` to initialize a Git repository, or point gitrisk at a Git repo.",
            ))
            return findings

        try:
            content = git_config.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        # Check for fileMode = false (can hide permission changes on POSIX systems)
        # Note: Windows filesystems (NTFS) do not support POSIX executable bits, so Git
        # sets fileMode = false automatically by default on Windows.
        import sys
        if sys.platform != "win32" and ("fileMode = false" in content or "filemode = false" in content.lower()):
            findings.append(Finding(
                id="GIT-011",
                scanner=self.name,
                title="fileMode disabled in Git config",
                description=(
                    "Git config has `fileMode = false`. This disables tracking of file permission "
                    "changes, which can mask the accidental addition of executable bits to scripts or "
                    "sensitive files, reducing auditability."
                ),
                severity=Severity.LOW,
                fix_type=FixType.REVIEW,
                remediation="Set `git config core.fileMode true` to restore permission tracking.",
                file=git_config,
            ))

        # Check for shared repository configuration
        if "sharedrepository" in content.lower() or "shared = true" in content.lower():
            findings.append(Finding(
                id="GIT-012",
                scanner=self.name,
                title="Shared repository mode enabled",
                description=(
                    "Git config enables shared repository mode. This allows multiple users on the same "
                    "system to push to this repository. Verify this is intentional and access is properly controlled."
                ),
                severity=Severity.MEDIUM,
                fix_type=FixType.REVIEW,
                remediation="Review whether shared repository mode is intentional. Disable with `git config core.sharedRepository false`.",
                file=git_config,
            ))

        # Check for http.sslVerify = false
        if "sslverify = false" in content.lower():
            findings.append(Finding(
                id="GIT-013",
                scanner=self.name,
                title="SSL verification disabled in Git config",
                description=(
                    "Git config has `sslVerify = false`. This disables TLS certificate verification "
                    "for Git remote operations, making the repository vulnerable to man-in-the-middle attacks."
                ),
                severity=Severity.HIGH,
                fix_type=FixType.SAFE,
                remediation="Set `git config http.sslVerify true` to re-enable SSL verification.",
                file=git_config,
                references=["https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslVerify"],
            ))

        # Check for credential helper storing plaintext
        if "store" in content and "credential" in content.lower():
            findings.append(Finding(
                id="GIT-014",
                scanner=self.name,
                title="Git credential helper stores credentials in plaintext",
                description=(
                    "Git is configured with `credential.helper=store`, which saves credentials in plaintext "
                    "to ~/.git-credentials. Anyone with read access to the home directory can read these credentials."
                ),
                severity=Severity.MEDIUM,
                fix_type=FixType.REVIEW,
                remediation=(
                    "Use a secure credential manager instead:\n"
                    "  macOS: git config --global credential.helper osxkeychain\n"
                    "  Windows: git config --global credential.helper manager\n"
                    "  Linux: git config --global credential.helper /usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring"
                ),
                file=git_config,
            ))

        return findings
