"""Git history scanner — scans commit history for exposed secrets.

This scanner checks past commits for secrets that may have been committed
and later removed. Even removed secrets are compromised if the repo was
ever public or shared.
"""
from __future__ import annotations
import re
import subprocess
from pathlib import Path
from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Secret patterns to search in git log output
HISTORY_PATTERNS: list[tuple[str, str, Severity]] = [
    ("HIST-001", r"(?<!\w)AKIA[0-9A-Z]{16}(?!\w)", Severity.CRITICAL),
    ("HIST-002", r"ghp_[0-9a-zA-Z]{30,40}", Severity.CRITICAL),
    ("HIST-003", r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL),
    ("HIST-004", r"-----BEGIN (RSA |OPENSSH |)PRIVATE KEY-----", Severity.CRITICAL),
    ("HIST-005", r"-----BEGIN PRIVATE KEY-----", Severity.CRITICAL),
    ("HIST-006", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("HIST-007", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", Severity.HIGH),
    ("HIST-008", r"npm_[A-Za-z0-9]{36}", Severity.HIGH),
    ("HIST-009", r"pypi-[A-Za-z0-9\-_]{50,}", Severity.HIGH),
    ("HIST-010", r"github_pat_[0-9a-zA-Z_]{82}", Severity.CRITICAL),
]

MAX_COMMITS = 100  # Limit history scan for performance


class GitHistoryScanner(BaseScanner):
    """Scanner: Scans recent Git commit history for exposed secrets."""

    name = "git_history"
    description = "Scans Git commit history for secrets that may have been committed and removed."
    category = "secrets"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        # Check if this is a git repo
        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            return findings

        # Get recent git log diff
        # Use encoding='utf-8' with errors='replace' to avoid UnicodeDecodeError on
        # Windows systems where the default encoding (cp1252) cannot handle non-ASCII bytes.
        try:
            result = subprocess.run(
                ["git", "log", f"-{MAX_COMMITS}", "-p", "--no-merges",
                 "--diff-filter=A",  # Only added lines
                 "--unified=0"],
                cwd=self.repo_path,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            log_output = result.stdout
        except Exception:
            return findings

        if not log_output:
            return findings

        compiled = [(fid, re.compile(pat, re.MULTILINE), sev) for fid, pat, sev in HISTORY_PATTERNS]
        seen: set[str] = set()

        current_commit = ""
        current_file = ""
        for line in log_output.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:12]
            elif line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                # This is an added line
                for fid, regex, severity in compiled:
                    m = regex.search(line)
                    if m:
                        key = f"{current_commit}:{current_file}:{fid}"
                        if key in seen:
                            continue
                        seen.add(key)
                        matched = m.group(0)
                        redacted = matched[:6] + "*" * max(0, len(matched) - 6)
                        findings.append(Finding(
                            id=fid,
                            scanner=self.name,
                            title=f"Secret exposed in Git history (commit {current_commit})",
                            description=(
                                f"A secret pattern matching `{fid}` was found in a past commit "
                                f"(`{current_commit}`) in file `{current_file}`. "
                                f"Even if later removed, this secret may be accessible via "
                                f"`git log` and is considered compromised if the repository "
                                f"was ever public or shared."
                            ),
                            severity=severity,
                            fix_type=FixType.MANUAL,
                            remediation=(
                                f"1. Immediately revoke and rotate the exposed credential.\n"
                                f"2. Clean Git history using git-filter-repo:\n"
                                f"   pip install git-filter-repo\n"
                                f"   git filter-repo --path {current_file} --invert-paths\n"
                                f"3. Force-push to all remotes and notify collaborators.\n"
                                f"4. Assume the secret is compromised regardless of cleanup."
                            ),
                            file=Path(current_file),
                            evidence=f"commit={current_commit} file={current_file} value={redacted}",
                            references=[
                                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                                "https://github.com/newren/git-filter-repo",
                            ],
                        ))
        return findings
