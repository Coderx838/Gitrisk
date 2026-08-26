"""Secrets scanner — detects API keys, tokens, private keys, and passwords in source code."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Each pattern: (id_suffix, title, regex, severity)
SECRET_PATTERNS: list[tuple[str, str, str, Severity]] = [
    ("001", "AWS Access Key ID",          r"(?<!\w)AKIA[0-9A-Z]{16}(?!\w)", Severity.CRITICAL),
    ("002", "AWS Secret Access Key",      r"(?i)aws[_\-.]?secret[_\-.]?access[_\-.]?key\s*[=:]\s*\S{20,}", Severity.CRITICAL),
    ("003", "GitHub Token",               r"ghp_[0-9a-zA-Z]{30,40}", Severity.CRITICAL),
    ("004", "GitHub Fine-Grained Token",  r"github_pat_[0-9a-zA-Z_]{82}", Severity.CRITICAL),
    ("005", "Slack Token",                r"xox[baprs]-[0-9A-Za-z]{10,48}", Severity.HIGH),
    ("006", "Stripe Secret Key",          r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL),
    ("007", "Stripe Publishable Key",     r"pk_live_[0-9a-zA-Z]{24,}", Severity.HIGH),
    ("008", "Google API Key",             r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("009", "Heroku API Key",             r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", Severity.MEDIUM),
    ("010", "RSA Private Key",            r"-----BEGIN RSA PRIVATE KEY-----", Severity.CRITICAL),
    ("011", "OpenSSH Private Key",        r"-----BEGIN OPENSSH PRIVATE KEY-----", Severity.CRITICAL),
    ("012", "PEM Private Key",            r"-----BEGIN PRIVATE KEY-----", Severity.CRITICAL),
    ("013", "Twilio Auth Token",          r"(?i)twilio.*[0-9a-f]{32}", Severity.HIGH),
    ("014", "SendGrid API Key",           r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", Severity.HIGH),
    ("015", "Mailgun API Key",            r"key-[0-9a-zA-Z]{32}", Severity.HIGH),
    ("016", "Slack Webhook URL",          r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+", Severity.HIGH),
    ("017", "NPM Token",                  r"npm_[A-Za-z0-9]{36}", Severity.HIGH),
    ("018", "PyPI Token",                 r"pypi-[A-Za-z0-9\-_]{50,}", Severity.HIGH),
    ("019", "Basic Auth in URL",          r"https?://[^:@\s]+:[^:@\s]+@[^\s]+", Severity.HIGH),
    ("020", "Generic Secret Assignment",  r"(?i)(secret|password|passwd|api_key|auth_token)\s*[=:]\s*\S{12,}", Severity.MEDIUM),
]

# File types to scan for secrets
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".env", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".tf",
    ".tfvars", ".properties", ".txt", ".md", ".rs", ".kt", ".swift",
    ".gradle", ".dockerfile", ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", "",  # no extension
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

# Max file size to scan (bytes)
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


class SecretsScanner(BaseScanner):
    """Scanner 1: Detect secrets, API keys, tokens, and private keys in source files."""

    name = "secrets"
    description = "Detects API keys, tokens, private keys, and passwords in source code."
    category = "secrets"

    def __init__(self, repo_path: Path) -> None:
        super().__init__(repo_path)
        self._compiled = [
            (sid, title, re.compile(pattern, re.MULTILINE), severity)
            for sid, title, pattern, severity in SECRET_PATTERNS
        ]

    def _iter_files(self) -> Iterator[Path]:
        for p in self.repo_path.rglob("*"):
            if not p.is_file():
                continue
            parts = p.relative_to(self.repo_path).parts
            if any(part in SKIP_DIRS for part in parts):
                continue
            if p.suffix.lower() not in TEXT_EXTENSIONS and p.suffix != "":
                continue
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            yield p

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()  # deduplicate by (file, line, pattern_id)

        for filepath in self._iter_files():
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                for sid, title, regex, severity in self._compiled:
                    match = regex.search(line)
                    if match:
                        key = f"{filepath}:{line_no}:{sid}"
                        if key in seen:
                            continue
                        seen.add(key)

                        # Redact the matched value for display
                        matched_val = match.group(0)
                        redacted = matched_val[:6] + "*" * (len(matched_val) - 6) if len(matched_val) > 6 else "***"

                        findings.append(Finding(
                            id=f"SEC-{sid}",
                            scanner=self.name,
                            title=f"{title} detected",
                            description=(
                                f"A {title.lower()} was found in {self._rel(filepath)}:{line_no}. "
                                f"This credential may already be compromised if the repository has "
                                f"ever been public or shared. Even if it appears private, secrets in "
                                f"source code can leak through forks, clones, or log files."
                            ),
                            severity=severity,
                            fix_type=FixType.MANUAL,
                            remediation=(
                                f"1. Immediately revoke and rotate the exposed credential.\n"
                                f"2. Remove it from the file and replace with an environment variable or secret manager.\n"
                                f"3. Add the file to .gitignore if it should never be committed.\n"
                                f"4. Consider cleaning Git history (git filter-repo or BFG Repo Cleaner) "
                                f"   if the secret was ever committed."
                            ),
                            file=filepath,
                            line=line_no,
                            evidence=redacted,
                            references=[
                                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                                "https://trufflesecurity.com/blog/oops-i-committed-a-secret",
                            ],
                        ))
        return findings
