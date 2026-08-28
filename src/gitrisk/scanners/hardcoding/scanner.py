"""Hardcoding scanner — detects hardcoded passwords, connection strings, and embedded tokens."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Patterns for hardcoded credentials (different from raw secret values)
HARDCODE_PATTERNS: list[tuple[str, str, str, Severity]] = [
    # Database connection strings
    (
        "HRD-001",
        "Hardcoded database connection string",
        r"(?i)(mysql|postgres|postgresql|mongodb|redis|sqlite|mssql|oracle)://[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+",
        Severity.HIGH,
    ),
    # Hardcoded password assignments
    (
        "HRD-002",
        "Hardcoded password in code",
        r"(?i)(?:password|passwd|pwd)\s*=\s*[\"'][^\"'\s]{4,}[\"']",
        Severity.HIGH,
    ),
    # Hardcoded username:password
    (
        "HRD-003",
        "Hardcoded username:password pair",
        r"(?i)(?:user|username|login)\s*=\s*[\"'][^\"'\s]+[\"'].*(?:password|passwd|pwd)\s*=\s*[\"'][^\"'\s]+[\"']",
        Severity.HIGH,
    ),
    # IP addresses in code (potential internal infrastructure leak)
    (
        "HRD-004",
        "Hardcoded internal IP address",
        r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
        Severity.LOW,
    ),
    # TODO/FIXME comments referencing security
    (
        "HRD-005",
        "Security TODO/FIXME comment",
        r"(?i)#\s*(?:todo|fixme|hack|xxx).*(?:password|secret|key|token|auth|credential)",
        Severity.LOW,
    ),
    # Hardcoded localhost with port (may reveal internal services)
    (
        "HRD-006",
        "Hardcoded service endpoint",
        r"(?i)(localhost|127\.0\.0\.1):\d{4,5}",
        Severity.INFO,
    ),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
SKIP_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".pdf", ".zip", ".tar", ".gz"}
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".yml", ".yaml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".tf", ".tfvars",
    ".env", ".properties", ".txt", ".rs", ".kt",
}
MAX_FILE_SIZE = 512 * 1024  # 512 KB

# Documentation extensions — IPs in these are almost always examples
_DOC_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}

# "example IP" indicator words anywhere on the line
_EXAMPLE_IP_RE = re.compile(
    r"\be\.g\.?\b|example|sample|placeholder|like\b|such as|e\.g|illustration|"
    r"for instance|demo|dummy|fake|test",
    re.IGNORECASE,
)


class HardcodingScanner(BaseScanner):
    """Scanner 10: Detect hardcoded passwords, connection strings, and sensitive values."""

    name = "hardcoding"
    description = "Detects hardcoded passwords, connection strings, and embedded sensitive values."
    category = "secrets"

    def __init__(self, repo_path: Path) -> None:
        super().__init__(repo_path)
        self._compiled = [
            (sid, title, re.compile(pattern, re.MULTILINE | re.IGNORECASE), severity)
            for sid, title, pattern, severity in HARDCODE_PATTERNS
        ]

    def _iter_files(self) -> Iterator[Path]:
        for p in self.repo_path.rglob("*"):
            if not p.is_file():
                continue
            parts = p.relative_to(self.repo_path).parts
            if any(part in SKIP_DIRS for part in parts):
                continue
            if p.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if p.suffix.lower() not in TEXT_EXTENSIONS and p.suffix != "":
                continue
            try:
                if p.stat().st_size > MAX_FILE_SIZE:
                    continue
            except Exception:
                continue
            yield p

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for filepath in self._iter_files():
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                stripped = line.strip()

                for sid, title, regex, severity in self._compiled:
                    match = regex.search(line)
                    if match:
                        # --- HRD-004: Context-aware IP false-positive filtering ---
                        if sid == "HRD-004":
                            # Skip comment-only lines
                            if stripped.startswith(("#", "//", "/*", "*", "--", "<!--")):
                                continue
                            # Skip documentation files (IPs in .md/.txt are usually examples)
                            if filepath.suffix.lower() in _DOC_EXTENSIONS:
                                continue
                            # Skip if the line contains example/illustration language
                            if _EXAMPLE_IP_RE.search(line):
                                continue
                            # Skip if IP appears inside a quoted string that looks like an example
                            # (e.g.  "(e.g. http://192.168.x.x:8080/video)")
                            if re.search(r'["\(].*' + re.escape(match.group(0)) + r'.*["\)]', line):
                                if _EXAMPLE_IP_RE.search(line):
                                    continue

                        key = f"{filepath}:{line_no}:{sid}"
                        if key in seen:
                            continue
                        seen.add(key)

                        matched_val = match.group(0)
                        # Partially redact for display
                        if len(matched_val) > 20:
                            evidence = matched_val[:20] + "..."
                        else:
                            evidence = matched_val

                        findings.append(Finding(
                            id=sid,
                            scanner=self.name,
                            title=f"{title}: {self._rel(filepath)}:{line_no}",
                            description=(
                                f"Found potential {title.lower()} in `{self._rel(filepath)}` at line {line_no}. "
                                f"Hardcoded sensitive values in source code can be extracted from "
                                f"repositories, compiled binaries, or Docker images."
                            ),
                            severity=severity,
                            fix_type=FixType.REVIEW,
                            remediation=(
                                f"Replace the hardcoded value with an environment variable or secret manager reference.\n"
                                f"Example: use os.getenv('MY_SECRET') or a secrets manager SDK."
                            ),
                            file=filepath,
                            line=line_no,
                            evidence=evidence,
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                            ],
                        ))
        return findings

