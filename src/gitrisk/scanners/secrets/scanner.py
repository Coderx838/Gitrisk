"""Secrets scanner — detects API keys, tokens, private keys, and passwords in source code."""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from enum import Enum
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
    # SEC-009: Requires 'heroku' in the variable name to avoid false-positives on
    # Bluetooth UUIDs (0000fff1-0000-...), database IDs, session tokens, etc.
    ("009", "Heroku API Key",
     r"(?i)heroku[_\-.]?(?:api[_\-.]?)?(?:key|token|secret)\s*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]?",
     Severity.HIGH),
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
    # SEC-020: Generic Secret Assignment — FP-filtered in scan() via _is_sec020_fp()
    ("020", "Generic Secret Assignment",  r"(?i)(secret|password|passwd|api_key|auth_token)\s*[=:]\s*(\S{12,})", Severity.MEDIUM),
]

# ---------------------------------------------------------------------------
# False-positive detection for SEC-020 — entropy + string literal requirement
# ---------------------------------------------------------------------------

# Code file extensions — values MUST be string literals (quoted) to be real secrets.
# A variable assignment like `api_key = self.gemini_api_key` is never a literal secret.
_CODE_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".rs", ".kt", ".swift",
}

# Config/env files — values may be unquoted; use entropy as primary filter.
_ENV_EXTS = {".env", ".ini", ".cfg", ".conf", ".properties"}

# Values that are provably not secrets
_FP_VALUE_RE = re.compile(
    r"^("
    r"None|False|True|null|undefined|NaN"
    r"|os\.getenv|environ\.get|getenv\("
    r"|config\.get|settings\.|os\.environ"
    r"|\$\{[^}]+\}|\{\{[^}]+\}\}|<[^>]+>"
    r"|your[_\-]?[a-z_]*[_\-]?(?:key|token|secret|password|here)"
    r"|xxx+|placeholder|changeme|secret_here|token_here"
    r"|[a-z_]+_here|add_your_|insert_your_"
    r"|\*+|\.\.\.+"
    r")",
    re.IGNORECASE,
)

# Env reference anywhere on the line
_ENV_REF_RE = re.compile(
    r"os\.getenv|os\.environ|environ\[|getenv\(|config\[|settings\.|dotenv|load_dotenv",
    re.IGNORECASE,
)

# Obvious placeholder words in the value
_PLACEHOLDER_RE = re.compile(
    r"your[_-]?[a-z_]*[_-]?(?:key|token|secret|password|here)"
    r"|<[a-zA-Z_]+>"
    r"|\{[a-zA-Z_]+\}"
    r"|xxx+"
    r"|example"
    r"|placeholder"
    r"|add[_-]your"
    r"|insert[_-]?here"
    r"|changeme",
    re.IGNORECASE,
)

# Python/JS function definition line (parameters are never secrets)
_FUNC_DEF_RE = re.compile(r"^\s*(?:def|function|func|fn)\s+\w+\s*\(")

# Documentation file extensions
_DOC_EXTS = {".md", ".rst", ".txt", ".adoc"}

# Entropy thresholds (bits per character)
# Real secrets: AKIA…, ghp_…, base64 tokens, API keys → typically 4.0–5.5
# Variable names: gemini_api_key, api_key.strip() → typically 2.5–3.2
_ENTROPY_MIN_CODE = 3.0   # for quoted string literals in code
_ENTROPY_MIN_ENV  = 3.2   # for unquoted values in .env/.cfg files


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character.
    High entropy (>3.5) means random, secret-like.
    Low entropy (<3.0) means structured/dictionary-like (variable names, words).
    """
    if len(s) < 2:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_sec020_fp(line: str, matched_value: str, filepath: Path) -> bool:
    """Return True if this SEC-020 match is a known false positive.

    Uses a two-stage approach (same methodology as Gitleaks/TruffleHog):
    1. String literal requirement: in code files, real secrets MUST be quoted.
       `api_key = self.gemini_api_key` → FP (unquoted variable reference)
       `api_key = "AIzaSy...actual..."` → real (quoted string literal)
    2. Shannon entropy gate: even if quoted, low-entropy strings are placeholders.
       `password = "my_password_here"` → FP (entropy ~2.8, below threshold)
       `password = "P@ssw0rd!k9xQr..."` → real (entropy ~4.2, above threshold)
    """
    val = matched_value.strip()
    ext = filepath.suffix.lower()
    fname = filepath.name.lower()

    is_env_file = ext in _ENV_EXTS or fname.startswith(".env")
    is_code_file = ext in _CODE_EXTS

    # --- Quick filters on the raw value (before entropy) ---
    # Strip quotes to get the inner value for checks
    inner = val.strip('"\'`')

    if _FP_VALUE_RE.match(inner) or _FP_VALUE_RE.match(val):
        return True
    if _PLACEHOLDER_RE.search(inner):
        return True
    if _ENV_REF_RE.search(line):
        return True
    if _FUNC_DEF_RE.match(line):
        return True

    stripped = line.strip()
    if stripped.startswith(("#", "//", "/*", "*", "--", "<!--")):
        return True

    if filepath.suffix.lower() in _DOC_EXTS:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", inner):
            return True

    # --- Stage 1: String Literal Requirement (code files only) ---
    if is_code_file:
        # If the value doesn't start with a quote, it's a variable/expression, never a literal secret.
        # Examples of what gets suppressed:
        #   self.api_key = gemini_api_key     → val = "gemini_api_key"        → no quote → FP
        #   api_key = api_key.strip()         → val = "api_key.strip()"       → no quote → FP
        #   api_key = self.gemini_api_key     → val = "self.gemini_api_key"   → no quote → FP
        #   api_key = load_api_key()          → val = "load_api_key()"        → no quote → FP
        is_quoted = bool(re.match(r'^[brfBRF]*["\']', val))
        if not is_quoted:
            return True  # Definite false positive: unquoted = code reference
        # Extract actual string content (remove quote chars and prefixes)
        inner = re.sub(r'^[brfBRF]*["\']|["\']$', '', val)

    # --- Stage 2: Shannon Entropy Gate ---
    if len(inner) < 8:
        return True

    threshold = _ENTROPY_MIN_ENV if is_env_file else _ENTROPY_MIN_CODE
    ent = _shannon_entropy(inner)
    if ent < threshold:
        return True  # Low entropy: placeholder, word, or structured text

    return False


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


class _GitExposure(Enum):
    """How exposed is a file's content in the git repository?"""
    TRACKED       = "tracked"        # File is in git index — content is in the repo
    UNTRACKED_UNSAFE = "unsafe"      # Not in git, not gitignored — could be committed accidentally
    UNTRACKED_SAFE   = "safe"        # Not in git, gitignored — properly protected
    UNKNOWN       = "unknown"        # Not a git repo or git unavailable


def _get_tracked_files(repo_path: Path) -> frozenset[str]:
    """Run `git ls-files` once and return all tracked files as a frozenset.
    Uses forward-slash paths for cross-platform consistency.
    Returns empty frozenset if not a git repo or git is unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_path,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode == 0:
            return frozenset(result.stdout.splitlines())
    except Exception:
        pass
    return frozenset()


def _is_gitignored(filepath: Path, repo_path: Path) -> bool:
    """Check if a specific file is gitignored (lazy — only called when needed).
    Uses `git check-ignore -q` which exits 0 if the file is ignored.
    """
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", "--", str(filepath)],
            cwd=repo_path,
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _classify_file_exposure(
    filepath: Path,
    repo_path: Path,
    tracked_files: frozenset[str],
    ignore_cache: dict[str, bool],
) -> _GitExposure:
    """Classify how exposed a file's content is in git.

    Algorithm:
    1. Convert file path to forward-slash relative path (git uses forward slashes).
    2. Check O(1) frozenset lookup for tracked status.
    3. If not tracked: check gitignore cache (lazy git check-ignore call).
       - Gitignored → SAFE (correctly protected)
       - Not gitignored → UNSAFE (risk of accidental commit)
    4. If not a git repo: return UNKNOWN (scan everything, be safe).
    """
    if not tracked_files and not (repo_path / ".git").exists():
        return _GitExposure.UNKNOWN

    try:
        rel = filepath.relative_to(repo_path)
        rel_str = str(rel).replace("\\", "/")  # git always uses forward slashes
    except ValueError:
        return _GitExposure.UNKNOWN

    # O(1) lookup in pre-computed frozenset
    if rel_str in tracked_files:
        return _GitExposure.TRACKED

    # Not tracked: check gitignore (with cache for performance)
    if rel_str not in ignore_cache:
        ignore_cache[rel_str] = _is_gitignored(filepath, repo_path)
    if ignore_cache[rel_str]:
        return _GitExposure.UNTRACKED_SAFE  # .env is in .gitignore → correctly protected

    return _GitExposure.UNTRACKED_UNSAFE  # Not in git, not ignored → accidental commit risk


# File extensions considered "config/env" files
# In these files we apply git exposure classification:
# - TRACKED → full severity (committed secret)
# - UNTRACKED_UNSAFE → LOW severity (risk of accidental commit)
# - UNTRACKED_SAFE → SKIP (gitignored, properly protected)
_CONFIG_EXTS = {".env", ".ini", ".cfg", ".conf", ".properties", ".tfvars"}


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
        # Pre-compute git-tracked files once (O(n) single git call → O(1) per-file lookup)
        self._tracked_files: frozenset[str] = _get_tracked_files(repo_path)
        # Cache for gitignore status (lazy: only populated for untracked config files)
        self._ignore_cache: dict[str, bool] = {}

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
        seen: set[str] = set()

        for filepath in self._iter_files():
            # --- Git Exposure Classification ---
            # For config/env files, determine if the file is actually in the git repository.
            # Secrets in gitignored local files are NOT a security risk for the repo.
            is_config_file = (
                filepath.suffix.lower() in _CONFIG_EXTS
                or filepath.name.lower().startswith(".env")
            )
            if is_config_file:
                exposure = _classify_file_exposure(
                    filepath, self.repo_path,
                    self._tracked_files, self._ignore_cache,
                )
                if exposure == _GitExposure.UNTRACKED_SAFE:
                    # File is gitignored — secrets in it are safe, skip entirely
                    continue
                exposure_override = exposure  # pass to finding builder below
            else:
                exposure_override = None  # code files: always scan, no override

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_no, line in enumerate(lines, start=1):
                for sid, title, regex, severity in self._compiled:
                    match = regex.search(line)
                    if match:
                        # Apply context-aware false-positive filter for SEC-020
                        if sid == "020":
                            matched_value = (
                                match.group(2)
                                if match.lastindex and match.lastindex >= 2
                                else match.group(0)
                            )
                            if _is_sec020_fp(line, matched_value, filepath):
                                continue

                        key = f"{filepath}:{line_no}:{sid}"
                        if key in seen:
                            continue
                        seen.add(key)

                        # Redact the matched value for display
                        matched_val = match.group(0)
                        redacted = matched_val[:6] + "*" * (len(matched_val) - 6) if len(matched_val) > 6 else "***"

                        # Adjust severity and description based on git exposure
                        effective_severity = severity
                        exposure_note = ""
                        remediation_note = (
                            f"1. Immediately revoke and rotate the exposed credential.\n"
                            f"2. Remove it from the file and replace with an environment variable or secret manager.\n"
                            f"3. Add the file to .gitignore if it should never be committed.\n"
                            f"4. Consider cleaning Git history (git filter-repo or BFG Repo Cleaner) "
                            f"   if the secret was ever committed."
                        )

                        if exposure_override == _GitExposure.TRACKED:
                            exposure_note = (
                                f" ⚠ This file ({self._rel(filepath)}) IS tracked by git — "
                                f"the secret is exposed in the repository and its full history."
                            )
                        elif exposure_override == _GitExposure.UNTRACKED_UNSAFE:
                            # File is not tracked AND not gitignored — warn at LOW severity
                            effective_severity = Severity.LOW
                            exposure_note = (
                                f" ⚠ {self._rel(filepath)} is not tracked by git but is also "
                                f"NOT in .gitignore. Running `git add .` would expose this secret."
                            )
                            remediation_note = (
                                f"1. Add `{self._rel(filepath)}` to .gitignore immediately to prevent accidental commits.\n"
                                f"2. Rotate the credential as a precaution.\n"
                                f"3. Consider using a secrets manager or environment variable instead."
                            )

                        findings.append(Finding(
                            id=f"SEC-{sid}",
                            scanner=self.name,
                            title=f"{title} detected",
                            description=(
                                f"A {title.lower()} was found in {self._rel(filepath)}:{line_no}. "
                                f"This credential may already be compromised if the repository has "
                                f"ever been public or shared. Even if it appears private, secrets in "
                                f"source code can leak through forks, clones, or log files."
                                f"{exposure_note}"
                            ),
                            severity=effective_severity,
                            fix_type=FixType.MANUAL,
                            remediation=remediation_note,
                            file=filepath,
                            line=line_no,
                            evidence=redacted,
                            references=[
                                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                                "https://trufflesecurity.com/blog/oops-i-committed-a-secret",
                            ],
                        ))
        return findings
