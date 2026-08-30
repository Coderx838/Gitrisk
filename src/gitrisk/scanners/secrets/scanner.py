"""Secrets scanner — powered by GitRisk SEI (Secret Intelligence Engine)."""

from __future__ import annotations

import subprocess
from enum import Enum
from pathlib import Path
from typing import Iterator

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity
from gitrisk.sei.engine import SecretIntelligenceEngine
from gitrisk.sei.topology import analyze_file_topology

# File types to scan for secrets
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".env", ".yml",
    ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".tf",
    ".tfvars", ".properties", ".txt", ".md", ".rs", ".kt", ".swift",
    ".gradle", ".dockerfile", ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
    ".svg", "",  # include SVG to run through SEI topology filter
}

# Directories to skip
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


class _GitExposure(Enum):
    TRACKED          = "tracked"
    UNTRACKED_UNSAFE = "unsafe"
    UNTRACKED_SAFE   = "safe"
    UNKNOWN          = "unknown"


def _get_tracked_files(repo_path: Path) -> frozenset[str]:
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
    if not tracked_files and not (repo_path / ".git").exists():
        return _GitExposure.UNKNOWN

    try:
        rel = filepath.relative_to(repo_path)
        rel_str = str(rel).replace("\\", "/")
    except ValueError:
        return _GitExposure.UNKNOWN

    if rel_str in tracked_files:
        return _GitExposure.TRACKED

    if rel_str not in ignore_cache:
        ignore_cache[rel_str] = _is_gitignored(filepath, repo_path)
    if ignore_cache[rel_str]:
        return _GitExposure.UNTRACKED_SAFE

    return _GitExposure.UNTRACKED_UNSAFE


_CONFIG_EXTS = {".env", ".ini", ".cfg", ".conf", ".properties", ".tfvars"}


class SecretsScanner(BaseScanner):
    """Scanner 1: Detect secrets, API keys, and credentials using the SEI engine."""

    name = "secrets"
    description = "Detects API keys, tokens, private keys, and passwords using the SEI engine."
    category = "secrets"

    def __init__(self, repo_path: Path) -> None:
        super().__init__(repo_path)
        self._sei = SecretIntelligenceEngine(repo_path=repo_path)
        self._tracked_files: frozenset[str] = _get_tracked_files(repo_path)
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
                    continue  # .env is gitignored, safe to skip
                exposure_override = exposure
            else:
                exposure_override = None

            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            topology = analyze_file_topology(filepath)
            lines = content.splitlines()

            for line_no, line in enumerate(lines, start=1):
                line_findings = self._sei.evaluate_line(
                    line=line,
                    line_number=line_no,
                    filepath=filepath,
                    topology=topology,
                )

                for f in line_findings:
                    key = f"{filepath}:{line_no}:{f.id}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Adjust severity based on git exposure
                    if exposure_override == _GitExposure.UNTRACKED_UNSAFE:
                        f.severity = Severity.LOW
                        f.description += f" ⚠ {self._rel(filepath)} is not in Git and not in .gitignore. Running git add . would expose this secret."

                    findings.append(f)

        return findings
