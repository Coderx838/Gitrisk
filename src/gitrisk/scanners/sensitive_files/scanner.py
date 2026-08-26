"""Sensitive files scanner — detects private keys, certs, dumps, credential files."""

from __future__ import annotations

from pathlib import Path

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# (filename_pattern, is_extension, severity, description)
SENSITIVE_FILE_RULES: list[tuple[str, bool, Severity, str]] = [
    # Private keys
    (".pem", True, Severity.CRITICAL, "PEM private key or certificate"),
    (".key", True, Severity.CRITICAL, "Private key file"),
    (".p12", True, Severity.CRITICAL, "PKCS#12 keystore"),
    (".pfx", True, Severity.CRITICAL, "PFX certificate/key bundle"),
    (".jks", True, Severity.CRITICAL, "Java KeyStore"),
    # Credentials
    ("credentials.json", False, Severity.CRITICAL, "Google/AWS credentials file"),
    ("credentials", False, Severity.HIGH, "Generic credentials file"),
    ("service-account.json", False, Severity.CRITICAL, "GCP service account key"),
    ("serviceaccount.json", False, Severity.CRITICAL, "GCP service account key"),
    ("secrets.json", False, Severity.HIGH, "Secrets JSON file"),
    ("secrets.yaml", False, Severity.HIGH, "Secrets YAML file"),
    ("secrets.yml", False, Severity.HIGH, "Secrets YAML file"),
    # Dumps
    (".sql", True, Severity.MEDIUM, "SQL database dump"),
    (".dump", True, Severity.MEDIUM, "Database dump file"),
    ("dump.sql", False, Severity.HIGH, "SQL dump"),
    ("database.sqlite", False, Severity.HIGH, "SQLite database"),
    (".sqlite", True, Severity.MEDIUM, "SQLite database"),
    (".db", True, Severity.MEDIUM, "Database file"),
    # SSH
    ("id_rsa", False, Severity.CRITICAL, "RSA private key"),
    ("id_ed25519", False, Severity.CRITICAL, "ED25519 private key"),
    ("id_dsa", False, Severity.CRITICAL, "DSA private key"),
    ("id_ecdsa", False, Severity.CRITICAL, "ECDSA private key"),
    # Config with embedded secrets
    (".htpasswd", False, Severity.HIGH, "Apache password file"),
    (".npmrc", False, Severity.MEDIUM, "npm config (may contain auth tokens)"),
    (".pypirc", False, Severity.HIGH, "PyPI credentials config"),
    ("netrc", False, Severity.HIGH, ".netrc credentials file"),
    (".netrc", False, Severity.HIGH, ".netrc credentials file"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


class SensitiveFilesScanner(BaseScanner):
    """Scanner 6: Detect sensitive files (keys, certs, dumps, credential files) in the repository."""

    name = "sensitive_files"
    description = "Detects private keys, certificates, dumps, and credential files in the repository."
    category = "secrets"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        for filepath in self.repo_path.rglob("*"):
            if not filepath.is_file():
                continue
            parts = filepath.relative_to(self.repo_path).parts
            if any(part in SKIP_DIRS for part in parts):
                continue

            name_lower = filepath.name.lower()
            suffix_lower = filepath.suffix.lower()

            for pattern, is_extension, severity, desc in SENSITIVE_FILE_RULES:
                matched = False
                if is_extension:
                    matched = suffix_lower == pattern
                else:
                    matched = name_lower == pattern.lower()

                if matched:
                    findings.append(Finding(
                        id="SEN-001",
                        scanner=self.name,
                        title=f"Sensitive file found: {self._rel(filepath)}",
                        description=(
                            f"`{self._rel(filepath)}` appears to be a {desc}. "
                            f"Sensitive files committed to a repository can expose credentials, "
                            f"encryption keys, or internal data to anyone with repository access."
                        ),
                        severity=severity,
                        fix_type=FixType.MANUAL,
                        remediation=(
                            f"1. Remove `{filepath.name}` from the repository: `git rm --cached {filepath.name}`\n"
                            f"2. Add it to .gitignore to prevent future commits.\n"
                            f"3. If it contains secrets or keys, rotate/revoke them immediately.\n"
                            f"4. Clean Git history if the file was ever committed."
                        ),
                        file=filepath,
                        references=[
                            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                        ],
                    ))
                    break  # Only report once per file

        return findings
