"""GitRisk scanners registry."""

from __future__ import annotations

from gitrisk.core.base import BaseScanner
from gitrisk.scanners.secrets.scanner import SecretsScanner
from gitrisk.scanners.dependencies.scanner import DependencyScanner
from gitrisk.scanners.env.scanner import EnvFileScanner
from gitrisk.scanners.github_actions.scanner import GitHubActionsScanner
from gitrisk.scanners.gitignore.scanner import GitIgnoreScanner
from gitrisk.scanners.sensitive_files.scanner import SensitiveFilesScanner
from gitrisk.scanners.git_config.scanner import GitConfigScanner
from gitrisk.scanners.outdated.scanner import OutdatedDepsScanner
from gitrisk.scanners.security_policy.scanner import SecurityPolicyScanner
from gitrisk.scanners.hardcoding.scanner import HardcodingScanner

_ALL_SCANNERS: list[type[BaseScanner]] = [
    SecretsScanner,
    DependencyScanner,
    EnvFileScanner,
    GitHubActionsScanner,
    GitIgnoreScanner,
    SensitiveFilesScanner,
    GitConfigScanner,
    OutdatedDepsScanner,
    SecurityPolicyScanner,
    HardcodingScanner,
]


def get_all_scanners() -> list[type[BaseScanner]]:
    """Return all registered scanner classes."""
    return _ALL_SCANNERS
