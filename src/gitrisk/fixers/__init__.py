"""GitRisk fixers package — smart safe-fix subsystem."""
from gitrisk.fixers.dependency_fixer import DependencyFixer
from gitrisk.fixers.gitignore_fixer import GitIgnoreFixer
from gitrisk.fixers.security_files_fixer import SecurityFilesFixer

__all__ = ["DependencyFixer", "GitIgnoreFixer", "SecurityFilesFixer"]
