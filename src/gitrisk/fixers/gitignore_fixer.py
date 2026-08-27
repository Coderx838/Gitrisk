"""GitIgnore auto-fixer for GitRisk v0.2."""
from __future__ import annotations
from pathlib import Path


SECURITY_PATTERNS = [
    ".env",
    ".env.*",
    "!.env.example",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
]

BASE_GITIGNORE = """
# GitRisk generated .gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
/.venv/
/venv/

# Node
node_modules/

# Secrets and credentials
.env
.env.*
!.env.example
*.key
*.pem
*.p12
*.pfx
*.crt
*.cer
credentials.json

# Logs
*.log
logs/

# OS
.DS_Store
Thumbs.db

# IDE
.idea/
.vscode/
""".strip()


class GitIgnoreFixer:
    """Creates or patches .gitignore with missing security patterns."""

    def __init__(self, missing_patterns: list[str] | None = None, create_new: bool = False) -> None:
        self.missing_patterns = missing_patterns or SECURITY_PATTERNS
        self.create_new = create_new

    def apply(self, repo_path: Path) -> None:
        gitignore = repo_path / ".gitignore"
        if self.create_new or not gitignore.exists():
            gitignore.write_text(BASE_GITIGNORE, encoding="utf-8")
        else:
            existing = gitignore.read_text(encoding="utf-8", errors="ignore")
            to_add = [p for p in self.missing_patterns if p not in existing]
            if to_add:
                with gitignore.open("a", encoding="utf-8") as f:
                    f.write("\n# GitRisk: added missing security patterns\n")
                    for p in to_add:
                        f.write(f"{p}\n")
