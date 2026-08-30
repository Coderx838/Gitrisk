"""Content Topology & Region Mapper for GitRisk SEI.

Maps files and raw string content into semantic topological regions:
- Code Instructions vs String Literals vs Comments
- Config / Environment Key-Value pairs
- Inline Media Payloads (Base64 data URIs, SVG image nodes, font embeds)
- Lockfile integrity hashes & package metadata
- Documentation & example text
"""
from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import NamedTuple, Optional


class RegionType(Enum):
    CODE = "code"
    STRING_LITERAL = "string_literal"
    COMMENT = "comment"
    CONFIG_KV = "config_kv"
    DOCS = "docs"
    MEDIA_BASE64 = "media_base64"
    LOCKFILE = "lockfile"
    UNKNOWN = "unknown"


# File extension groups
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh", ".rs", ".kt",
    ".swift", ".scala", ".pl", ".r", ".lua",
}
CONFIG_EXTENSIONS = {
    ".env", ".ini", ".cfg", ".conf", ".properties", ".tfvars",
    ".toml", ".yaml", ".yml",
}
DOC_EXTENSIONS = {
    ".md", ".rst", ".txt", ".adoc", ".markdown", ".tex",
}
MEDIA_EXTENSIONS = {
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
}
LOCKFILE_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "cargo.lock", "gemfile.lock", "composer.lock", "flake.lock",
}


# Base64 data URI pattern
DATA_URI_PATTERN = re.compile(
    r"data:(?:image/[a-zA-Z+.-]+|font/[a-zA-Z+.-]+|application/[a-zA-Z+.-]+);base64,[A-Za-z0-9+/=]{40,}",
    re.IGNORECASE,
)

# SVG inline image element pattern
SVG_IMAGE_DATA_PATTERN = re.compile(
    r"""(?:href|xlink:href)\s*=\s*["']data:image/[^"']+["']""",
    re.IGNORECASE,
)

# Unbroken massive base64 blob pattern (>80 chars without whitespace or punctuation)
MASSIVE_BASE64_BLOB = re.compile(
    r"[A-Za-z0-9+/=]{80,}"
)


class TopologyMap(NamedTuple):
    file_type: str
    primary_region: RegionType
    is_media_file: bool
    is_doc_file: bool
    is_lockfile: bool


def analyze_file_topology(filepath: Optional[Path]) -> TopologyMap:
    """Analyze file level topology from its path and extension."""
    if not filepath:
        return TopologyMap(
            file_type="unknown",
            primary_region=RegionType.CODE,
            is_media_file=False,
            is_doc_file=False,
            is_lockfile=False,
        )

    ext = filepath.suffix.lower()
    name = filepath.name.lower()

    is_media = ext in MEDIA_EXTENSIONS
    is_doc = ext in DOC_EXTENSIONS
    is_lock = name in LOCKFILE_NAMES

    if is_media:
        primary = RegionType.MEDIA_BASE64
    elif is_lock:
        primary = RegionType.LOCKFILE
    elif is_doc:
        primary = RegionType.DOCS
    elif ext in CONFIG_EXTENSIONS or name.startswith(".env"):
        primary = RegionType.CONFIG_KV
    elif ext in CODE_EXTENSIONS:
        primary = RegionType.CODE
    else:
        primary = RegionType.UNKNOWN

    return TopologyMap(
        file_type=ext if ext else name,
        primary_region=primary,
        is_media_file=is_media,
        is_doc_file=is_doc,
        is_lockfile=is_lock,
    )


def classify_line_region(line: str, topology: TopologyMap) -> RegionType:
    """Classify the specific topological region for a single line of text."""
    stripped = line.strip()

    # Lockfiles
    if topology.is_lockfile:
        return RegionType.LOCKFILE

    # Media files (e.g. SVG containing raster data)
    if topology.is_media_file or DATA_URI_PATTERN.search(line) or SVG_IMAGE_DATA_PATTERN.search(line):
        return RegionType.MEDIA_BASE64

    # Documentation files
    if topology.is_doc_file:
        return RegionType.DOCS

    # Pure comments
    if stripped.startswith(("#", "//", "/*", "*", "--", "<!--", ";")):
        return RegionType.COMMENT

    # Config Key-Value lines (.env, .ini, etc.)
    if topology.primary_region == RegionType.CONFIG_KV:
        return RegionType.CONFIG_KV

    # Code files
    return RegionType.CODE
