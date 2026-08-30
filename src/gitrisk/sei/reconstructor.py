"""Token Reconstructor for GitRisk SEI.

Reassembles fragmented, concatenated, or split string tokens
(e.g. "AIza" + "Sy12345..." or multi-line string splits) into logical credentials.
"""
from __future__ import annotations

import re
from typing import NamedTuple

# Matches string concatenation: "foo" + "bar" or 'foo' + 'bar'
CONCAT_PATTERN = re.compile(
    r"""(?:["']([^"'\\]*(?:\\.[^"'\\]*)*)["']\s*\+\s*)+["']([^"'\\]*(?:\\.[^"'\\]*)*)["']"""
)

# Matches implicit string literal concatenation: ("foo" "bar")
IMPLICIT_CONCAT_PATTERN = re.compile(
    r"""["']([^"'\\]*(?:\\.[^"'\\]*)*)["']\s+["']([^"'\\]*(?:\\.[^"'\\]*)*)["']"""
)


class ReconstructedToken(NamedTuple):
    original_snippet: str
    reconstructed_value: str
    is_reconstructed: bool


def reconstruct_tokens(line: str) -> list[ReconstructedToken]:
    """Extract and reconstruct all string tokens from a single line or snippet."""
    results: list[ReconstructedToken] = []

    # 1. Explicit concatenation with +
    for match in CONCAT_PATTERN.finditer(line):
        full_match = match.group(0)
        # Extract all string literals inside the concatenation chain
        parts = re.findall(r"""["']([^"'\\]*(?:\\.[^"'\\]*)*)["']""", full_match)
        if len(parts) >= 2:
            combined = "".join(parts)
            results.append(ReconstructedToken(
                original_snippet=full_match,
                reconstructed_value=combined,
                is_reconstructed=True,
            ))

    # 2. Implicit concatenation: ("foo" "bar")
    for match in IMPLICIT_CONCAT_PATTERN.finditer(line):
        full_match = match.group(0)
        parts = re.findall(r"""["']([^"'\\]*(?:\\.[^"'\\]*)*)["']""", full_match)
        if len(parts) >= 2:
            combined = "".join(parts)
            results.append(ReconstructedToken(
                original_snippet=full_match,
                reconstructed_value=combined,
                is_reconstructed=True,
            ))

    return results
