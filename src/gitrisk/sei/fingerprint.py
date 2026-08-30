"""Secret Fingerprinting Engine for GitRisk SEI.

Generates privacy-preserving, one-way non-reversible cryptographic fingerprints
for credential deduplication, lifecycle tracking, and cross-file correlation.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import NamedTuple

# Fixed internal salt for consistent hashing per scan session
_ENGINE_SALT = b"GitRisk-SEI-v1-Sentry"


class SecretFingerprint(NamedTuple):
    fingerprint_id: str   # 12-char hex digest (e.g. "a8f1b2c3d4e5")
    redacted_preview: str # e.g. "AKIAIO**********MPLE"


def generate_fingerprint(secret_value: str) -> SecretFingerprint:
    """Generate a one-way fingerprint and secure redaction from a raw secret string."""
    cleaned = secret_value.strip().strip("'\"`;")
    
    # Compute 1-way HMAC-SHA256
    digest = hmac.new(_ENGINE_SALT, cleaned.encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()
    fp_id = digest[:12]

    # Create redaction preview
    n = len(cleaned)
    if n <= 8:
        redacted = "*" * n
    elif n <= 16:
        redacted = cleaned[:2] + "*" * (n - 4) + cleaned[-2:]
    else:
        prefix_len = 6 if n > 24 else 4
        suffix_len = 4 if n > 24 else 2
        redacted = cleaned[:prefix_len] + "*" * max(4, n - prefix_len - suffix_len) + cleaned[-suffix_len:]

    return SecretFingerprint(
        fingerprint_id=fp_id,
        redacted_preview=redacted,
    )
