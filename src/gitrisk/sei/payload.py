"""Payload & Magic Byte Inspector for GitRisk SEI.

Analyzes Base64, Hex, and embedded data payloads to disambiguate
media streams (images, fonts, archives) from genuine encoded credentials (JWTs, tokens).
"""
from __future__ import annotations

import base64
import json
import re
from typing import NamedTuple, Optional

# Magic byte signatures
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "image/webp"),  # WEBP has RIFF header
    (b"wOFF", "font/woff"),
    (b"wOF2", "font/woff2"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"%PDF", "application/pdf"),
    (b"<?xml", "image/svg+xml"),
    (b"<svg", "image/svg+xml"),
]


class PayloadAnalysis(NamedTuple):
    is_base64_encoded: bool
    is_media_or_binary: bool
    is_jwt: bool
    mime_type: Optional[str]
    decoded_preview: str


def inspect_payload_bytes(raw_token: str) -> PayloadAnalysis:
    """Inspect a token to see if it decodes to known media magic bytes or a JWT."""
    cleaned = raw_token.strip().strip("'\"`;")

    # Check if candidate is a JWT (format: header.payload.signature)
    jwt_parts = cleaned.split(".")
    if len(jwt_parts) == 3:
        try:
            # Pad base64 if needed
            header_b64 = jwt_parts[0] + "=" * ((4 - len(jwt_parts[0]) % 4) % 4)
            decoded_header = base64.urlsafe_b64decode(header_b64.encode()).decode("utf-8", errors="ignore")
            if "alg" in decoded_header or "typ" in decoded_header:
                return PayloadAnalysis(
                    is_base64_encoded=True,
                    is_media_or_binary=False,
                    is_jwt=True,
                    mime_type="application/jwt",
                    decoded_preview=decoded_header[:50],
                )
        except Exception:
            pass

    # Test for standard Base64 decoding
    # Must look like valid base64 and be at least 16 chars
    if len(cleaned) >= 16 and re.match(r"^[A-Za-z0-9+/=_-]+$", cleaned):
        try:
            # Normalize padding
            padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
            decoded_bytes = base64.b64decode(padded.encode(), validate=False)
            if decoded_bytes:
                # Check magic bytes for media formats
                for magic, mime in MAGIC_SIGNATURES:
                    if decoded_bytes.startswith(magic):
                        return PayloadAnalysis(
                            is_base64_encoded=True,
                            is_media_or_binary=True,
                            is_jwt=False,
                            mime_type=mime,
                            decoded_preview=f"Magic: {mime}",
                        )
                # Check if decoded is valid JSON containing JWT header
                try:
                    text = decoded_bytes.decode("utf-8", errors="ignore")
                    if text.startswith("{") and ("alg" in text or "typ" in text):
                        return PayloadAnalysis(
                            is_base64_encoded=True,
                            is_media_or_binary=False,
                            is_jwt=True,
                            mime_type="application/jwt",
                            decoded_preview=text[:50],
                        )
                except Exception:
                    pass
        except Exception:
            pass

    return PayloadAnalysis(
        is_base64_encoded=False,
        is_media_or_binary=False,
        is_jwt=False,
        mime_type=None,
        decoded_preview="",
    )
