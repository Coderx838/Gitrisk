"""Multi-Signal Evidence Scoring Engine for GitRisk SEI.

Calculates a weighted confidence score [0 - 100] by aggregating
positive and negative evidential signals across syntax, topology,
entropy, payload bytes, and semantics.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple, Optional

from gitrisk.core.models import Severity
from gitrisk.sei.candidates import RawCandidate
from gitrisk.sei.payload import PayloadAnalysis, inspect_payload_bytes
from gitrisk.sei.topology import RegionType, TopologyMap


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if len(s) < 2:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Obvious placeholder and dummy values
PLACEHOLDER_RE = re.compile(
    r"your[_-]?[a-z_]*[_-]?(?:key|token|secret|password|here)|"
    r"<[a-zA-Z_]+>|"
    r"\{[a-zA-Z_]+\}|"
    r"xxx+|"
    r"\bexample\b|"
    r"placeholder|"
    r"add[_-]your|"
    r"insert[_-]?here|"
    r"changeme|"
    r"secret_here|"
    r"dummy_token",
    re.IGNORECASE,
)

# Safe environment variable retrievals
ENV_RETRIEVAL_RE = re.compile(
    r"os\.getenv|os\.environ|environ\[|getenv\(|config\[|settings\.|dotenv|load_dotenv",
    re.IGNORECASE,
)

# Function parameter signature (def foo(api_key=None))
FUNC_DEF_RE = re.compile(r"^\s*(?:def|function|func|fn)\s+\w+\s*\(")

# Non-secret constant values
SAFE_CONSTANTS_RE = re.compile(
    r"^(?:None|False|True|null|undefined|NaN|''|"")$",
    re.IGNORECASE,
)


class EvidenceReport(NamedTuple):
    total_score: int             # 0 to 100
    is_credible_secret: bool     # True if score >= 50
    severity: Severity
    entropy: float
    positive_signals: list[str]
    negative_signals: list[str]
    payload_info: Optional[PayloadAnalysis]


def evaluate_candidate_evidence(
    candidate: RawCandidate,
    topology: TopologyMap,
    line_region: RegionType,
) -> EvidenceReport:
    """Aggregate positive and negative evidential signals to produce a confidence score."""
    pos: list[str] = []
    neg: list[str] = []
    score = 0

    token = candidate.extracted_secret.strip().strip("'\"`;")
    line = candidate.raw_line
    ent = shannon_entropy(token)
    payload = inspect_payload_bytes(candidate.matched_text)

    # =========================================================================
    # 1. POSITIVE SIGNALS
    # =========================================================================
    # High-confidence provider signature
    if candidate.rule.rule_id in ("SEC-010", "SEC-011", "SEC-012"):
        score += 70
        pos.append(f"Definitive cryptographic private key header: {candidate.rule.title} (+70)")
    elif candidate.rule.rule_id in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-006"):
        score += 45
        pos.append(f"High-confidence provider signature: {candidate.rule.title} (+45)")
    elif candidate.rule.rule_id in ("SEC-005", "SEC-007", "SEC-008", "SEC-014", "SEC-015", "SEC-017", "SEC-018"):
        score += 35
        pos.append(f"Provider signature: {candidate.rule.title} (+35)")
    else:
        score += 20
        pos.append(f"Generic pattern matched: {candidate.rule.title} (+20)")

    # Semantic variable name context (e.g. api_key = ..., token = ...)
    if re.search(r"(?i)(?:api_key|token|secret|password|private_key|access_key)\s*[:=]", line):
        score += 25
        pos.append("Explicit credential assignment in variable name (+25)")

    # Quoted string literal
    is_quoted = bool(re.search(r"""["'][^"']{8,}["']""", line))
    if is_quoted:
        score += 15
        pos.append("Value is an explicit quoted string literal (+15)")

    # Entropy in true cryptographic secret band (3.8 - 5.5)
    if 3.8 <= ent <= 5.5 and len(token) >= 16:
        score += 20
        pos.append(f"Cryptographic-band entropy: {ent:.2f} bits/char (+20)")

    # JWT detected inside payload
    if payload.is_jwt:
        score += 35
        pos.append("Decoded JWT header payload structure (+35)")

    # Config / Env file primary region
    if topology.primary_region == RegionType.CONFIG_KV:
        score += 10
        pos.append("Located in configuration/environment file (+10)")

    # =========================================================================
    # 2. NEGATIVE SIGNALS (SUPPRESSION)
    # =========================================================================
    # Media payload or Base64 image data URI
    if line_region == RegionType.MEDIA_BASE64 or topology.is_media_file:
        score -= 75
        neg.append("Topological region is media / Base64 image stream (-75)")

    if payload.is_media_or_binary:
        score -= 80
        neg.append(f"Decoded magic bytes indicate {payload.mime_type} binary data (-80)")

    # Lockfile integrity hashes
    if line_region == RegionType.LOCKFILE or topology.is_lockfile:
        score -= 70
        neg.append("Inside dependency lockfile integrity hash (-70)")

    # Documentation / Example files
    if line_region == RegionType.DOCS or topology.is_doc_file:
        score -= 30
        neg.append("Located in documentation file (-30)")

    # Explicit placeholder words
    if PLACEHOLDER_RE.search(token) or PLACEHOLDER_RE.search(line):
        score -= 60
        neg.append("Contains obvious placeholder / dummy token words (-60)")

    # Environment variable references (os.getenv, os.environ)
    if ENV_RETRIEVAL_RE.search(line):
        score -= 60
        neg.append("Line references environment variable retrieval (-60)")

    # Function definition signature
    if FUNC_DEF_RE.match(line):
        score -= 60
        neg.append("Inside function definition parameter signature (-60)")

    # Regex / Pattern definitions (e.g. re.compile(r"..."), pattern = "...")
    if re.search(r"re\.compile|regex\s*=|pattern\s*=|CandidateRule\(", line):
        score -= 75
        neg.append("Inside regular expression or pattern definition (-75)")

    # Safe constants (None, False, True, empty string)
    if SAFE_CONSTANTS_RE.match(token):
        score -= 70
        neg.append("Value is a safe language constant (None/False/True) (-70)")

    # Unquoted code variable in a programming language file
    if topology.primary_region == RegionType.CODE and candidate.rule.requires_quoted_literal and not is_quoted:
        score -= 60
        neg.append("Unquoted code variable assignment / expression pass-through (-60)")

    # Low entropy (plain English word or variable identifier)
    if ent < 3.0 and len(token) > 8:
        score -= 35
        neg.append(f"Low entropy ({ent:.2f} bits/char) indicates natural language or identifier (-35)")

    # =========================================================================
    # 3. FINAL AGGREGATION & SEVERITY MAPPING
    # =========================================================================
    clamped_score = max(0, min(100, score))
    is_credible = clamped_score >= 50

    # Map score to severity
    if clamped_score >= 80:
        sev = candidate.rule.severity
    elif clamped_score >= 60:
        sev = Severity.HIGH if candidate.rule.severity == Severity.CRITICAL else candidate.rule.severity
    elif clamped_score >= 50:
        sev = Severity.MEDIUM
    elif clamped_score >= 30:
        sev = Severity.LOW
    else:
        sev = Severity.INFO

    return EvidenceReport(
        total_score=clamped_score,
        is_credible_secret=is_credible,
        severity=sev,
        entropy=ent,
        positive_signals=pos,
        negative_signals=neg,
        payload_info=payload if payload.is_base64_encoded else None,
    )
