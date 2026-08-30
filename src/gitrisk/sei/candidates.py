"""High-Recall Candidate Generator for GitRisk SEI.

Generates candidate secret tokens across multiple detector families:
- Cloud & SaaS Provider Signatures (AWS, GitHub, Google, Stripe, Slack, etc.)
- Asymmetric Private Keys (RSA, OpenSSH, PEM)
- Semantic Credential Assignments
- Embedded URL Credentials
"""
from __future__ import annotations

import re
from typing import NamedTuple

from gitrisk.core.models import Severity


class CandidateRule(NamedTuple):
    rule_id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    requires_quoted_literal: bool


# Provider signature candidates
# Notice the strict negative lookbehind/lookahead (?<![A-Za-z0-9+/]) to prevent
# slicing random 39-character substrings out of continuous Base64 image payloads.
CANDIDATE_RULES: list[CandidateRule] = [
    CandidateRule(
        "SEC-001",
        "AWS Access Key ID",
        re.compile(r"(?<![A-Za-z0-9+/])(A[KSCB]IA[0-9A-Z]{16})(?![A-Za-z0-9+/])"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-002",
        "AWS Secret Access Key",
        re.compile(r"""(?i)aws[_\-.]?secret[_\-.]?access[_\-.]?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-003",
        "GitHub Token",
        re.compile(r"(?<![A-Za-z0-9_])(gh[pours]_[0-9a-zA-Z]{30,40})(?![A-Za-z0-9_])"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-004",
        "GitHub Fine-Grained Token",
        re.compile(r"(?<![A-Za-z0-9_])(github_pat_[0-9a-zA-Z_]{82})(?![A-Za-z0-9_])"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-005",
        "Slack Token",
        re.compile(r"(?<![A-Za-z0-9_-])(xox[baprs]-[0-9A-Za-z]{10,48})(?![A-Za-z0-9_-])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-006",
        "Stripe Secret Key",
        re.compile(r"(?<![A-Za-z0-9_])(sk_live_[0-9a-zA-Z]{24,})(?![A-Za-z0-9_])"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-007",
        "Stripe Publishable Key",
        re.compile(r"(?<![A-Za-z0-9_])(pk_live_[0-9a-zA-Z]{24,})(?![A-Za-z0-9_])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-008",
        "Google API Key",
        # Strict boundary: AIza must not be preceded or followed by Base64 chars
        re.compile(r"(?<![A-Za-z0-9+/=_-])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9+/=_-])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-009",
        "Heroku API Key",
        re.compile(r"""(?i)heroku[_\-.]?(?:api[_\-.]?)?(?:key|token|secret)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"""),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-010",
        "RSA Private Key",
        re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-011",
        "OpenSSH Private Key",
        re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-012",
        "PEM Private Key",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
        Severity.CRITICAL,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-013",
        "Twilio Auth Token",
        re.compile(r"""(?i)twilio.*['"]?([0-9a-f]{32})['"]?"""),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-014",
        "SendGrid API Key",
        re.compile(r"(?<![A-Za-z0-9_])(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})(?![A-Za-z0-9_])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-015",
        "Mailgun API Key",
        re.compile(r"(?<![A-Za-z0-9_])(key-[0-9a-zA-Z]{32})(?![A-Za-z0-9_])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-016",
        "Slack Webhook URL",
        re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+)"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-017",
        "NPM Token",
        re.compile(r"(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9_])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-018",
        "PyPI Token",
        re.compile(r"(?<![A-Za-z0-9_])(pypi-[A-Za-z0-9\-_]{50,})(?![A-Za-z0-9_])"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-019",
        "Basic Auth in URL",
        re.compile(r"https?://([^:@\s]+):([^:@\s]+)@[^\s]+"),
        Severity.HIGH,
        requires_quoted_literal=False,
    ),
    CandidateRule(
        "SEC-020",
        "Generic Secret Assignment",
        re.compile(r"(?i)(secret|password|passwd|api_key|auth_token|access_token|private_key)\s*[=:]\s*(\S+)"),
        Severity.MEDIUM,
        requires_quoted_literal=True,
    ),
]


class RawCandidate(NamedTuple):
    rule: CandidateRule
    matched_text: str
    extracted_secret: str
    line_number: int
    raw_line: str


def extract_raw_candidates(line: str, line_number: int) -> list[RawCandidate]:
    """Run all candidate generators over a single line of text."""
    candidates: list[RawCandidate] = []
    
    for rule in CANDIDATE_RULES:
        for match in rule.pattern.finditer(line):
            matched_text = match.group(0)
            # If regex has capture groups, use group 1, else entire match
            if match.lastindex and match.lastindex >= 1:
                extracted = match.group(match.lastindex)
            else:
                extracted = matched_text

            candidates.append(RawCandidate(
                rule=rule,
                matched_text=matched_text,
                extracted_secret=extracted,
                line_number=line_number,
                raw_line=line,
            ))
            
    return candidates
