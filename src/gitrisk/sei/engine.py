"""Secret Intelligence Engine (SEI) Coordinator.

Unifies content topology, token reconstruction, multi-signal evidence scoring,
and secret fingerprinting to evaluate working tree files and Git commit diffs.
"""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple, Optional

from gitrisk.core.models import Finding, FixType, Severity
from gitrisk.sei.candidates import extract_raw_candidates
from gitrisk.sei.evidence import EvidenceReport, evaluate_candidate_evidence
from gitrisk.sei.fingerprint import generate_fingerprint
from gitrisk.sei.reconstructor import reconstruct_tokens
from gitrisk.sei.topology import RegionType, TopologyMap, analyze_file_topology, classify_line_region


class SEICandidate(NamedTuple):
    rule_id: str
    title: str
    extracted_secret: str
    evidence: EvidenceReport
    fingerprint_id: str
    redacted_preview: str


class SEIEvaluation(NamedTuple):
    findings: list[Finding]
    suppressed_count: int


class SecretIntelligenceEngine:
    """The central coordinator of the GitRisk Secret Intelligence Engine (SEI)."""

    def __init__(self, repo_path: Optional[Path] = None) -> None:
        self.repo_path = repo_path

    def evaluate_line(
        self,
        line: str,
        line_number: int,
        filepath: Optional[Path],
        topology: Optional[TopologyMap] = None,
        commit_hash: Optional[str] = None,
    ) -> list[Finding]:
        """Analyze a single line or diff addition through the complete SEI pipeline."""
        findings: list[Finding] = []
        
        topo = topology or analyze_file_topology(filepath)
        line_region = classify_line_region(line, topo)

        # 1. Direct candidates from raw line
        raw_candidates = extract_raw_candidates(line, line_number)

        # 2. Reconstructed split string candidates (e.g. "AIza" + "Sy123...")
        reconstructed = reconstruct_tokens(line)
        for recon in reconstructed:
            recon_candidates = extract_raw_candidates(recon.reconstructed_value, line_number)
            raw_candidates.extend(recon_candidates)

        # Sort candidates so specific provider signatures (SEC-001..SEC-019) take precedence
        # over generic variable assignments (SEC-020)
        raw_candidates.sort(key=lambda c: 99 if c.rule.rule_id == "SEC-020" else 1)

        seen_fingerprints: set[str] = set()

        for cand in raw_candidates:
            # 3. Multi-Signal Evidence Scoring
            evidence = evaluate_candidate_evidence(cand, topo, line_region)
            if not evidence.is_credible_secret:
                continue  # Suppressed as noise / media / placeholder / variable

            # 4. Fingerprint generation & deduplication
            fp = generate_fingerprint(cand.extracted_secret)
            if fp.fingerprint_id in seen_fingerprints:
                continue
            seen_fingerprints.add(fp.fingerprint_id)

            # 5. Build standard GitRisk Finding
            rel_file = filepath.relative_to(self.repo_path) if (filepath and self.repo_path and filepath.is_relative_to(self.repo_path)) else (filepath or Path("unknown"))
            
            if commit_hash:
                title = f"Secret exposed in Git history (commit {commit_hash[:12]})"
                desc = (
                    f"A verified {cand.rule.title.lower()} was discovered in Git commit {commit_hash[:12]} "
                    f"in file {rel_file}. Confidence score: {evidence.total_score}/100. "
                    f"Entropy: {evidence.entropy:.2f} bits/char. Fingerprint: {fp.fingerprint_id}."
                )
                remediation = (
                    f"1. Immediately revoke and rotate the exposed credential.\\n"
                    f"2. Clean Git history using git-filter-repo:\\n"
                    f"   pip install git-filter-repo\\n"
                    f"   git filter-repo --path {rel_file} --invert-paths\\n"
                    f"3. Force-push to all remotes and notify collaborators."
                )
                finding_id = cand.rule.rule_id
            else:
                title = f"{cand.rule.title} detected"
                desc = (
                    f"A verified {cand.rule.title.lower()} was found in {rel_file}:{line_number}. "
                    f"SEI Confidence score: {evidence.total_score}/100 (Entropy: {evidence.entropy:.2f} bits/char). "
                    f"Fingerprint: {fp.fingerprint_id}."
                )
                remediation = (
                    f"1. Immediately revoke and rotate the exposed credential.\\n"
                    f"2. Move the secret to an environment variable or secrets manager.\\n"
                    f"3. Ensure the containing file is in .gitignore if not already tracked."
                )
                finding_id = cand.rule.rule_id

            findings.append(Finding(
                id=finding_id,
                scanner="secrets" if not commit_hash else "git_history",
                title=title,
                description=desc,
                severity=evidence.severity,
                fix_type=FixType.MANUAL,
                remediation=remediation,
                file=filepath,
                line=line_number,
                evidence=f"{fp.redacted_preview} (SEI Score: {evidence.total_score}/100)",
                references=[
                    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
                    "https://trufflesecurity.com/blog/oops-i-committed-a-secret",
                ],
            ))

        # If any specific provider rule matched on this line (e.g. SEC-001..SEC-019),
        # filter out any redundant generic SEC-020 assignments for the same line.
        if any(f.id != "SEC-020" for f in findings):
            findings = [f for f in findings if f.id != "SEC-020"]

        return findings
