"""GitHub Actions scanner — detects excessive permissions and unsafe patterns."""

from __future__ import annotations

import re
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from gitrisk.core.base import BaseScanner
from gitrisk.core.models import Finding, FixType, Severity

# Dangerous permissions
DANGEROUS_WRITE_PERMS = [
    "contents: write",
    "packages: write",
    "actions: write",
    "deployments: write",
    "id-token: write",
    "pull-requests: write",
    "security-events: write",
    "statuses: write",
    "checks: write",
    "issues: write",
]


class GitHubActionsScanner(BaseScanner):
    """Scanner 4: Detect excessive permissions and risky patterns in GitHub Actions workflows."""

    name = "github_actions"
    description = "Detects excessive permissions and unsafe patterns in GitHub Actions workflows."
    category = "configuration"

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        workflows_dir = self.repo_path / ".github" / "workflows"

        if not workflows_dir.exists():
            return findings

        for wf_file in workflows_dir.glob("*.yml"):
            findings.extend(self._check_workflow(wf_file))
        for wf_file in workflows_dir.glob("*.yaml"):
            findings.extend(self._check_workflow(wf_file))

        return findings

    def _check_workflow(self, wf_file: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = wf_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        # Check for write-all permissions
        if re.search(r"permissions:\s*write-all", content):
            findings.append(Finding(
                id="GHA-001",
                scanner=self.name,
                title=f"Workflow uses write-all permissions: {self._rel(wf_file)}",
                description=(
                    f"`{self._rel(wf_file)}` grants `write-all` permissions to the workflow token. "
                    f"This gives the workflow write access to all repository resources, which is "
                    f"excessive for most CI tasks and increases the blast radius of a supply-chain attack."
                ),
                severity=Severity.HIGH,
                fix_type=FixType.REVIEW,
                remediation=(
                    "Replace `permissions: write-all` with the minimum required permissions.\n"
                    "Example:\n"
                    "  permissions:\n"
                    "    contents: read\n"
                    "    pull-requests: write"
                ),
                file=wf_file,
                references=[
                    "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
                ],
            ))

        # Check for individual dangerous write permissions
        for line_no, line in enumerate(content.splitlines(), start=1):
            for perm in DANGEROUS_WRITE_PERMS:
                if perm in line:
                    findings.append(Finding(
                        id="GHA-002",
                        scanner=self.name,
                        title=f"Elevated write permission in workflow: {perm}",
                        description=(
                            f"`{self._rel(wf_file)}` grants `{perm}` at line {line_no}. "
                            f"Granting write permissions beyond what is needed increases the risk "
                            f"of a compromised workflow modifying repository contents."
                        ),
                        severity=Severity.MEDIUM,
                        fix_type=FixType.REVIEW,
                        remediation=f"Review whether `{perm}` is required. If not, remove it or restrict to read access.",
                        file=wf_file,
                        line=line_no,
                        evidence=line.strip(),
                        references=[
                            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
                        ],
                    ))

        # Check for pull_request_target without ref pinning
        if "pull_request_target" in content and "ref:" not in content:
            findings.append(Finding(
                id="GHA-003",
                scanner=self.name,
                title=f"Dangerous pull_request_target trigger: {self._rel(wf_file)}",
                description=(
                    f"`{self._rel(wf_file)}` uses `pull_request_target` which runs with write access "
                    f"to the base repository. Combined with `actions/checkout` of the PR head, "
                    f"this can lead to arbitrary code execution from untrusted forks."
                ),
                severity=Severity.HIGH,
                fix_type=FixType.REVIEW,
                remediation=(
                    "Review whether `pull_request_target` is necessary. If checking out PR code, "
                    "always pin the ref to a trusted SHA and avoid granting write permissions."
                ),
                file=wf_file,
                references=[
                    "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                ],
            ))

        # Check for missing permissions block
        if "permissions:" not in content:
            findings.append(Finding(
                id="GHA-004",
                scanner=self.name,
                title=f"No explicit permissions block in workflow: {self._rel(wf_file)}",
                description=(
                    f"`{self._rel(wf_file)}` does not define a `permissions` block. "
                    f"Without explicit permissions, GitHub grants the default token permissions, "
                    f"which can be overly broad depending on repository settings."
                ),
                severity=Severity.LOW,
                fix_type=FixType.REVIEW,
                remediation=(
                    "Add a `permissions` block to restrict the GITHUB_TOKEN to only what is needed.\n"
                    "Minimum viable:\n"
                    "  permissions:\n"
                    "    contents: read"
                ),
                file=wf_file,
                references=[
                    "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
                ],
            ))

        return findings
