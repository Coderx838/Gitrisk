"""SARIF reporter — Static Analysis Results Interchange Format output."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from gitrisk import __version__
from gitrisk.core.models import ScanResults, Severity

# SARIF severity mapping
SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SARIFReporter:
    """Render scan results as SARIF 2.1.0."""

    def render(self, results: ScanResults) -> str:
        rules: dict[str, dict] = {}
        sarif_results = []

        for finding in results.findings:
            # Register rule
            if finding.id not in rules:
                rules[finding.id] = {
                    "id": finding.id,
                    "name": finding.title.replace(" ", ""),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "helpUri": finding.references[0] if finding.references else "",
                    "properties": {
                        "security-severity": self._cvss_from_severity(finding.severity),
                    },
                }

            result: dict = {
                "ruleId": finding.id,
                "level": SEVERITY_TO_SARIF[finding.severity],
                "message": {"text": finding.description},
                "locations": [],
            }

            if finding.file:
                uri = Path(finding.file).as_uri()
                loc = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                    }
                }
                if finding.line:
                    loc["physicalLocation"]["region"] = {"startLine": finding.line}
                result["locations"].append(loc)

            sarif_results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GitRisk",
                            "version": __version__,
                            "informationUri": "https://github.com/gitrisk/gitrisk",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                        }
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _cvss_from_severity(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "9.8",
            Severity.HIGH: "7.5",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "2.5",
            Severity.INFO: "0.0",
        }[severity]