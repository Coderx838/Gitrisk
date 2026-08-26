"""JSON reporter — machine-readable output."""

from __future__ import annotations

import json
from datetime import datetime

from gitrisk import __version__
from gitrisk.core.models import ScanResults


class JSONReporter:
    """Render scan results as JSON."""

    def render(self, results: ScanResults) -> str:
        output = {
            "gitrisk_version": __version__,
            "scanned_at": datetime.now().isoformat(),
            "repository": str(results.repo_path),
            "repo_name": results.repo_name,
            "files_scanned": results.files_scanned,
            "overall_score": results.overall_score,
            "category_scores": [
                {"name": cs.name, "score": cs.score, "findings": cs.findings}
                for cs in results.category_scores
            ],
            "summary": {
                "total": len(results.findings),
                "critical": results.critical_count,
                "high": results.high_count,
                "medium": results.medium_count,
                "low": results.low_count,
                "info": results.info_count,
            },
            "findings": [f.to_dict() for f in results.findings],
        }
        return json.dumps(output, indent=2, default=str)