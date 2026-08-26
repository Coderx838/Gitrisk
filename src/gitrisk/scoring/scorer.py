"""Repository health scoring engine."""

from __future__ import annotations

from gitrisk.core.models import CategoryScore, Finding, Severity

# Category names and their weight in overall score
CATEGORY_WEIGHTS: dict[str, float] = {
    "secrets": 0.25,
    "dependencies": 0.20,
    "git": 0.15,
    "configuration": 0.20,
    "policy": 0.10,
    "general": 0.10,
}

# Penalty per severity per finding
SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def compute_scores(
    findings: list[Finding],
) -> tuple[list[CategoryScore], int]:
    """Compute category and overall scores from findings."""
    # Group findings by category
    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.scanner, []).append(f)

    # Compute per-category scores
    category_scores: list[CategoryScore] = []
    all_categories = set(CATEGORY_WEIGHTS.keys())

    # Map scanner name -> category
    scanner_to_category = {
        "secrets": "secrets",
        "dependencies": "dependencies",
        "outdated": "dependencies",
        "env": "configuration",
        "github_actions": "configuration",
        "gitignore": "git",
        "sensitive_files": "secrets",
        "git_config": "git",
        "security_policy": "policy",
        "hardcoding": "secrets",
    }

    cat_penalties: dict[str, int] = {c: 0 for c in all_categories}
    cat_finding_counts: dict[str, int] = {c: 0 for c in all_categories}

    for scanner_name, scanner_findings in by_category.items():
        cat = scanner_to_category.get(scanner_name, "general")
        for f in scanner_findings:
            cat_penalties[cat] += SEVERITY_PENALTY[f.severity]
            cat_finding_counts[cat] += 1

    for cat in all_categories:
        raw_score = max(0, 100 - cat_penalties[cat])
        category_scores.append(
            CategoryScore(
                name=cat.capitalize(),
                score=raw_score,
                findings=cat_finding_counts[cat],
            )
        )

    # Weighted overall score
    overall = 0.0
    for cs in category_scores:
        weight = CATEGORY_WEIGHTS.get(cs.name.lower(), 0.1)
        overall += cs.score * weight

    # Normalize if weights don't sum to 1
    total_weight = sum(CATEGORY_WEIGHTS.values())
    overall = overall / total_weight if total_weight else overall
    overall_int = max(0, min(100, int(overall)))

    return category_scores, overall_int
