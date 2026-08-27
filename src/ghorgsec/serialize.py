"""Deterministic JSON serialization for organization security snapshots.

Pure functions only. The dict shape is a stable contract: keys are emitted in a
fixed order and values are JSON-native, so output is reproducible and safe to
pipe into other tools.
"""

from __future__ import annotations

import json
from typing import Any

from ghorgsec.models import OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.risk import RepositoryRisk, rate_repository
from ghorgsec.summary import ControlCoverage, summarize_snapshot


def snapshot_to_dict(snapshot: OrgSecuritySnapshot) -> dict[str, Any]:
    """Convert a snapshot (plus derived posture summary) into a JSON-ready dict."""

    summary = summarize_snapshot(snapshot)

    return {
        "organization": snapshot.organization,
        "generated_at": snapshot.generated_at.isoformat(),
        "collection_mode": snapshot.collection_mode,
        "warnings": list(snapshot.warnings),
        "summary": {
            "total_repositories": summary.total_repositories,
            "controls": [_coverage_to_dict(coverage) for coverage in summary.controls],
        },
        "repositories": [_repository_to_dict(repo) for repo in snapshot.repositories],
    }


def render_json_report(snapshot: OrgSecuritySnapshot) -> str:
    """Render a deterministic, indented JSON report for the snapshot."""

    return json.dumps(snapshot_to_dict(snapshot), indent=2, ensure_ascii=False)


def _coverage_to_dict(coverage: ControlCoverage) -> dict[str, Any]:
    return {
        "field": coverage.field,
        "label": coverage.label,
        "enabled": coverage.enabled,
        "disabled": coverage.disabled,
        "unknown": coverage.unknown,
        "not_collected": coverage.not_collected,
        "total": coverage.total,
        "coverage_percent": coverage.coverage_percent,
    }


def _repository_to_dict(repository: RepositorySecurityControls) -> dict[str, Any]:
    return {
        "name": repository.name,
        "default_branch": repository.default_branch,
        "visibility": repository.visibility.value if repository.visibility else None,
        "controls": {
            "branch_protection": repository.branch_protection.value,
            "secret_scanning": repository.secret_scanning.value,
            "code_scanning": repository.code_scanning.value,
            "dependabot_alerts": repository.dependabot_alerts.value,
        },
        "risk": _risk_to_dict(rate_repository(repository)),
    }


def _risk_to_dict(risk: RepositoryRisk) -> dict[str, Any]:
    return {
        "rating": risk.rating.value,
        "score": risk.score,
        "assessed_controls": risk.assessed_controls,
        "factors": list(risk.factors),
    }
