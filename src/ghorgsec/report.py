"""Markdown report rendering for organization security snapshots."""

from ghorgsec.models import OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.risk import RepositoryRisk, rate_snapshot
from ghorgsec.summary import ControlCoverage, summarize_snapshot

MISSING_REPOSITORY_METADATA = "not_collected"
NOT_ASSESSED_COVERAGE = "not_assessed"

# Newlines, tabs and other control characters fold to a space before rendering.
_CONTROL_CHARACTERS = dict.fromkeys([*range(0x20), 0x7F], " ")


def render_markdown_report(snapshot: OrgSecuritySnapshot) -> str:
    """Render a basic Markdown dashboard report."""

    lines = [
        "# GitHub Org Security Dashboard",
        "",
        f"- Organization: `{_escape_inline(snapshot.organization)}`",
        f"- Collection mode: `{_escape_inline(snapshot.collection_mode)}`",
        f"- Generated at: `{snapshot.generated_at.isoformat()}`",
        "",
    ]

    if snapshot.warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {_single_line(warning)}" for warning in snapshot.warnings)
        lines.append("")

    lines.extend(_summary_section(snapshot))

    lines.extend(
        [
            "## Repository Controls",
            "",
            "| Repository | Default branch | Visibility | Branch protection | "
            "Secret scanning | Code scanning | Dependabot alerts |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
    )

    if snapshot.repositories:
        lines.extend(_repository_row(repository) for repository in snapshot.repositories)
    else:
        lines.append(
            "| _none_ | not_collected | not_collected | not_collected | "
            "not_collected | not_collected | not_collected |"
        )

    lines.append("")
    lines.extend(_risk_section(snapshot))

    return "\n".join(lines)


def _risk_section(snapshot: OrgSecuritySnapshot) -> list[str]:
    lines = [
        "## Repository Risk",
        "",
        "Ratings describe the supplied control states only. A partial assessment does not "
        "establish the posture of controls that were not collected.",
        "",
        "| Repository | Rating | Score | Assessed | Not collected | Assessment | Factors |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]

    risks = rate_snapshot(snapshot)
    if risks:
        lines.extend(_risk_row(risk) for risk in risks)
    else:
        lines.append("| _none_ | not_assessed | 0 | 0 | - | not_assessed | - |")

    lines.append("")
    return lines


def _risk_row(risk: RepositoryRisk) -> str:
    factors = "; ".join(_escape_cell(factor) for factor in risk.factors) or "-"
    return (
        f"| {_escape_cell(risk.name)} | {risk.rating.value} | {risk.score} | "
        f"{risk.assessed_controls} | {risk.not_collected_controls} | "
        f"{risk.assessment_status} | {factors} |"
    )


def _summary_section(snapshot: OrgSecuritySnapshot) -> list[str]:
    summary = summarize_snapshot(snapshot)

    lines = [
        "## Posture Summary",
        "",
        f"- Repositories: {summary.total_repositories}",
        "",
        "| Control | Enabled | Disabled | Unknown | Not collected | Enabled coverage |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    lines.extend(_coverage_row(coverage) for coverage in summary.controls)
    lines.append("")
    return lines


def _coverage_row(coverage: ControlCoverage) -> str:
    # A control nobody collected is not a control that is off. Reporting 0% for
    # both makes them indistinguishable, so an uncollected control says so —
    # the same answer the risk table already gives via ``not_assessed``.
    reported = (
        NOT_ASSESSED_COVERAGE
        if coverage.assessed == 0
        else f"{coverage.coverage_percent}%"
    )
    return (
        f"| {coverage.label} | {coverage.enabled} | {coverage.disabled} | "
        f"{coverage.unknown} | {coverage.not_collected} | {reported} |"
    )


def _repository_row(repository: RepositorySecurityControls) -> str:
    return " | ".join(
        [
            f"| {_escape_cell(repository.name)}",
            _optional_cell(repository.default_branch),
            _optional_cell(repository.visibility),
            repository.branch_protection.value,
            repository.secret_scanning.value,
            repository.code_scanning.value,
            f"{repository.dependabot_alerts.value} |",
        ]
    )


def _optional_cell(value: str | None) -> str:
    if value is None:
        return MISSING_REPOSITORY_METADATA

    return _escape_cell(value)


def _single_line(value: str) -> str:
    """Collapse a value onto one line so it cannot forge document structure.

    Repository and organization names arrive from a fixture the operator did
    not necessarily author. Escaping only the delimiter of the surrounding
    context leaves the line structure open: a value carrying a newline injects
    Markdown headings and splits a table row, making the report assert a shape
    the underlying data never supported.
    """

    return " ".join(value.translate(_CONTROL_CHARACTERS).split())


def _escape_cell(value: str) -> str:
    return _single_line(value).replace("|", "\\|")


def _escape_inline(value: str) -> str:
    return _single_line(value).replace("`", "\\`")
