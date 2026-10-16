"""Markdown report rendering for organization security snapshots."""

import re

from ghorgsec.actions import plan_next_steps
from ghorgsec.comparison import SnapshotComparison
from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.risk import RepositoryRisk, rate_snapshot
from ghorgsec.summary import CONTROL_FIELDS, ControlCoverage, summarize_snapshot

MISSING_REPOSITORY_METADATA = "not_collected"
NOT_ASSESSED_COVERAGE = "not_assessed"

# Newlines, tabs and other control characters fold to a space before rendering.
_CONTROL_CHARACTERS = dict.fromkeys([*range(0x20), 0x7F], " ")
_MARKDOWN_ESCAPES = str.maketrans({character: "\\" + character for character in "\\|&<>`*_[]~!"})


def render_markdown_report(snapshot: OrgSecuritySnapshot) -> str:
    """Render a basic Markdown dashboard report."""

    owner_label = (
        "Personal account" if snapshot.collection_mode == "github_live_user" else "Organization"
    )
    lines = [
        "# GitHub Org Security Dashboard",
        "",
        f"- {owner_label}: {_inline_code(snapshot.organization)}",
        f"- Collection mode: {_inline_code(snapshot.collection_mode)}",
        f"- Generated at: `{snapshot.generated_at.isoformat()}`",
        "",
    ]

    if snapshot.warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {_escape_warning(warning)}" for warning in snapshot.warnings)
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
    lines.extend(_next_steps_section(snapshot))

    return "\n".join(lines)


def render_markdown_comparison(comparison: SnapshotComparison) -> str:
    """Render changes between supplied local observations, without scoring them."""

    lines = [
        "# GitHub Security Snapshot Comparison",
        "",
        f"- Owner: {_inline_code(comparison.organization)}",
        "- Collection mode: `local_snapshot_comparison`",
        f"- Baseline at: `{comparison.baseline_at.isoformat()}`",
        f"- Current at: `{comparison.current_at.isoformat()}`",
        f"- Changed controls in matched repositories: {len(comparison.changes)}",
        f"- Unchanged controls in matched repositories: {comparison.unchanged_controls}",
        "",
        "## Warnings",
        "",
        *[f"- {_escape_warning(warning)}" for warning in comparison.warnings],
        "",
        "## Repository Membership",
        "",
        "These lists describe snapshot membership; they do not establish repository "
        "creation or deletion.",
        "",
        "### Present only in current",
        "",
        *([f"- {_escape_cell(name)}" for name in comparison.added_repositories] or ["None."]),
        "",
        "### Present only in baseline",
        "",
        *([f"- {_escape_cell(name)}" for name in comparison.missing_repositories] or ["None."]),
        "",
        "## Control Observations",
        "",
        "enabled_observed and disabled_observed describe a known-state transition. "
        "evidence_gained and evidence_lost describe collection changes; gap_changed "
        "distinguishes two evidence gaps. scope_changed marks a different default branch "
        "and takes precedence over its branch-protection state transition.",
        "",
        "| Repository | Control | Before | After | Classification |",
        "| --- | --- | --- | --- | --- |",
    ]
    labels = dict(CONTROL_FIELDS)
    lines.extend(
        f"| {_escape_cell(change.repository)} | {labels[change.control]} | "
        f"{change.before.value} | {change.after.value} | `{change.classification}` |"
        for change in comparison.changes
    )
    if not comparison.changes:
        lines.append("| _none_ | - | - | - | - |")
    lines.append("")
    return "\n".join(lines)


def _next_steps_section(snapshot: OrgSecuritySnapshot) -> list[str]:
    lines = [
        "## Next Steps",
        "",
        "Suggestions describe the supplied states. Review configuration with its owner; "
        "unknown and not_collected are evidence gaps. No GitHub settings are changed.",
        "",
    ]
    steps = plan_next_steps(snapshot)
    labels = dict(CONTROL_FIELDS)
    groups = (
        (ControlState.DISABLED, "Disabled controls", "Review configuration with the owner."),
        (ControlState.UNKNOWN, "Unknown controls", "Verify collection access and permissions."),
        (
            ControlState.NOT_COLLECTED,
            "Not collected controls",
            "Collect evidence for this control.",
        ),
    )
    for state, heading, guidance in groups:
        lines.extend([f"### {heading}", "", guidance, ""])
        selected = [step for step in steps if step.state is state]
        if selected:
            lines.extend([
                "| Repository | Control | State | Suggested action |",
                "| --- | --- | --- | --- |",
            ])
            lines.extend(
                f"| {_escape_cell(step.repository)} | {labels[step.control]} | "
                f"{step.state.value} | `{step.action}` |"
                for step in selected
            )
        else:
            lines.append("None in the supplied snapshot.")
        lines.append("")
    return lines


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
    """Show input literally in CommonMark text and table cells."""

    return _single_line(value).translate(_MARKDOWN_ESCAPES)


def _escape_warning(value: str) -> str:
    # Warning text starts a list item's block. Inline escaping alone still
    # permits headings, nested lists and thematic breaks at that position.
    text = _escape_cell(value)
    if text.startswith(("#", "+", "-")):
        return "\\" + text
    return re.sub(r"^(\d+)([.)])(?=\s)", r"\1\\\2", text)


def _inline_code(value: str) -> str:
    # Backslash escapes do not work inside CommonMark code spans. Choose a
    # delimiter longer than any input run and pad backticks at the edges.
    text = _single_line(value)
    delimiter = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"
