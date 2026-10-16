"""Pure comparison of the control states supplied in two local snapshots."""

from dataclasses import dataclass
from datetime import UTC, datetime

from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.summary import CONTROL_FIELDS


@dataclass(frozen=True, slots=True)
class ControlChange:
    """One supplied state transition, or a change of default-branch scope."""

    repository: str
    control: str
    before: ControlState
    after: ControlState
    classification: str


@dataclass(frozen=True, slots=True)
class SnapshotComparison:
    """Deterministic differences between supplied files, without live verification."""

    baseline_at: datetime
    current_at: datetime
    organization: str
    added_repositories: tuple[str, ...]
    missing_repositories: tuple[str, ...]
    changes: tuple[ControlChange, ...]
    unchanged_controls: int
    warnings: tuple[str, ...]


def compare_snapshots(
    baseline: OrgSecuritySnapshot, current: OrgSecuritySnapshot
) -> SnapshotComparison:
    """Compare exact repository names and state values in chronological snapshots.

    The result describes only the supplied snapshots. It does not establish GitHub
    provenance, remediation, enforcement, or the creation/deletion of repositories.
    """
    if baseline.organization != current.organization:
        raise ValueError("Snapshots must have the same organization or owner.")
    for label, snapshot in (("Baseline", baseline), ("Current", current)):
        if snapshot.generated_at.tzinfo is None or snapshot.generated_at.utcoffset() is None:
            raise ValueError(f"{label} snapshot timestamp must include a timezone.")
    baseline_time = baseline.generated_at.astimezone(UTC)
    current_time = current.generated_at.astimezone(UTC)
    if current_time < baseline_time:
        raise ValueError("Current snapshot timestamp must not precede the baseline timestamp.")

    before_repositories = _repositories_by_name(baseline)
    after_repositories = _repositories_by_name(current)
    warnings = [
        "Local comparison of supplied snapshot states only; no GitHub API calls or provenance "
        "verification were performed.",
        "Repository membership reflects these files only; token visibility or inventory filtering "
        "may differ. Added and missing do not establish creation or deletion on GitHub.",
        "Branch protection compares default-branch scope only; default_branch changes are "
        "classified as scope_changed.",
        "Supplied enabled/disabled states do not prove remediation, enforcement, or vulnerability "
        "absence.",
    ]
    if current_time == baseline_time:
        warnings.append(
            "Snapshot timestamps are equal; no elapsed observation interval is established."
        )
    warnings.extend(f"baseline: {warning}" for warning in baseline.warnings)
    warnings.extend(f"current: {warning}" for warning in current.warnings)

    changes: list[ControlChange] = []
    unchanged_controls = 0
    for name in sorted(before_repositories.keys() & after_repositories.keys()):
        before_repository = before_repositories[name]
        after_repository = after_repositories[name]
        branch_changed = before_repository.default_branch != after_repository.default_branch
        for control, _ in CONTROL_FIELDS:
            before: ControlState = getattr(before_repository, control)
            after: ControlState = getattr(after_repository, control)
            if control == "branch_protection" and branch_changed:
                classification = "scope_changed"
            elif before == after:
                unchanged_controls += 1
                continue
            else:
                classification = _classify_change(before, after)
            changes.append(ControlChange(name, control, before, after, classification))

    return SnapshotComparison(
        baseline_at=baseline.generated_at,
        current_at=current.generated_at,
        organization=baseline.organization,
        added_repositories=tuple(sorted(after_repositories.keys() - before_repositories.keys())),
        missing_repositories=tuple(sorted(before_repositories.keys() - after_repositories.keys())),
        changes=tuple(changes),
        unchanged_controls=unchanged_controls,
        warnings=tuple(warnings),
    )


def _repositories_by_name(
    snapshot: OrgSecuritySnapshot,
) -> dict[str, RepositorySecurityControls]:
    repositories: dict[str, RepositorySecurityControls] = {}
    for repository in snapshot.repositories:
        if repository.name in repositories:
            raise ValueError("A snapshot contains duplicate repository names.")
        repositories[repository.name] = repository
    return repositories


def _classify_change(before: ControlState, after: ControlState) -> str:
    known = (ControlState.ENABLED, ControlState.DISABLED)
    if before in known and after in known:
        return "enabled_observed" if after is ControlState.ENABLED else "disabled_observed"
    if after in known:
        return "evidence_gained"
    if before in known:
        return "evidence_lost"
    return "gap_changed"
