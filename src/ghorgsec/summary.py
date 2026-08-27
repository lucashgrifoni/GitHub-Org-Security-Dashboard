"""Posture aggregation for organization security snapshots.

Pure, deterministic aggregation over an in-memory snapshot. No I/O, no network.
"""

from __future__ import annotations

from dataclasses import dataclass

from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls

# Ordered (attribute, display label) pairs for the modeled controls. The order
# defines column/row order across the report so output stays deterministic.
CONTROL_FIELDS: tuple[tuple[str, str], ...] = (
    ("branch_protection", "Branch protection"),
    ("secret_scanning", "Secret scanning"),
    ("code_scanning", "Code scanning"),
    ("dependabot_alerts", "Dependabot alerts"),
)


@dataclass(frozen=True, slots=True)
class ControlCoverage:
    """Aggregate counts for a single control across all repositories."""

    field: str
    label: str
    enabled: int
    disabled: int
    unknown: int
    not_collected: int

    @property
    def total(self) -> int:
        return self.enabled + self.disabled + self.unknown + self.not_collected

    @property
    def assessed(self) -> int:
        """Repositories with a known state for this control.

        Mirrors ``RepositoryRisk.assessed_controls``: it is the denominator of
        ``coverage_percent``, and zero means the control was never collected,
        which is not the same as the control being off.
        """

        return self.enabled + self.disabled + self.unknown

    @property
    def coverage_percent(self) -> int:
        """Percentage of repositories with the control enabled (integer floor).

        ``not_collected`` repositories are excluded from the denominator so a
        skeleton snapshot with no real data does not report misleading 0%
        coverage. Returns 0 when no repository has a known state.
        """

        if self.assessed == 0:
            return 0
        return self.enabled * 100 // self.assessed


@dataclass(frozen=True, slots=True)
class PostureSummary:
    """Organization-level posture aggregation derived from a snapshot."""

    total_repositories: int
    controls: tuple[ControlCoverage, ...]


def summarize_snapshot(snapshot: OrgSecuritySnapshot) -> PostureSummary:
    """Aggregate per-control state counts across the snapshot's repositories."""

    controls = tuple(
        _coverage_for_field(field, label, snapshot.repositories)
        for field, label in CONTROL_FIELDS
    )
    return PostureSummary(
        total_repositories=len(snapshot.repositories),
        controls=controls,
    )


def _coverage_for_field(
    field: str,
    label: str,
    repositories: tuple[RepositorySecurityControls, ...],
) -> ControlCoverage:
    counts: dict[ControlState, int] = dict.fromkeys(ControlState, 0)

    for repository in repositories:
        state = getattr(repository, field)
        counts[state] += 1

    return ControlCoverage(
        field=field,
        label=label,
        enabled=counts[ControlState.ENABLED],
        disabled=counts[ControlState.DISABLED],
        unknown=counts[ControlState.UNKNOWN],
        not_collected=counts[ControlState.NOT_COLLECTED],
    )
