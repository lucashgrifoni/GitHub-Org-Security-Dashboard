"""Contract tests for local state comparisons, including evidence and scope gaps."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from ghorgsec.comparison import ControlChange, SnapshotComparison, compare_snapshots
from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)

BASELINE_AT = datetime(2026, 1, 1, tzinfo=UTC)
CURRENT_AT = datetime(2026, 1, 2, tzinfo=UTC)


def _repo(
    name: str = "api",
    state: ControlState = ControlState.ENABLED,
    *,
    default_branch: str | None = "main",
) -> RepositorySecurityControls:
    return RepositorySecurityControls(
        name=name,
        branch_protection=state,
        secret_scanning=state,
        code_scanning=state,
        dependabot_alerts=state,
        default_branch=default_branch,
    )


def _snapshot(
    *repositories: RepositorySecurityControls,
    generated_at: datetime = BASELINE_AT,
    owner: str = "example-org",
    warnings: tuple[str, ...] = (),
) -> OrgSecuritySnapshot:
    return OrgSecuritySnapshot(owner, generated_at, "fixture_json", repositories, warnings)


@pytest.mark.parametrize(
    "before,after,classification",
    [
        (ControlState.ENABLED, ControlState.ENABLED, None),
        (ControlState.ENABLED, ControlState.DISABLED, "disabled_observed"),
        (ControlState.ENABLED, ControlState.UNKNOWN, "evidence_lost"),
        (ControlState.ENABLED, ControlState.NOT_COLLECTED, "evidence_lost"),
        (ControlState.DISABLED, ControlState.ENABLED, "enabled_observed"),
        (ControlState.DISABLED, ControlState.DISABLED, None),
        (ControlState.DISABLED, ControlState.UNKNOWN, "evidence_lost"),
        (ControlState.DISABLED, ControlState.NOT_COLLECTED, "evidence_lost"),
        (ControlState.UNKNOWN, ControlState.ENABLED, "evidence_gained"),
        (ControlState.UNKNOWN, ControlState.DISABLED, "evidence_gained"),
        (ControlState.UNKNOWN, ControlState.UNKNOWN, None),
        (ControlState.UNKNOWN, ControlState.NOT_COLLECTED, "gap_changed"),
        (ControlState.NOT_COLLECTED, ControlState.ENABLED, "evidence_gained"),
        (ControlState.NOT_COLLECTED, ControlState.DISABLED, "evidence_gained"),
        (ControlState.NOT_COLLECTED, ControlState.UNKNOWN, "gap_changed"),
        (ControlState.NOT_COLLECTED, ControlState.NOT_COLLECTED, None),
    ],
)
def test_all_sixteen_state_transitions_preserve_evidence_meaning(
    before: ControlState, after: ControlState, classification: str | None
) -> None:
    baseline = _snapshot(replace(_repo(), secret_scanning=before))
    current = _snapshot(replace(_repo(), secret_scanning=after), generated_at=CURRENT_AT)

    result = compare_snapshots(baseline, current)

    if classification is None:
        assert result.changes == ()
        assert result.unchanged_controls == 4
    else:
        assert result.changes == (
            ControlChange("api", "secret_scanning", before, after, classification),
        )
        assert result.unchanged_controls == 3
    assert result.added_repositories == result.missing_repositories == ()


def test_changes_are_sorted_by_exact_repository_name_then_control_order() -> None:
    baseline = _snapshot(_repo("z", ControlState.DISABLED), _repo("a", ControlState.DISABLED))
    current = _snapshot(
        _repo("a", ControlState.ENABLED), _repo("z", ControlState.ENABLED), generated_at=CURRENT_AT
    )
    result = compare_snapshots(baseline, current)
    expected_controls = [
        "branch_protection",
        "secret_scanning",
        "code_scanning",
        "dependabot_alerts",
    ]
    assert [(change.repository, change.control) for change in result.changes] == [
        (name, control) for name in ("a", "z") for control in expected_controls
    ]
    assert all(change.classification == "enabled_observed" for change in result.changes)
    assert result.unchanged_controls == 0
    assert result == compare_snapshots(
        replace(baseline, repositories=tuple(reversed(baseline.repositories))),
        replace(current, repositories=tuple(reversed(current.repositories))),
    )


@pytest.mark.parametrize("branches", [("main", "release"), (None, "main"), ("main", None)])
@pytest.mark.parametrize(
    "before,after",
    [
        (ControlState.ENABLED, ControlState.ENABLED),
        (ControlState.DISABLED, ControlState.ENABLED),
        (ControlState.UNKNOWN, ControlState.NOT_COLLECTED),
    ],
)
def test_default_branch_change_takes_priority_over_state_classification(
    branches: tuple[str | None, str | None], before: ControlState, after: ControlState
) -> None:
    baseline_repo = replace(_repo(default_branch=branches[0]), branch_protection=before)
    current_repo = replace(_repo(default_branch=branches[1]), branch_protection=after)
    result = compare_snapshots(
        _snapshot(baseline_repo), _snapshot(current_repo, generated_at=CURRENT_AT)
    )
    assert result.changes == (
        ControlChange("api", "branch_protection", before, after, "scope_changed"),
    )
    assert result.unchanged_controls == 3
    assert any(
        "default_branch" in warning and "scope_changed" in warning for warning in result.warnings
    )


def test_unrelated_visibility_metadata_does_not_invent_a_control_transition() -> None:
    repo = _repo()
    baseline = _snapshot(replace(repo, visibility=Visibility.PUBLIC))
    current = _snapshot(replace(repo, visibility=Visibility.PRIVATE), generated_at=CURRENT_AT)
    result = compare_snapshots(baseline, current)
    assert result.changes == ()
    assert result.unchanged_controls == 4


def test_added_and_missing_are_only_sorted_file_membership() -> None:
    baseline = _snapshot(_repo("gone-z"), _repo("common"), _repo("gone-a"))
    current = _snapshot(
        _repo("new-z", ControlState.UNKNOWN),
        _repo("common"),
        _repo("new-a", ControlState.DISABLED),
        generated_at=CURRENT_AT,
    )
    result = compare_snapshots(baseline, current)
    assert result.added_repositories == ("new-a", "new-z")
    assert result.missing_repositories == ("gone-a", "gone-z")
    assert result.changes == ()
    assert result.unchanged_controls == 4
    assert any("creation or deletion" in warning for warning in result.warnings)
    assert any("inventory filtering" in warning for warning in result.warnings)


def test_repository_names_are_exact_and_case_variants_are_distinct() -> None:
    result = compare_snapshots(
        _snapshot(_repo("API"), _repo("api")), _snapshot(_repo("api"), generated_at=CURRENT_AT)
    )
    assert result.missing_repositories == ("API",)
    assert result.added_repositories == ()
    assert result.unchanged_controls == 4


@pytest.mark.parametrize("owner", ["other-org", "Example-org", "example-org "])
def test_owner_must_match_exactly(owner: str) -> None:
    with pytest.raises(ValueError, match="same organization or owner"):
        compare_snapshots(_snapshot(), _snapshot(owner=owner, generated_at=CURRENT_AT))


def test_earlier_current_timestamp_is_rejected_by_instant_not_local_clock() -> None:
    baseline_at = datetime(2026, 1, 1, 12, tzinfo=UTC)
    earlier_at = datetime(2026, 1, 1, 13, tzinfo=timezone(timedelta(hours=2)))
    with pytest.raises(ValueError, match="must not precede"):
        compare_snapshots(_snapshot(generated_at=baseline_at), _snapshot(generated_at=earlier_at))


@pytest.mark.parametrize("naive_side", ["baseline", "current"])
def test_naive_timestamp_has_a_safe_value_error(naive_side: str) -> None:
    baseline = _snapshot(generated_at=BASELINE_AT)
    current = _snapshot(generated_at=CURRENT_AT)
    if naive_side == "baseline":
        baseline = replace(baseline, generated_at=BASELINE_AT.replace(tzinfo=None))
    else:
        current = replace(current, generated_at=CURRENT_AT.replace(tzinfo=None))
    with pytest.raises(ValueError, match="timestamp must include a timezone"):
        compare_snapshots(baseline, current)


def test_equal_instants_are_allowed_warned_and_original_offsets_preserved() -> None:
    same_instant = datetime(2026, 1, 1, 3, tzinfo=timezone(timedelta(hours=3)))
    result = compare_snapshots(_snapshot(_repo()), _snapshot(_repo(), generated_at=same_instant))
    assert result.baseline_at is BASELINE_AT
    assert result.current_at is same_instant
    assert result.organization == "example-org"
    assert result.changes == ()
    assert result.unchanged_controls == 4
    assert any("timestamps are equal" in warning for warning in result.warnings)


@pytest.mark.parametrize("duplicate_side", ["baseline", "current"])
def test_directly_constructed_duplicate_repository_names_are_rejected(duplicate_side: str) -> None:
    baseline = _snapshot(_repo())
    current = _snapshot(_repo(), generated_at=CURRENT_AT)
    if duplicate_side == "baseline":
        baseline = replace(baseline, repositories=(_repo(), _repo(state=ControlState.DISABLED)))
    else:
        current = replace(current, repositories=(_repo(), _repo(state=ControlState.DISABLED)))
    with pytest.raises(ValueError, match="duplicate repository names"):
        compare_snapshots(baseline, current)


def test_supplied_warnings_are_preserved_as_labelled_data() -> None:
    baseline = _snapshot(warnings=("a literal <warning>", "shared"))
    current = _snapshot(generated_at=CURRENT_AT, warnings=("shared", "current-only"))
    result = compare_snapshots(baseline, current)
    assert result.warnings[-4:] == (
        "baseline: a literal <warning>",
        "baseline: shared",
        "current: shared",
        "current: current-only",
    )
    assert any("no GitHub API calls" in warning for warning in result.warnings)
    assert any("provenance verification" in warning for warning in result.warnings)
    assert any("do not prove remediation" in warning for warning in result.warnings)


def test_empty_snapshots_have_no_invented_changes_or_controls() -> None:
    result = compare_snapshots(_snapshot(), _snapshot(generated_at=CURRENT_AT))
    assert result.added_repositories == result.missing_repositories == ()
    assert result.changes == ()
    assert result.unchanged_controls == 0


def test_comparison_and_changes_are_frozen_slots_dataclasses() -> None:
    result = compare_snapshots(
        _snapshot(_repo(state=ControlState.DISABLED)), _snapshot(_repo(), generated_at=CURRENT_AT)
    )
    assert isinstance(result, SnapshotComparison)
    assert isinstance(result.changes[0], ControlChange)
    for obj in (result, result.changes[0]):
        assert not hasattr(obj, "__dict__")
        with pytest.raises(FrozenInstanceError):
            setattr(obj, "organization" if obj is result else "classification", "changed")


def test_comparison_preserves_inputs_and_requires_no_file_or_network_io() -> None:
    baseline = _snapshot(_repo(state=ControlState.DISABLED), warnings=("baseline warning",))
    current = _snapshot(_repo(), generated_at=CURRENT_AT, warnings=("current warning",))
    before = (baseline, current)
    with (
        patch("builtins.open", side_effect=AssertionError("File I/O is forbidden")),
        patch("socket.create_connection", side_effect=AssertionError("Network I/O is forbidden")),
    ):
        result = compare_snapshots(baseline, current)
    assert (baseline, current) == before
    assert len(result.changes) == 4
    assert baseline.repositories[0].branch_protection is ControlState.DISABLED
    assert current.repositories[0].branch_protection is ControlState.ENABLED
