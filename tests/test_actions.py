"""Behavior checks for suggested review and evidence steps."""

from dataclasses import FrozenInstanceError, asdict, replace
from datetime import UTC, datetime

import pytest

from ghorgsec.actions import NextStep, plan_next_steps
from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls


def _repository(
    name: str,
    branch_protection: ControlState = ControlState.ENABLED,
    secret_scanning: ControlState = ControlState.ENABLED,
    code_scanning: ControlState = ControlState.ENABLED,
    dependabot_alerts: ControlState = ControlState.ENABLED,
) -> RepositorySecurityControls:
    return RepositorySecurityControls(
        name=name,
        branch_protection=branch_protection,
        secret_scanning=secret_scanning,
        code_scanning=code_scanning,
        dependabot_alerts=dependabot_alerts,
    )


def _snapshot(*repositories: RepositorySecurityControls) -> OrgSecuritySnapshot:
    return OrgSecuritySnapshot(
        organization="example-org",
        generated_at=datetime(2026, 10, 6, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=repositories,
        warnings=("Synthetic snapshot only.",),
    )


@pytest.mark.parametrize(
    "control",
    ["branch_protection", "secret_scanning", "code_scanning", "dependabot_alerts"],
)
@pytest.mark.parametrize(
    ("state", "action"),
    [
        (ControlState.DISABLED, "review_configuration"),
        (ControlState.UNKNOWN, "verify_access"),
        (ControlState.NOT_COLLECTED, "collect_evidence"),
        (ControlState.ENABLED, None),
    ],
)
def test_each_control_preserves_state_and_suggests_its_action(
    control: str, state: ControlState, action: str | None
) -> None:
    repository = _repository(
        "api",
        branch_protection=state if control == "branch_protection" else ControlState.ENABLED,
        secret_scanning=state if control == "secret_scanning" else ControlState.ENABLED,
        code_scanning=state if control == "code_scanning" else ControlState.ENABLED,
        dependabot_alerts=state if control == "dependabot_alerts" else ControlState.ENABLED,
    )

    steps = plan_next_steps(_snapshot(repository))

    if action is None:
        assert steps == ()
    else:
        assert steps == (NextStep("api", control, state, action),)


def test_empty_inventory_has_no_next_steps() -> None:
    assert plan_next_steps(_snapshot()) == ()


def test_mixed_snapshot_separates_configuration_and_evidence_work() -> None:
    snapshot = _snapshot(
        _repository("web", secret_scanning=ControlState.UNKNOWN),
        _repository(
            "api",
            branch_protection=ControlState.DISABLED,
            secret_scanning=ControlState.UNKNOWN,
            code_scanning=ControlState.NOT_COLLECTED,
        ),
    )

    assert plan_next_steps(snapshot) == (
        NextStep("api", "branch_protection", ControlState.DISABLED, "review_configuration"),
        NextStep("api", "secret_scanning", ControlState.UNKNOWN, "verify_access"),
        NextStep("api", "code_scanning", ControlState.NOT_COLLECTED, "collect_evidence"),
        NextStep("web", "secret_scanning", ControlState.UNKNOWN, "verify_access"),
    )


def test_order_is_lexical_by_repository_then_modeled_control() -> None:
    snapshot = _snapshot(
        *(
            _repository(name, *([ControlState.DISABLED] * 4))
            for name in ("z", "a", "Z", "A")
        )
    )

    steps = plan_next_steps(snapshot)

    assert [(step.repository, step.control) for step in steps] == [
        (repository, control)
        for repository in ("A", "Z", "a", "z")
        for control in (
            "branch_protection",
            "secret_scanning",
            "code_scanning",
            "dependabot_alerts",
        )
    ]
    reordered = replace(snapshot, repositories=tuple(reversed(snapshot.repositories)))
    assert plan_next_steps(reordered) == steps


def test_planning_leaves_snapshot_metadata_states_and_order_unchanged() -> None:
    snapshot = _snapshot(
        _repository("web", code_scanning=ControlState.NOT_COLLECTED),
        _repository("api", dependabot_alerts=ControlState.DISABLED),
    )
    before = asdict(snapshot)
    original_repositories = snapshot.repositories

    plan_next_steps(snapshot)

    assert asdict(snapshot) == before
    assert snapshot.repositories is original_repositories


def test_next_steps_are_immutable_value_objects() -> None:
    step = plan_next_steps(_snapshot(_repository("api", ControlState.UNKNOWN)))[0]

    with pytest.raises(FrozenInstanceError):
        step.action = "review_configuration"  # type: ignore[misc]  # Intentional mutation attempt.
    assert not hasattr(step, "__dict__")
