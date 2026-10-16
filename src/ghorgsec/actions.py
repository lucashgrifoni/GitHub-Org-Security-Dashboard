"""Pure next-step planning from supplied repository control states."""

from dataclasses import dataclass

from ghorgsec.models import ControlState, OrgSecuritySnapshot
from ghorgsec.summary import CONTROL_FIELDS

_STATE_ACTIONS: dict[ControlState, str] = {
    ControlState.DISABLED: "review_configuration",
    ControlState.UNKNOWN: "verify_access",
    ControlState.NOT_COLLECTED: "collect_evidence",
}


@dataclass(frozen=True, slots=True)
class NextStep:
    """A suggested review or evidence step; no configuration change is performed."""

    repository: str
    control: str
    state: ControlState
    action: str


def plan_next_steps(snapshot: OrgSecuritySnapshot) -> tuple[NextStep, ...]:
    """List non-enabled controls by repository name and modeled control order."""

    steps = []
    for repository in sorted(snapshot.repositories, key=lambda repository: repository.name):
        for control, _ in CONTROL_FIELDS:
            state: ControlState = getattr(repository, control)
            if state is ControlState.ENABLED:
                continue
            steps.append(
                NextStep(
                    repository=repository.name,
                    control=control,
                    state=state,
                    action=_STATE_ACTIONS[state],
                )
            )
    return tuple(steps)
