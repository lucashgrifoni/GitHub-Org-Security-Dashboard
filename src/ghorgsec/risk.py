"""Deterministic per-repository posture rating.

Pure scoring over modeled control states. This is a transparency aid for a
skeleton dashboard, not a real risk assessment: it never invents data and
excludes ``not_collected`` controls from the score so missing data is not
treated as either safe or unsafe.

Rubric (per repository, over the 4 modeled controls):

* ``disabled``       -> 2 points  (control explicitly off)
* ``unknown``        -> 1 point   (state could not be determined)
* ``enabled``        -> 0 points  (control on)
* ``not_collected``  -> excluded  (no data; not scored, not counted as assessed)

Rating bands, evaluated only over assessed (non ``not_collected``) controls:

* no assessed controls -> ``not_assessed``
* score == 0           -> ``strong``
* score in 1..2        -> ``moderate``
* score >= 3           -> ``weak``
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.summary import CONTROL_FIELDS

_STATE_WEIGHTS: dict[ControlState, int] = {
    ControlState.DISABLED: 2,
    ControlState.UNKNOWN: 1,
    ControlState.ENABLED: 0,
}


class RiskRating(StrEnum):
    """Qualitative posture rating for a repository."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True, slots=True)
class RepositoryRisk:
    """Deterministic posture rating for a single repository."""

    name: str
    score: int
    rating: RiskRating
    assessed_controls: int
    factors: tuple[str, ...]


def rate_repository(repository: RepositorySecurityControls) -> RepositoryRisk:
    """Compute the deterministic posture rating for one repository."""

    score = 0
    assessed = 0
    factors: list[str] = []

    for field, label in CONTROL_FIELDS:
        state: ControlState = getattr(repository, field)
        if state is ControlState.NOT_COLLECTED:
            continue

        assessed += 1
        weight = _STATE_WEIGHTS[state]
        score += weight
        if weight > 0:
            factors.append(f"{label}: {state.value}")

    return RepositoryRisk(
        name=repository.name,
        score=score,
        rating=_rating_for(score, assessed),
        assessed_controls=assessed,
        factors=tuple(factors),
    )


def rate_snapshot(snapshot: OrgSecuritySnapshot) -> tuple[RepositoryRisk, ...]:
    """Rate every repository in the snapshot, preserving snapshot order."""

    return tuple(rate_repository(repository) for repository in snapshot.repositories)


def _rating_for(score: int, assessed: int) -> RiskRating:
    if assessed == 0:
        return RiskRating.NOT_ASSESSED
    if score == 0:
        return RiskRating.STRONG
    if score <= 2:
        return RiskRating.MODERATE
    return RiskRating.WEAK
