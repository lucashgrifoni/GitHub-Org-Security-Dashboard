"""Unit tests for deterministic per-repository risk rating."""

import unittest

from ghorgsec.models import ControlState, RepositorySecurityControls
from ghorgsec.risk import RiskRating, rate_repository


def _repo(
    branch_protection: ControlState,
    secret_scanning: ControlState,
    code_scanning: ControlState,
    dependabot_alerts: ControlState,
    name: str = "repo",
) -> RepositorySecurityControls:
    return RepositorySecurityControls(
        name=name,
        branch_protection=branch_protection,
        secret_scanning=secret_scanning,
        code_scanning=code_scanning,
        dependabot_alerts=dependabot_alerts,
    )


class RiskTests(unittest.TestCase):
    def test_all_enabled_is_strong_with_zero_score(self) -> None:
        risk = rate_repository(
            _repo(
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            )
        )

        self.assertEqual(risk.rating, RiskRating.STRONG)
        self.assertEqual(risk.score, 0)
        self.assertEqual(risk.assessed_controls, 4)
        self.assertEqual(risk.factors, ())

    def test_single_unknown_is_moderate(self) -> None:
        risk = rate_repository(
            _repo(
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.UNKNOWN,
                ControlState.ENABLED,
            )
        )

        self.assertEqual(risk.rating, RiskRating.MODERATE)
        self.assertEqual(risk.score, 1)
        self.assertIn("Code scanning: unknown", risk.factors)

    def test_two_disabled_controls_is_weak(self) -> None:
        risk = rate_repository(
            _repo(
                ControlState.DISABLED,
                ControlState.DISABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            )
        )

        self.assertEqual(risk.score, 4)
        self.assertEqual(risk.rating, RiskRating.WEAK)

    def test_boundary_score_two_is_moderate(self) -> None:
        # one disabled (2) + all else enabled -> score 2 -> still moderate
        risk = rate_repository(
            _repo(
                ControlState.DISABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            )
        )

        self.assertEqual(risk.score, 2)
        self.assertEqual(risk.rating, RiskRating.MODERATE)

    def test_boundary_score_three_is_weak(self) -> None:
        # one disabled (2) + one unknown (1) -> score 3 -> weak
        risk = rate_repository(
            _repo(
                ControlState.DISABLED,
                ControlState.UNKNOWN,
                ControlState.ENABLED,
                ControlState.ENABLED,
            )
        )

        self.assertEqual(risk.score, 3)
        self.assertEqual(risk.rating, RiskRating.WEAK)

    def test_all_not_collected_is_not_assessed(self) -> None:
        risk = rate_repository(
            _repo(
                ControlState.NOT_COLLECTED,
                ControlState.NOT_COLLECTED,
                ControlState.NOT_COLLECTED,
                ControlState.NOT_COLLECTED,
            )
        )

        self.assertEqual(risk.rating, RiskRating.NOT_ASSESSED)
        self.assertEqual(risk.assessed_controls, 0)
        self.assertEqual(risk.score, 0)

    def test_not_collected_excluded_from_assessment(self) -> None:
        # only one assessed control (disabled) -> score 2, assessed 1 -> moderate
        risk = rate_repository(
            _repo(
                ControlState.DISABLED,
                ControlState.NOT_COLLECTED,
                ControlState.NOT_COLLECTED,
                ControlState.NOT_COLLECTED,
            )
        )

        self.assertEqual(risk.assessed_controls, 1)
        self.assertEqual(risk.score, 2)
        self.assertEqual(risk.rating, RiskRating.MODERATE)


if __name__ == "__main__":
    unittest.main()
