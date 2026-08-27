"""Unit tests for posture summary aggregation."""

import unittest
from datetime import UTC, datetime

from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)
from ghorgsec.summary import summarize_snapshot


def _repo(
    name: str,
    branch_protection: ControlState,
    secret_scanning: ControlState,
    code_scanning: ControlState,
    dependabot_alerts: ControlState,
) -> RepositorySecurityControls:
    return RepositorySecurityControls(
        name=name,
        branch_protection=branch_protection,
        secret_scanning=secret_scanning,
        code_scanning=code_scanning,
        dependabot_alerts=dependabot_alerts,
        visibility=Visibility.PRIVATE,
    )


def _snapshot(*repositories: RepositorySecurityControls) -> OrgSecuritySnapshot:
    return OrgSecuritySnapshot(
        organization="example-org",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=repositories,
    )


class SummaryTests(unittest.TestCase):
    def test_counts_states_per_control(self) -> None:
        snapshot = _snapshot(
            _repo(
                "a",
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.UNKNOWN,
                ControlState.DISABLED,
            ),
            _repo(
                "b",
                ControlState.DISABLED,
                ControlState.ENABLED,
                ControlState.NOT_COLLECTED,
                ControlState.ENABLED,
            ),
        )

        summary = summarize_snapshot(snapshot)
        by_field = {coverage.field: coverage for coverage in summary.controls}

        self.assertEqual(summary.total_repositories, 2)
        self.assertEqual(by_field["branch_protection"].enabled, 1)
        self.assertEqual(by_field["branch_protection"].disabled, 1)
        self.assertEqual(by_field["secret_scanning"].enabled, 2)
        self.assertEqual(by_field["code_scanning"].unknown, 1)
        self.assertEqual(by_field["code_scanning"].not_collected, 1)
        self.assertEqual(by_field["dependabot_alerts"].enabled, 1)

    def test_total_property_sums_all_states(self) -> None:
        snapshot = _snapshot(
            _repo(
                "a",
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            ),
        )
        summary = summarize_snapshot(snapshot)

        for coverage in summary.controls:
            self.assertEqual(coverage.total, 1)

    def test_coverage_percent_excludes_not_collected_from_denominator(self) -> None:
        snapshot = _snapshot(
            _repo(
                "a",
                ControlState.ENABLED,
                ControlState.NOT_COLLECTED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            ),
            _repo(
                "b",
                ControlState.DISABLED,
                ControlState.NOT_COLLECTED,
                ControlState.ENABLED,
                ControlState.ENABLED,
            ),
        )
        summary = summarize_snapshot(snapshot)
        by_field = {coverage.field: coverage for coverage in summary.controls}

        # branch_protection: 1 enabled / 2 known -> 50%
        self.assertEqual(by_field["branch_protection"].coverage_percent, 50)
        # secret_scanning: all not_collected -> 0 known -> 0%
        self.assertEqual(by_field["secret_scanning"].coverage_percent, 0)
        # code_scanning: 2 enabled / 2 known -> 100%
        self.assertEqual(by_field["code_scanning"].coverage_percent, 100)

    def test_empty_snapshot_yields_zero_coverage(self) -> None:
        summary = summarize_snapshot(_snapshot())

        self.assertEqual(summary.total_repositories, 0)
        for coverage in summary.controls:
            self.assertEqual(coverage.total, 0)
            self.assertEqual(coverage.coverage_percent, 0)


if __name__ == "__main__":
    unittest.main()
