"""Unit tests for deterministic JSON serialization."""

import json
import unittest
from datetime import UTC, datetime

from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)
from ghorgsec.serialize import render_json_report, snapshot_to_dict


def _snapshot() -> OrgSecuritySnapshot:
    return OrgSecuritySnapshot(
        organization="example-org",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=(
            RepositorySecurityControls(
                name="api",
                default_branch="main",
                visibility=Visibility.PRIVATE,
                branch_protection=ControlState.ENABLED,
                secret_scanning=ControlState.ENABLED,
                code_scanning=ControlState.UNKNOWN,
                dependabot_alerts=ControlState.DISABLED,
            ),
        ),
        warnings=("local fixture only",),
    )


class SerializeTests(unittest.TestCase):
    def test_snapshot_to_dict_has_stable_shape(self) -> None:
        data = snapshot_to_dict(_snapshot())

        self.assertEqual(data["organization"], "example-org")
        self.assertEqual(data["generated_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(data["collection_mode"], "fixture_json")
        self.assertEqual(data["warnings"], ["local fixture only"])
        self.assertEqual(data["summary"]["total_repositories"], 1)

        repo = data["repositories"][0]
        self.assertEqual(repo["name"], "api")
        self.assertEqual(repo["default_branch"], "main")
        self.assertEqual(repo["visibility"], "private")
        self.assertEqual(repo["controls"]["branch_protection"], "enabled")
        self.assertEqual(repo["controls"]["dependabot_alerts"], "disabled")
        # api: enabled+enabled+unknown(1)+disabled(2) -> score 3 -> weak
        self.assertEqual(repo["risk"]["rating"], "weak")
        self.assertEqual(repo["risk"]["score"], 3)
        self.assertEqual(repo["risk"]["assessed_controls"], 4)
        self.assertIn("Dependabot alerts: disabled", repo["risk"]["factors"])

    def test_missing_metadata_serializes_as_null(self) -> None:
        snapshot = OrgSecuritySnapshot(
            organization="example-org",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(
                RepositorySecurityControls(
                    name="worker",
                    branch_protection=ControlState.NOT_COLLECTED,
                    secret_scanning=ControlState.NOT_COLLECTED,
                    code_scanning=ControlState.NOT_COLLECTED,
                    dependabot_alerts=ControlState.NOT_COLLECTED,
                ),
            ),
        )

        repo = snapshot_to_dict(snapshot)["repositories"][0]

        self.assertIsNone(repo["default_branch"])
        self.assertIsNone(repo["visibility"])

    def test_render_json_report_is_valid_and_deterministic(self) -> None:
        snapshot = _snapshot()
        first = render_json_report(snapshot)
        second = render_json_report(snapshot)

        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(parsed["organization"], "example-org")
        self.assertEqual(parsed["summary"]["controls"][0]["field"], "branch_protection")


if __name__ == "__main__":
    unittest.main()
