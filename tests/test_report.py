"""Unit tests for Markdown report rendering."""

import unittest
from datetime import UTC, datetime

from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)
from ghorgsec.report import render_markdown_report


class ReportTests(unittest.TestCase):
    def test_report_renders_metadata_warnings_and_repository_rows(self) -> None:
        snapshot = OrgSecuritySnapshot(
            organization="example-org",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(
                RepositorySecurityControls(
                    name="api|service",
                    default_branch="main|stable",
                    visibility=Visibility.PRIVATE,
                    branch_protection=ControlState.NOT_COLLECTED,
                    secret_scanning=ControlState.NOT_COLLECTED,
                    code_scanning=ControlState.NOT_COLLECTED,
                    dependabot_alerts=ControlState.NOT_COLLECTED,
                ),
            ),
            warnings=("Offline stub only.",),
        )

        markdown = render_markdown_report(snapshot)

        self.assertIn("Organization: `example-org`", markdown)
        self.assertIn("Collection mode: `offline_stub`", markdown)
        self.assertIn("## Posture Summary", markdown)
        self.assertIn("- Repositories: 1", markdown)
        self.assertIn(
            "| Control | Enabled | Disabled | Unknown | Not collected | Enabled coverage |",
            markdown,
        )
        self.assertIn("- Offline stub only.", markdown)
        self.assertIn(
            "| Repository | Default branch | Visibility | Branch protection |",
            markdown,
        )
        self.assertIn(
            "| api\\|service | main\\|stable | private | not_collected",
            markdown,
        )

    def test_report_marks_missing_repository_metadata_as_not_collected(self) -> None:
        snapshot = OrgSecuritySnapshot(
            organization="example-org",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(
                RepositorySecurityControls(
                    name="worker",
                    branch_protection=ControlState.ENABLED,
                    secret_scanning=ControlState.ENABLED,
                    code_scanning=ControlState.UNKNOWN,
                    dependabot_alerts=ControlState.DISABLED,
                ),
            ),
        )

        markdown = render_markdown_report(snapshot)

        self.assertIn(
            "| worker | not_collected | not_collected | enabled | enabled | "
            "unknown | disabled |",
            markdown,
        )
        # worker: enabled+enabled+unknown(1)+disabled(2) -> score 3 -> weak
        self.assertIn("## Repository Risk", markdown)
        self.assertIn("| worker | weak | 3 | 4 |", markdown)


    def test_report_with_no_repositories_renders_placeholder_row(self) -> None:
        snapshot = OrgSecuritySnapshot(
            organization="example-org",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(),
            warnings=("No repositories were provided; the report will contain no rows.",),
        )

        markdown = render_markdown_report(snapshot)

        self.assertIn("| _none_ | not_collected | not_collected | not_collected |", markdown)


if __name__ == "__main__":
    unittest.main()
