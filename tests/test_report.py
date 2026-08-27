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


    def test_line_breaks_in_rendered_values_cannot_forge_report_structure(self) -> None:
        """A value carrying newlines must not inject headings or split a table row.

        Repository and organization names come from a fixture the operator did
        not necessarily write. Escaping only the cell delimiter leaves the line
        structure open: a value containing a newline forges Markdown headings
        and breaks the posture table, so the rendered report asserts a shape the
        underlying data never supported.
        """

        snapshot = OrgSecuritySnapshot(
            organization="acme\n\n# Fabricated Title\n\nAll controls verified.",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(
                RepositorySecurityControls(
                    name="good\n\n## Posture Summary\n\n- Repositories: 1\n",
                    default_branch="main\r\n### injected",
                    branch_protection=ControlState.DISABLED,
                    secret_scanning=ControlState.DISABLED,
                    code_scanning=ControlState.DISABLED,
                    dependabot_alerts=ControlState.DISABLED,
                ),
            ),
            warnings=("ok\n\n## Injected Section\n\n- No issues found.",),
        )

        markdown = render_markdown_report(snapshot)

        # The security property is structural: no injected value may become a
        # heading. The headings must be exactly the ones the renderer emits.
        self.assertEqual(
            [line for line in markdown.splitlines() if line.startswith("#")],
            [
                "# GitHub Org Security Dashboard",
                "## Warnings",
                "## Posture Summary",
                "## Repository Controls",
                "## Repository Risk",
            ],
        )

        # Every table row stays on exactly one line, so no repository can be
        # pushed out of the rendered table by a crafted neighbour.
        rows = [line for line in markdown.splitlines() if line.startswith("|")]
        # 6 posture-summary rows + 3 control rows + 3 risk rows.
        self.assertEqual(len(rows), 12)
        for row in rows:
            self.assertEqual(len(row.splitlines()), 1)

        # Flattening must not delete operator data: the value is still
        # rendered, it simply can no longer forge structure.
        self.assertIn("acme # Fabricated Title All controls verified.", markdown)
        self.assertIn("good ## Posture Summary - Repositories: 1", markdown)


    def test_uncollected_control_reports_not_assessed_instead_of_zero_percent(self) -> None:
        """No data collected must not render as 0% coverage.

        The risk table already refuses to invent a rating when nothing was
        assessed and prints ``not_assessed``. The posture summary printed 0%
        for the same snapshot, which reads as "the control is off everywhere"
        rather than "nothing was collected" — the exact misleading 0% that
        excluding ``not_collected`` from the denominator exists to prevent.
        """

        snapshot = OrgSecuritySnapshot(
            organization="example-org",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            collection_mode="offline_stub",
            repositories=(
                RepositorySecurityControls(
                    name="alpha",
                    branch_protection=ControlState.NOT_COLLECTED,
                    secret_scanning=ControlState.NOT_COLLECTED,
                    code_scanning=ControlState.ENABLED,
                    dependabot_alerts=ControlState.DISABLED,
                ),
            ),
        )

        markdown = render_markdown_report(snapshot)

        # Nothing assessed -> not_assessed, mirroring the risk table.
        self.assertIn("| Branch protection | 0 | 0 | 0 | 1 | not_assessed |", markdown)
        self.assertIn("| Secret scanning | 0 | 0 | 0 | 1 | not_assessed |", markdown)
        # Genuinely assessed controls still report a real percentage.
        self.assertIn("| Code scanning | 1 | 0 | 0 | 0 | 100% |", markdown)
        self.assertIn("| Dependabot alerts | 0 | 1 | 0 | 0 | 0% |", markdown)


if __name__ == "__main__":
    unittest.main()
