"""Contract checks for next-step presentation and additive JSON output."""

from datetime import UTC, datetime

from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.report import render_markdown_report
from ghorgsec.serialize import snapshot_to_dict


def test_report_separates_configuration_review_from_evidence_gaps() -> None:
    snapshot = OrgSecuritySnapshot(
        organization="example-org",
        generated_at=datetime(2026, 10, 6, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=(RepositorySecurityControls(
            name="api",
            branch_protection=ControlState.DISABLED,
            secret_scanning=ControlState.UNKNOWN,
            code_scanning=ControlState.NOT_COLLECTED,
            dependabot_alerts=ControlState.ENABLED,
        ),),
    )

    data = snapshot_to_dict(snapshot)
    assert data["next_steps"] == [
        {"repository": "api", "control": "branch_protection", "state": "disabled",
         "action": "review_configuration"},
        {"repository": "api", "control": "secret_scanning", "state": "unknown",
         "action": "verify_access"},
        {"repository": "api", "control": "code_scanning", "state": "not_collected",
         "action": "collect_evidence"},
    ]
    assert data["repositories"][0]["risk"]["score"] == 3
    assert data["repositories"][0]["risk"]["assessment_status"] == "partial"
    markdown = render_markdown_report(snapshot)
    disabled = markdown.split("### Disabled controls")[1].split("### Unknown controls")[0]
    unknown = markdown.split("### Unknown controls")[1].split("### Not collected controls")[0]
    missing = markdown.split("### Not collected controls")[1]
    assert "review_configuration" in disabled and "verify_access" not in disabled
    assert "verify_access" in unknown and "review_configuration" not in unknown
    assert "collect_evidence" in missing and "review_configuration" not in missing
    assert "No GitHub settings are changed." in markdown


def test_enabled_snapshot_has_no_suggested_actions() -> None:
    snapshot = OrgSecuritySnapshot(
        organization="example-org",
        generated_at=datetime(2026, 10, 6, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=(RepositorySecurityControls(
            name="api",
            branch_protection=ControlState.ENABLED,
            secret_scanning=ControlState.ENABLED,
            code_scanning=ControlState.ENABLED,
            dependabot_alerts=ControlState.ENABLED,
        ),),
    )
    assert snapshot_to_dict(snapshot)["next_steps"] == []
    assert render_markdown_report(snapshot).count("None in the supplied snapshot.") == 3
