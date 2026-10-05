"""Regression checks for fixture integrity and report evidence contracts."""

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ghorgsec.cli import app, write_report
from ghorgsec.fixture_loader import FixtureLoadError, load_snapshot_fixture, parse_snapshot_fixture
from ghorgsec.report import render_markdown_report
from ghorgsec.serialize import snapshot_to_dict

runner = CliRunner()
CONTROL_NAMES = (
    "branch_protection",
    "secret_scanning",
    "code_scanning",
    "dependabot_alerts",
)


def test_utf8_stdout_does_not_translate_lf_to_crlf() -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8", newline="\r\n")

    write_report("report\n", stream)

    assert raw.getvalue() == b"report\n"


def fixture_payload() -> dict[str, Any]:
    return {
        "organization": "example-org",
        "generated_at": "2026-10-05T12:00:00Z",
        "repositories": [
            {"name": "api", "controls": dict.fromkeys(CONTROL_NAMES, "enabled")}
        ],
    }


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_fixture_rejects_non_json_numbers(tmp_path: Path, constant: str) -> None:
    fixture = tmp_path / "snapshot.json"
    fixture.write_text(
        json.dumps(fixture_payload())[:-1] + f', "extra": {constant}' + "}",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["report", "--fixture", str(fixture)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert "non-finite" in result.stderr


def test_integer_beyond_python_limit_uses_fixture_error_contract(tmp_path: Path) -> None:
    fixture = tmp_path / "snapshot.json"
    fixture.write_text(
        json.dumps(fixture_payload())[:-1] + ', "extra": ' + "9" * 5000 + "}",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["report", "--fixture", str(fixture)])

    assert result.exit_code == 2
    assert "Error: Invalid JSON fixture" in result.stderr


@pytest.mark.parametrize("field", ["organization", "name", "default_branch", "warnings"])
def test_fixture_rejects_unpaired_surrogates(field: str) -> None:
    payload = fixture_payload()
    if field == "organization":
        payload[field] = "invalid\ud800"
    elif field == "warnings":
        payload[field] = ["invalid\udfff"]
    else:
        payload["repositories"][0][field] = "invalid\ud800"

    with pytest.raises(FixtureLoadError, match="valid Unicode"):
        parse_snapshot_fixture(payload)


def test_invalid_unicode_does_not_truncate_an_existing_report(tmp_path: Path) -> None:
    fixture = tmp_path / "snapshot.json"
    fixture.write_text(
        json.dumps(fixture_payload()).replace("example-org", r"invalid\ud800"),
        encoding="utf-8",
    )
    target = tmp_path / "report.md"
    target.write_bytes(b"previous report\n")

    result = runner.invoke(app, ["report", "--fixture", str(fixture), "-o", str(target)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr
    assert target.read_bytes() == b"previous report\n"


@pytest.mark.parametrize("inline_state", ["enabled", "disabled"])
def test_mixed_control_locations_are_rejected(inline_state: str) -> None:
    payload = fixture_payload()
    payload["repositories"][0]["branch_protection"] = inline_state

    with pytest.raises(FixtureLoadError, match="mix"):
        parse_snapshot_fixture(payload)


@pytest.mark.parametrize("alias", ["same_path", "relative_path", "hard_link"])
def test_output_cannot_overwrite_fixture_even_through_an_alias(tmp_path: Path, alias: str) -> None:
    fixture = tmp_path / "snapshot.json"
    content = json.dumps(fixture_payload()).encode("utf-8")
    fixture.write_bytes(content)
    if alias == "hard_link":
        target = tmp_path / "alias.json"
        os.link(fixture, target)
    elif alias == "relative_path":
        nested = fixture.parent / "nested"
        nested.mkdir()
        target = nested / ".." / fixture.name
    else:
        target = fixture

    result = runner.invoke(app, ["report", "--fixture", str(fixture), "-o", str(target)])

    assert result.exit_code == 2
    assert "--output must not overwrite" in result.stderr
    assert fixture.read_bytes() == content


@pytest.mark.parametrize("format_name", ["md", "json"])
def test_stdout_and_file_have_identical_utf8_lf_bytes(tmp_path: Path, format_name: str) -> None:
    payload = fixture_payload()
    payload["repositories"][0]["default_branch"] = "主分支"
    fixture = tmp_path / "snapshot.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")
    target = tmp_path / f"report.{format_name}"
    command = ["report", "--fixture", str(fixture), "--format", format_name]

    stdout = runner.invoke(app, command)
    written = runner.invoke(app, [*command, "--output", str(target)])

    assert stdout.exit_code == written.exit_code == 0
    assert stdout.stdout.encode("utf-8") == target.read_bytes()
    assert target.read_bytes().endswith(b"\n")
    assert not target.read_bytes().endswith(b"\n\n")
    assert b"\r\n" not in target.read_bytes()


@pytest.mark.parametrize(
    ("states", "status", "not_collected"),
    [
        (["enabled"] * 4, "complete", 0),
        (["enabled", "unknown", "not_collected", "not_collected"], "partial", 2),
        (["not_collected"] * 4, "not_assessed", 4),
    ],
)
def test_risk_exposes_collection_limits(
    states: list[str], status: str, not_collected: int
) -> None:
    payload = fixture_payload()
    payload["repositories"][0]["controls"] = dict(zip(CONTROL_NAMES, states, strict=True))
    snapshot = parse_snapshot_fixture(payload)
    risk = snapshot_to_dict(snapshot)["repositories"][0]["risk"]

    assert risk["assessment_status"] == status
    assert risk["not_collected_controls"] == not_collected
    assert "Not collected" in render_markdown_report(snapshot)


def test_json_distinguishes_disabled_from_uncollected_coverage(tmp_path: Path) -> None:
    payload = fixture_payload()
    payload["repositories"][0]["controls"]["branch_protection"] = "disabled"
    payload["repositories"][0]["controls"]["secret_scanning"] = "not_collected"
    fixture = tmp_path / "snapshot.json"
    fixture.write_text(json.dumps(payload), encoding="utf-8")

    controls = snapshot_to_dict(load_snapshot_fixture(fixture))["summary"]["controls"]
    by_field = {control["field"]: control for control in controls}
    disabled = by_field["branch_protection"]
    uncollected = by_field["secret_scanning"]

    assert disabled["coverage_percent"] == uncollected["coverage_percent"] == 0
    assert disabled["assessed"] == 1
    assert disabled["coverage_status"] == "assessed"
    assert uncollected["assessed"] == 0
    assert uncollected["coverage_status"] == "not_assessed"
