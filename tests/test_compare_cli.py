"""Offline comparison workflow, input preservation and output contracts."""

import json
import os
from pathlib import Path
from typing import Any, NoReturn

import pytest
from typer.testing import CliRunner

from ghorgsec.cli import app

runner = CliRunner()
CONTROLS = ("branch_protection", "secret_scanning", "code_scanning", "dependabot_alerts")


def _payload(date: str, state: str = "disabled") -> dict[str, Any]:
    return {
        "organization": "example-org",
        "generated_at": date,
        "repositories": [{"name": "api", "default_branch": "main",
                          "controls": dict.fromkeys(CONTROLS, state)}],
    }


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    baseline, current = tmp_path / "baseline.json", tmp_path / "current.json"
    baseline.write_text(json.dumps(_payload("2026-10-05T12:00:00Z")), encoding="utf-8")
    current.write_text(
        json.dumps(_payload("2026-10-06T12:00:00Z", "enabled")), encoding="utf-8"
    )
    return baseline, current


def _command(baseline: Path, current: Path) -> list[str]:
    return ["compare", "--baseline", str(baseline), "--current", str(current)]


def test_compare_is_offline_even_when_synthetic_credentials_are_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deny_live(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("Offline comparison attempted to construct the live client")

    monkeypatch.setattr("ghorgsec.cli.GitHubClient", deny_live)
    monkeypatch.setenv("GH_TOKEN", "synthetic-no-auth")
    baseline, current = _inputs(tmp_path)
    original = baseline.read_bytes(), current.read_bytes()
    result = runner.invoke(app, [*_command(baseline, current), "--format", "json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["schema_version"] == 1
    assert data["collection_mode"] == "local_snapshot_comparison"
    assert data["summary"] == {"changed_controls": 4, "unchanged_controls": 0}
    assert {change["classification"] for change in data["changes"]} == {"enabled_observed"}
    assert "synthetic-no-auth" not in result.output
    assert (baseline.read_bytes(), current.read_bytes()) == original


@pytest.mark.parametrize("format_name", ["md", "json"])
def test_compare_stdout_matches_utf8_lf_file(tmp_path: Path, format_name: str) -> None:
    baseline, current = _inputs(tmp_path)
    target = tmp_path / "comparison output.txt"
    command = [*_command(baseline, current), "--format", format_name]
    stdout = runner.invoke(app, command)
    written = runner.invoke(app, [*command, "--output", str(target)])

    assert stdout.exit_code == written.exit_code == 0
    assert stdout.stdout.encode("utf-8") == target.read_bytes()
    assert b"\r\n" not in target.read_bytes()
    assert target.read_bytes().endswith(b"\n") and not target.read_bytes().endswith(b"\n\n")
    assert "Comparison written" in written.stdout


@pytest.mark.parametrize("source", ["baseline", "current"])
@pytest.mark.parametrize("alias", ["same_path", "resolved_path", "hard_link"])
def test_compare_preserves_both_inputs_through_aliases(
    tmp_path: Path, source: str, alias: str
) -> None:
    baseline, current = _inputs(tmp_path)
    selected = baseline if source == "baseline" else current
    if alias == "hard_link":
        target = tmp_path / "alias.json"
        os.link(selected, target)
    elif alias == "resolved_path":
        nested = tmp_path / "nested"
        nested.mkdir()
        target = nested / ".." / selected.name
    else:
        target = selected
    original = baseline.read_bytes(), current.read_bytes()

    result = runner.invoke(app, [*_command(baseline, current), "-o", str(target)])

    assert result.exit_code == 2
    assert "--output must not overwrite" in result.stderr
    assert (baseline.read_bytes(), current.read_bytes()) == original


@pytest.mark.parametrize("defect", ["owner", "reversed_time", "invalid_json", "missing_file"])
def test_invalid_comparison_preserves_existing_output(tmp_path: Path, defect: str) -> None:
    baseline, current = _inputs(tmp_path)
    payload = _payload("2026-10-06T12:00:00Z")
    if defect == "owner":
        payload["organization"] = "another-org"
    elif defect == "reversed_time":
        payload["generated_at"] = "2026-10-04T12:00:00Z"
    current.write_text(
        "{broken" if defect == "invalid_json" else json.dumps(payload), encoding="utf-8"
    )
    if defect == "missing_file":
        current = tmp_path / "not-present.json"
    target = tmp_path / "previous.md"
    target.write_bytes(b"previous report\n")

    result = runner.invoke(app, [*_command(baseline, current), "-o", str(target)])

    assert result.exit_code == 2
    assert "Error:" in result.stderr and "Traceback" not in result.output
    assert target.read_bytes() == b"previous report\n"


@pytest.mark.parametrize("problem", ["directory", "missing_parent"])
def test_compare_write_error_has_normal_cli_contract(tmp_path: Path, problem: str) -> None:
    baseline, current = _inputs(tmp_path)
    target = tmp_path if problem == "directory" else tmp_path / "missing" / "report.md"
    result = runner.invoke(app, [*_command(baseline, current), "-o", str(target)])
    assert result.exit_code == 2
    assert "Error:" in result.stderr and "Traceback" not in result.output


def test_report_json_can_be_reused_as_compare_input(tmp_path: Path) -> None:
    baseline, current = _inputs(tmp_path)
    exported = tmp_path / "exported.json"
    report = runner.invoke(
        app, ["report", "--fixture", str(baseline), "--format", "json", "-o", str(exported)]
    )
    assert report.exit_code == 0
    result = runner.invoke(app, [*_command(exported, current), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["changes"]) == 4


def test_compare_does_not_accept_live_options(tmp_path: Path) -> None:
    baseline, current = _inputs(tmp_path)
    result = runner.invoke(app, [*_command(baseline, current), "--live"])
    assert result.exit_code == 2


def test_imported_scores_and_modes_do_not_control_comparison(tmp_path: Path) -> None:
    baseline, current = _inputs(tmp_path)
    payload = json.loads(current.read_text(encoding="utf-8"))
    payload["collection_mode"] = "github_live_org"
    payload["summary"] = {"total_repositories": 999, "changed_controls": 999}
    payload["repositories"][0]["risk"] = {"score": 999, "rating": "weak"}
    current.write_text(json.dumps(payload), encoding="utf-8")
    result = runner.invoke(app, [*_command(baseline, current), "--format", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["collection_mode"] == "local_snapshot_comparison"
    assert data["summary"]["changed_controls"] == 4
