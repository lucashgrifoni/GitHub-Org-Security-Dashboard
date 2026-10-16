"""Offline user journeys for selecting repositories from a captured snapshot."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from ghorgsec.cli import app


def write_fixture(path: Path, *, names: tuple[str, ...] = ("api", "web")) -> bytes:
    payload = {
        "organization": "example",
        "generated_at": "2026-10-01T12:00:00Z",
        "repositories": [
            {
                "name": name,
                "branch_protection": "enabled",
                "secret_scanning": "disabled",
                "code_scanning": "unknown",
                "dependabot_alerts": "not_collected",
            }
            for name in names
        ],
    }
    raw = json.dumps(payload).encode("utf-8")
    path.write_bytes(raw)
    return raw


@pytest.mark.parametrize("name", ["api", "API", " api "])
def test_fixture_filter_selects_offline_and_preserves_source(tmp_path: Path, name: str) -> None:
    fixture = tmp_path / "snapshot.json"
    original = write_fixture(fixture)
    with patch("ghorgsec.cli.GitHubClient", side_effect=AssertionError("No live client allowed")):
        result = CliRunner().invoke(app, [
            "report", "--fixture", str(fixture), "--repo", name, "--repo", name,
            "--format", "json",
        ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert [repo["name"] for repo in payload["repositories"]] == ["api"]
    assert payload["collection_mode"] == "fixture_json"
    assert any("filter applied" in warning for warning in payload["warnings"])
    assert fixture.read_bytes() == original


@pytest.mark.parametrize("name", ["absent", " "])
def test_fixture_filter_unknown_or_empty_name_is_a_cli_error(tmp_path: Path, name: str) -> None:
    fixture = tmp_path / "snapshot.json"
    write_fixture(fixture)
    result = CliRunner().invoke(app, ["report", "--fixture", str(fixture), "--repo", name])
    assert result.exit_code == 2
    assert "Error:" in result.stderr


def test_fixture_filter_refuses_ambiguous_casefold_names(tmp_path: Path) -> None:
    fixture = tmp_path / "snapshot.json"
    write_fixture(fixture, names=("API", "api"))
    result = CliRunner().invoke(app, ["report", "--fixture", str(fixture), "--repo", "api"])
    assert result.exit_code == 2
    assert "ambiguous" in result.stderr


def test_fixture_filter_validates_unselected_repositories(tmp_path: Path) -> None:
    fixture = tmp_path / "snapshot.json"
    write_fixture(fixture)
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    payload["repositories"][1]["code_scanning"] = "invented"
    fixture.write_text(json.dumps(payload), encoding="utf-8")
    result = CliRunner().invoke(app, ["report", "--fixture", str(fixture), "--repo", "api"])
    assert result.exit_code == 2
    assert "code_scanning must be one of" in result.stderr


def test_fixture_filter_cannot_overwrite_its_source(tmp_path: Path) -> None:
    fixture = tmp_path / "snapshot.json"
    original = write_fixture(fixture)
    result = CliRunner().invoke(app, [
        "report", "--fixture", str(fixture), "--repo", "api", "--output", str(fixture),
    ])
    assert result.exit_code == 2
    assert "must not overwrite" in result.stderr
    assert fixture.read_bytes() == original
