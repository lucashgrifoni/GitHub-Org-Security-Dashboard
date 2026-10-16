"""Discriminating artifact, graph and platform checks for release SBOMs."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packaging.markers import default_environment
from scripts.build_sbom import build_sbom


def entry(name: str, requires: list[str], digest: str = "a" * 64) -> dict[str, Any]:
    return {
        "metadata": {
            "name": name, "version": "1.0", "license_expression": "MIT",
            "requires_dist": requires,
        },
        "download_info": {"archive_info": {"hashes": {"sha256": digest}}},
    }


def report(install: list[dict[str, Any]], platform: str = "linux") -> dict[str, Any]:
    return {
        "version": "1", "environment": {**default_environment(), "sys_platform": platform},
        "install": install,
    }


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_sbom_keeps_application_hash_licenses_and_platform_dependency_edges(
    tmp_path: Path, platform: str,
) -> None:
    wheel = tmp_path / "application.whl"
    wheel.write_bytes(b"synthetic application archive")
    root = entry("ghorgsec", ["demo[feature]>=1"], hashlib.sha256(wheel.read_bytes()).hexdigest())
    packages = [
        entry("demo", ["helper; extra == 'feature'", "windows-only; sys_platform == 'win32'"]),
        entry("helper", []),
    ]
    if platform == "win32":
        packages.append(entry("windows-only", []))
    bom = build_sbom([report([root, *packages], platform)], wheel)
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom)) is None
    assert bom["metadata"]["component"]["hashes"][0]["content"] == root[
        "download_info"
    ]["archive_info"]["hashes"]["sha256"]
    assert all(component["licenses"] == [{"expression": "MIT"}] for component in bom["components"])
    graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
    assert graph["pkg:pypi/ghorgsec@1.0"] == ["pkg:pypi/demo@1.0"]
    assert "pkg:pypi/helper@1.0" in graph["pkg:pypi/demo@1.0"]
    assert ("pkg:pypi/windows-only@1.0" in graph["pkg:pypi/demo@1.0"]) == (platform == "win32")
    assert graph["pkg:pypi/helper@1.0"] == []


@pytest.mark.parametrize("defect", ["hash", "missing", "orphan", "duplicate", "yanked", "version"])
def test_sbom_rejects_unbound_or_incomplete_inventory(tmp_path: Path, defect: str) -> None:
    wheel = tmp_path / "application.whl"
    wheel.write_bytes(b"synthetic wheel")
    root = entry("ghorgsec", ["demo>=1"], hashlib.sha256(wheel.read_bytes()).hexdigest())
    packages = [root, entry("demo", [])]
    if defect == "hash":
        wheel.write_bytes(b"modified wheel")
    elif defect == "missing":
        packages.pop()
    elif defect == "orphan":
        packages.append(entry("unused", []))
    elif defect == "duplicate":
        packages.append(entry("demo", []))
    elif defect == "yanked":
        packages[1]["is_yanked"] = True
    else:
        packages[1]["metadata"]["version"] = "0.5"
    with pytest.raises(ValueError):
        build_sbom([report(packages)], wheel)


@pytest.mark.parametrize("source", ["legacy", "classifier", "absent"])
def test_sbom_keeps_license_source_and_never_invents_an_spdx_id(
    tmp_path: Path, source: str,
) -> None:
    wheel = tmp_path / "application.whl"
    wheel.write_bytes(b"synthetic wheel")
    root = entry("ghorgsec", [], hashlib.sha256(wheel.read_bytes()).hexdigest())
    root["metadata"].pop("license_expression")
    if source == "legacy":
        root["metadata"]["license"] = "declared legacy license text"
    elif source == "classifier":
        root["metadata"]["classifier"] = ["License :: OSI Approved :: BSD License"]
    component = build_sbom([report([root])], wheel)["metadata"]["component"]
    if source == "absent":
        assert "licenses" not in component
        assert component["properties"] == [{
            "name": "ghorgsec:license-status", "value": "not-declared",
        }]
    else:
        assert "expression" not in component["licenses"][0]
        assert component["licenses"][0]["license"]["name"] == (
            "BSD License" if source == "classifier" else "declared legacy license text"
        )
