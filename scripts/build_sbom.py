"""Build a runtime CycloneDX inventory from fresh pip installation reports.

Archive hashes come from the installer reports, not guesses from package names.
The graph evaluates PEP 508 markers for the reported target environment, including
requested extras. It covers that environment, not every supported platform.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from packaging.licenses import canonicalize_license_expression
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


def build_sbom(reports: list[dict[str, Any]], wheel: Path) -> dict[str, Any]:
    """Verify identities, archive hashes and a closed runtime dependency graph."""
    entries: dict[str, dict[str, Any]] = {}
    environment = reports[0]["environment"]
    for report in reports:
        if report.get("version") != "1" or report.get("environment") != environment:
            raise ValueError("Installation report versions or environments do not match.")
        for entry in report["install"]:
            metadata = entry["metadata"]
            name: str = canonicalize_name(metadata["name"], validate=True)
            Version(metadata["version"])
            digest = entry["download_info"]["archive_info"]["hashes"]["sha256"]
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("A package is missing a valid archive SHA-256.")
            if entry.get("is_yanked") or name in entries:
                raise ValueError("A package is yanked or occurs more than once in the reports.")
            entries[name] = entry
    if "ghorgsec" not in entries:
        raise ValueError("The application must be included in its runtime inventory.")
    application_hash = entries["ghorgsec"]["download_info"]["archive_info"]["hashes"]["sha256"]
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != application_hash:
        raise ValueError("The application wheel does not match its installation report.")

    extras: dict[str, set[str]] = {name: set() for name in entries}
    graph: dict[str, set[str]] = {name: set() for name in entries}
    changed = True
    while changed:
        changed = False
        for name, entry in entries.items():
            for raw in entry["metadata"].get("requires_dist", []):
                requirement = Requirement(raw)
                if requirement.marker is not None and not any(
                    requirement.marker.evaluate({**environment, "extra": extra})
                    for extra in ("", *sorted(extras[name]))
                ):
                    continue
                child: str = canonicalize_name(requirement.name)
                if child not in entries or not requirement.specifier.contains(
                    entries[child]["metadata"]["version"], prereleases=True
                ):
                    raise ValueError("An active runtime dependency is absent or incompatible.")
                graph[name].add(child)
                new_extras = requirement.extras - extras[child]
                if new_extras:
                    extras[child].update(new_extras)
                    changed = True

    reachable = {"ghorgsec"}
    pending = ["ghorgsec"]
    while pending:
        for child in graph[pending.pop()]:
            if child not in reachable:
                reachable.add(child)
                pending.append(child)
    if reachable != entries.keys():
        raise ValueError("The reported installation includes packages outside the runtime graph.")

    components = {name: _component(name, entry) for name, entry in entries.items()}
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": uuid4().urn,
        "version": 1,
        "metadata": {
            "component": components["ghorgsec"],
            "tools": {"components": [{
                "type": "application", "name": "ghorgsec-release-inventory",
                "version": entries["ghorgsec"]["metadata"]["version"],
            }]},
            "properties": [
                {"name": "ghorgsec:scope", "value": "reported runtime installation"},
                *[
                    {"name": f"ghorgsec:environment:{key}", "value": environment[key]}
                    for key in ("python_full_version", "sys_platform", "platform_machine")
                ],
            ],
        },
        "components": [components[name] for name in sorted(entries) if name != "ghorgsec"],
        "dependencies": [
            {
                "ref": components[name]["bom-ref"],
                "dependsOn": sorted(components[child]["bom-ref"] for child in graph[name]),
            }
            for name in sorted(entries)
        ],
    }


def _component(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    metadata = entry["metadata"]
    purl = f"pkg:pypi/{name}@{quote(metadata['version'], safe='')}"
    component: dict[str, Any] = {
        "type": "application" if name == "ghorgsec" else "library",
        "bom-ref": purl,
        "name": name,
        "version": metadata["version"],
        "purl": purl,
        "hashes": [{
            "alg": "SHA-256",
            "content": entry["download_info"]["archive_info"]["hashes"]["sha256"],
        }],
    }
    expression = metadata.get("license_expression")
    license_name = metadata.get("license")
    if isinstance(expression, str) and expression.strip():
        component["licenses"] = [{"expression": canonicalize_license_expression(expression)}]
    elif isinstance(license_name, str) and license_name.strip():
        component["licenses"] = [{"license": {"name": license_name.strip()}}]
    else:
        classifiers = [
            value for value in metadata.get("classifier", [])
            if isinstance(value, str) and value.startswith("License :: ")
            and value.count(" :: ") >= 2
        ]
        if classifiers:
            component["licenses"] = [
                {"license": {"name": value.rsplit(" :: ", 1)[-1]}} for value in classifiers
            ]
            component["properties"] = [{"name": "ghorgsec:license-source", "value": "classifier"}]
        else:
            component["properties"] = [
                {"name": "ghorgsec:license-status", "value": "not-declared"}
            ]
    return component


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, action="append", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if any(
            args.output.resolve() == source.resolve()
            or (args.output.exists() and args.output.samefile(source))
            for source in [args.wheel, *args.report]
        ):
            raise ValueError("The SBOM output must preserve its source artifacts.")
        result = build_sbom(
            [json.loads(path.read_text(encoding="utf-8")) for path in args.report], args.wheel,
        )
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n",
        )
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
