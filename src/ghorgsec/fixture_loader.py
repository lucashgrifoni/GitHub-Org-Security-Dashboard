"""Load organization security snapshots from local JSON fixtures."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)

FIXTURE_COLLECTION_MODE = "fixture_json"
SAFE_FIXTURE_WARNING = (
    "Local fixture only: no GitHub API calls were made and no tokens or real "
    "organization data are required."
)


class FixtureLoadError(ValueError):
    """Raised when a local fixture cannot be parsed into a valid snapshot."""


def load_snapshot_fixture(path: str | Path) -> OrgSecuritySnapshot:
    """Load an organization security snapshot from a local JSON fixture file."""

    fixture_path = Path(path)

    try:
        raw_fixture = fixture_path.read_text(encoding="utf-8")
    except OSError as error:
        raise FixtureLoadError(
            f"Unable to read fixture file: {fixture_path}"
        ) from error

    try:
        payload = json.loads(raw_fixture)
    except JSONDecodeError as error:
        raise FixtureLoadError(
            f"Invalid JSON fixture {fixture_path}: {error.msg}"
        ) from error

    return parse_snapshot_fixture(payload)


def parse_snapshot_fixture(payload: object) -> OrgSecuritySnapshot:
    """Parse a decoded JSON fixture into an organization security snapshot."""

    fixture = _require_mapping(payload, "fixture")
    repositories = _parse_repositories(fixture.get("repositories"))
    fixture_warnings = _parse_warnings(fixture.get("warnings"))

    return OrgSecuritySnapshot(
        organization=_required_non_empty_string(fixture, "organization", "fixture"),
        generated_at=_parse_generated_at(fixture.get("generated_at")),
        collection_mode=FIXTURE_COLLECTION_MODE,
        repositories=repositories,
        warnings=_deduplicate_warnings((SAFE_FIXTURE_WARNING, *fixture_warnings)),
    )


def _parse_repositories(value: object) -> tuple[RepositorySecurityControls, ...]:
    if not isinstance(value, list):
        raise FixtureLoadError("fixture.repositories must be a JSON array")

    repositories = []
    seen_names = set()

    for index, repository_value in enumerate(value):
        context = f"fixture.repositories[{index}]"
        repository = _parse_repository(repository_value, context)

        if repository.name in seen_names:
            raise FixtureLoadError(f"{context}.name must be unique")

        repositories.append(repository)
        seen_names.add(repository.name)

    return tuple(repositories)


def _parse_repository(value: object, context: str) -> RepositorySecurityControls:
    repository = _require_mapping(value, context)
    controls, controls_context = _control_source(repository, context)

    return RepositorySecurityControls(
        name=_required_non_empty_string(repository, "name", context),
        branch_protection=_parse_control_state(
            controls, "branch_protection", controls_context
        ),
        secret_scanning=_parse_control_state(
            controls, "secret_scanning", controls_context
        ),
        code_scanning=_parse_control_state(
            controls, "code_scanning", controls_context
        ),
        dependabot_alerts=_parse_control_state(
            controls, "dependabot_alerts", controls_context
        ),
        default_branch=_optional_non_empty_string(
            repository, "default_branch", context
        ),
        visibility=_parse_visibility(repository, context),
    )


def _parse_visibility(value: Mapping[str, Any], context: str) -> Visibility | None:
    raw_value = _optional_non_empty_string(value, "visibility", context)

    if raw_value is None:
        return None

    try:
        return Visibility(raw_value)
    except ValueError as error:
        allowed = ", ".join(option.value for option in Visibility)
        raise FixtureLoadError(
            f"{context}.visibility must be one of: {allowed}"
        ) from error


def _control_source(
    repository: Mapping[str, Any], context: str
) -> tuple[Mapping[str, Any], str]:
    controls = repository.get("controls")

    if controls is None:
        return repository, context

    return _require_mapping(controls, f"{context}.controls"), f"{context}.controls"


def _parse_control_state(
    value: Mapping[str, Any], key: str, context: str
) -> ControlState:
    raw_state = _required_non_empty_string(value, key, context)

    try:
        return ControlState(raw_state)
    except ValueError as error:
        allowed = ", ".join(state.value for state in ControlState)
        raise FixtureLoadError(
            f"{context}.{key} must be one of: {allowed}"
        ) from error


def _parse_generated_at(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise FixtureLoadError("fixture.generated_at must be a non-empty ISO datetime")

    raw_value = value.strip()
    normalized_value = (
        f"{raw_value[:-1]}+00:00" if raw_value.endswith("Z") else raw_value
    )

    try:
        generated_at = datetime.fromisoformat(normalized_value)
    except ValueError as error:
        raise FixtureLoadError(
            "fixture.generated_at must be a valid ISO datetime"
        ) from error

    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise FixtureLoadError("fixture.generated_at must include a timezone")

    return generated_at


def _parse_warnings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()

    if not isinstance(value, list):
        raise FixtureLoadError("fixture.warnings must be a JSON array when provided")

    warnings = []

    for index, warning in enumerate(value):
        if not isinstance(warning, str) or not warning.strip():
            raise FixtureLoadError(
                f"fixture.warnings[{index}] must be a non-empty string"
            )

        warnings.append(warning.strip())

    return tuple(warnings)


def _deduplicate_warnings(warnings: tuple[str, ...]) -> tuple[str, ...]:
    deduplicated = []
    seen = set()

    for warning in warnings:
        if warning in seen:
            continue

        deduplicated.append(warning)
        seen.add(warning)

    return tuple(deduplicated)


def _require_mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FixtureLoadError(f"{context} must be a JSON object")

    return value


def _required_non_empty_string(
    value: Mapping[str, Any], key: str, context: str
) -> str:
    raw_value = value.get(key)

    if not isinstance(raw_value, str) or not raw_value.strip():
        raise FixtureLoadError(f"{context}.{key} must be a non-empty string")

    return raw_value.strip()


def _optional_non_empty_string(
    value: Mapping[str, Any], key: str, context: str
) -> str | None:
    raw_value = value.get(key)

    if raw_value is None:
        return None

    if not isinstance(raw_value, str) or not raw_value.strip():
        raise FixtureLoadError(f"{context}.{key} must be a non-empty string when set")

    return raw_value.strip()
