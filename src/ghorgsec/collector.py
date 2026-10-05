"""Offline collector stub for organization security snapshots."""

from collections.abc import Iterable
from datetime import UTC, datetime

from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls

SAFE_STUB_WARNING = (
    "Offline stub only: no GitHub API calls were made and no real security "
    "controls were collected."
)


class RealCollectionDisabledError(RuntimeError):
    """Raised when a caller attempts to enable real GitHub collection."""


def collect_org_security_snapshot(
    org: str,
    repositories: Iterable[str] = (),
    *,
    allow_network: bool = False,
) -> OrgSecuritySnapshot:
    """Build an offline snapshot with the current timestamp for the requested repositories.

    The current implementation intentionally refuses real network collection.
    This keeps the skeleton safe to run without tokens, external API calls, or
    accidental collection of organization data.
    """

    if allow_network:
        raise RealCollectionDisabledError(
            "Real GitHub collection is not implemented. Run the offline stub only."
        )

    repo_names = tuple(_normalize_repository_names(repositories))
    controls = tuple(_stub_repository_controls(repo_name) for repo_name in repo_names)
    warnings = [SAFE_STUB_WARNING]

    if not controls:
        warnings.append("No repositories were provided; the report will contain no rows.")

    return OrgSecuritySnapshot(
        organization=org.strip(),
        generated_at=datetime.now(tz=UTC),
        collection_mode="offline_stub",
        repositories=controls,
        warnings=tuple(warnings),
    )


def _normalize_repository_names(repositories: Iterable[str]) -> tuple[str, ...]:
    normalized = []
    seen = set()

    for raw_name in repositories:
        name = raw_name.strip()
        if not name or name in seen:
            continue
        normalized.append(name)
        seen.add(name)

    return tuple(normalized)


def _stub_repository_controls(repository: str) -> RepositorySecurityControls:
    return RepositorySecurityControls(
        name=repository,
        branch_protection=ControlState.NOT_COLLECTED,
        secret_scanning=ControlState.NOT_COLLECTED,
        code_scanning=ControlState.NOT_COLLECTED,
        dependabot_alerts=ControlState.NOT_COLLECTED,
    )

