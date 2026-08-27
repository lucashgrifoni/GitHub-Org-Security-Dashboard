"""Domain models for organization security snapshots."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ControlState(StrEnum):
    """Known state for a repository security control."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    UNKNOWN = "unknown"
    NOT_COLLECTED = "not_collected"


class Visibility(StrEnum):
    """GitHub repository visibility values.

    Mirrors the values GitHub exposes for repository visibility: ``public``,
    ``private``, and ``internal`` (the last available for organization repos in
    enterprise contexts). See GitHub docs on setting repository visibility.
    """

    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class RepositorySecurityControls:
    """Security control summary for one repository."""

    name: str
    branch_protection: ControlState
    secret_scanning: ControlState
    code_scanning: ControlState
    dependabot_alerts: ControlState
    default_branch: str | None = None
    visibility: Visibility | None = None


@dataclass(frozen=True, slots=True)
class OrgSecuritySnapshot:
    """Point-in-time organization security snapshot."""

    organization: str
    generated_at: datetime
    collection_mode: str
    repositories: tuple[RepositorySecurityControls, ...]
    warnings: tuple[str, ...] = ()

