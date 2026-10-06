"""Read-only collection of token-visible repository controls, with explicit gaps."""

import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from ghorgsec.github_client import GitHubClient, GitHubCollectionError, GitHubResponse
from ghorgsec.models import (
    ControlState,
    OrgSecuritySnapshot,
    RepositorySecurityControls,
    Visibility,
)


def collect_live_snapshot(
    owner: str,
    *,
    client: GitHubClient,
    personal: bool = False,
    repositories: Iterable[str] = (),
) -> OrgSecuritySnapshot:
    """Observe controls for an organization or the authenticated personal account.

    This is separate from the existing offline collector: that API still refuses
    network opt-in. All network operations go through the injected GET client.
    """
    owner = owner.strip()
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner):
        raise GitHubCollectionError("Invalid GitHub organization or account name.")
    requested = {_repository_name(name.strip()).casefold() for name in repositories}
    if personal:
        identity = _object(client.get("/user"), "authenticated account")
        if str(identity.get("login", "")).casefold() != owner.casefold():
            raise GitHubCollectionError("--user must match the authenticated personal account.")
        inventory_path = "/user/repos?affiliation=owner&visibility=all&sort=full_name&per_page=100"
    else:
        identity = _object(client.get(f"/orgs/{owner}"), "organization")
        if str(identity.get("login", "")).casefold() != owner.casefold():
            raise GitHubCollectionError("GitHub returned an unexpected organization identity.")
        inventory_path = f"/orgs/{owner}/repos?type=all&sort=full_name&per_page=100"

    inventory: dict[str, dict[str, Any]] = {}
    for item in client.pages(inventory_path):
        repo = _repository(item, owner)
        key = str(repo["name"]).casefold()
        if key in inventory:
            raise GitHubCollectionError("GitHub inventory contains duplicate repositories; retry.")
        inventory[key] = repo
    if requested - inventory.keys():
        raise GitHubCollectionError(
            "A requested repository is absent from the token-visible inventory; check access."
        )
    warnings = [
        "Live read-only observation of token-visible repositories only; the inventory does not "
        "prove full account or organization coverage.",
        "Requests are sequential: this snapshot is not an atomic observation of GitHub state.",
        "Branch protection covers the default branch only. Enabled describes an observed "
        "configuration, not enforcement quality or vulnerability absence.",
    ]
    if requested:
        warnings.append(
            "Repository filter applied; coverage describes the selected repositories only."
        )
    observed = tuple(
        _collect_repository(owner, repo, client, warnings)
        for key, repo in sorted(inventory.items())
        if not requested or key in requested
    )
    return OrgSecuritySnapshot(
        organization=owner,
        generated_at=datetime.now(UTC),
        collection_mode="github_live_user" if personal else "github_live_org",
        repositories=observed,
        warnings=tuple(warnings),
    )


def _repository_name(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value) or value in (".", ".."):
        raise GitHubCollectionError("Invalid GitHub repository name.")
    return value


def _repository(payload: Any, owner: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise GitHubCollectionError("GitHub returned invalid repository metadata.")
    _repository_name(payload["name"])
    identity = payload.get("owner")
    if (
        not isinstance(identity, dict)
        or str(identity.get("login", "")).casefold() != owner.casefold()
    ):
        raise GitHubCollectionError("GitHub returned a repository outside the requested owner.")
    return payload


def _object(response: GitHubResponse, label: str) -> dict[str, Any]:
    if response.status != 200:
        raise GitHubCollectionError(f"GitHub {label} is unavailable; check access and target.")
    value = response.json()
    if not isinstance(value, dict):
        raise GitHubCollectionError(f"GitHub returned an invalid {label} object.")
    return value


def _collect_repository(
    owner: str,
    inventory: dict[str, Any],
    client: GitHubClient,
    warnings: list[str],
) -> RepositorySecurityControls:
    name = str(inventory["name"])
    path = f"/repos/{owner}/{name}"
    response = client.get(path)
    metadata = inventory
    secret = ControlState.UNKNOWN
    if response.status == 200:
        metadata = _repository(response.json(), owner)
        if metadata["name"].casefold() != name.casefold():
            raise GitHubCollectionError("Repository identity changed during collection; retry.")
        analysis = metadata.get("security_and_analysis")
        setting = analysis.get("secret_scanning") if isinstance(analysis, dict) else None
        status = setting.get("status") if isinstance(setting, dict) else None
        if status in ("enabled", "disabled"):
            secret = ControlState(status)
    if secret is ControlState.UNKNOWN:
        warnings.append(f"{name}: secret_scanning unknown; configuration omitted or inaccessible.")

    branch = metadata.get("default_branch")
    if branch is not None and (not isinstance(branch, str) or not _safe_branch(branch)):
        raise GitHubCollectionError("GitHub returned an invalid default branch.")
    branch_state = ControlState.NOT_COLLECTED
    if branch:
        result = client.get(path + "/branches/" + quote(branch, safe=""))
        branch_state = ControlState.UNKNOWN
        if result.status == 200:
            protected = _object(result, "branch").get("protected")
            if type(protected) is bool:
                branch_state = ControlState.ENABLED if protected else ControlState.DISABLED
        if branch_state is ControlState.UNKNOWN:
            warnings.append(f"{name}: branch_protection unknown; default-branch state unavailable.")
    else:
        warnings.append(f"{name}: branch_protection not_collected; no default branch was returned.")

    code = ControlState.UNKNOWN
    result = client.get(path + "/code-scanning/default-setup")
    if result.status == 200:
        state = _object(result, "code scanning configuration").get("state")
        if state == "configured":
            code = ControlState.ENABLED
        elif state == "not-configured":
            warnings.append(
                f"{name}: code_scanning unknown; default setup is not configured, "
                "but advanced or third-party scanning may exist."
            )
    if code is ControlState.UNKNOWN and not any(
        warning.startswith(f"{name}: code_scanning") for warning in warnings
    ):
        warnings.append(f"{name}: code_scanning unknown; default-setup configuration unavailable.")

    result = client.get(path + "/vulnerability-alerts")
    dependabot = ControlState.ENABLED if result.status == 204 else ControlState.UNKNOWN
    if dependabot is ControlState.UNKNOWN:
        warnings.append(
            f"{name}: dependabot_alerts unknown; the API did not confirm enabled. "
            "HTTP 403/404 can also reflect insufficient access."
        )
    raw_visibility = metadata.get("visibility")
    if raw_visibility is not None and (
        not isinstance(raw_visibility, str)
        or raw_visibility not in {item.value for item in Visibility}
    ):
        raise GitHubCollectionError("GitHub returned an invalid repository visibility.")
    return RepositorySecurityControls(
        name=name,
        default_branch=branch or None,
        visibility=Visibility(raw_visibility) if raw_visibility is not None else None,
        branch_protection=branch_state,
        secret_scanning=secret,
        code_scanning=code,
        dependabot_alerts=dependabot,
    )


def _safe_branch(branch: str) -> bool:
    try:
        branch.encode("utf-8")
    except UnicodeError:
        return False
    return len(branch) <= 1024 and not any(ord(char) < 32 or ord(char) == 127 for char in branch)
