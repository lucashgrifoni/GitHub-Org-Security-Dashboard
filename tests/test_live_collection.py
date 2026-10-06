"""Network-free contract and abuse tests for explicit read-only live collection."""

import io
import json
from collections.abc import Mapping
from email.message import Message
from http.client import HTTPMessage
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

import pytest
from typer.testing import CliRunner

from ghorgsec.cli import app
from ghorgsec.github_client import (
    API_ORIGIN,
    API_VERSION,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    GitHubClient,
    GitHubCollectionError,
    GitHubResponse,
    UrllibTransport,
    _NoRedirect,
)
from ghorgsec.live_collector import collect_live_snapshot
from ghorgsec.models import ControlState, OrgSecuritySnapshot
from ghorgsec.report import render_markdown_report

TOKEN = "synthetic-token-canary"


def response(
    payload: Any = None,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> GitHubResponse:
    return GitHubResponse(status, headers or {}, json.dumps(payload).encode("utf-8"))


class FakeTransport:
    def __init__(self, routes: Mapping[str, GitHubResponse]) -> None:
        self.routes = routes
        self.calls: list[str] = []
        self.headers: list[Mapping[str, str]] = []

    def get(
        self,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> GitHubResponse:
        assert timeout > 0
        assert max_bytes == MAX_RESPONSE_BYTES
        assert url.startswith(API_ORIGIN + "/")
        self.calls.append(url)
        self.headers.append(headers)
        parsed = urlsplit(url)
        target = parsed.path + ("?" + parsed.query if parsed.query else "")
        return self.routes[target]


def repository(name: str = "api", **fields: Any) -> dict[str, Any]:
    return {
        "name": name,
        "owner": {"login": "example"},
        "default_branch": "main",
        "visibility": "private",
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
        },
        **fields,
    }


def routes_for(repo: dict[str, Any], *, personal: bool = False) -> dict[str, GitHubResponse]:
    inventory = (
        "/user/repos?affiliation=owner&visibility=all&sort=full_name&per_page=100"
        if personal
        else "/orgs/example/repos?type=all&sort=full_name&per_page=100"
    )
    path = "/repos/example/" + repo["name"]
    return {
        "/user" if personal else "/orgs/example": response({"login": "example"}),
        inventory: response([repo]),
        path: response(repo),
        path + "/branches/main": response({"protected": True}),
        path + "/code-scanning/default-setup": response({"state": "configured"}),
        path + "/vulnerability-alerts": response(status=204),
    }


def collect(routes: Mapping[str, GitHubResponse], **kwargs: Any) -> OrgSecuritySnapshot:
    transport = FakeTransport(routes)
    return collect_live_snapshot(
        "example",
        client=GitHubClient(TOKEN, transport=transport),
        **kwargs,
    )


def test_observes_four_controls_and_personal_report_without_changing_json_contract() -> None:
    routes = routes_for(repository(), personal=True)
    snapshot = collect(routes, personal=True)
    assert snapshot.collection_mode == "github_live_user"
    assert "Personal account: `example`" in render_markdown_report(snapshot)
    repo = snapshot.repositories[0]
    assert repo.branch_protection is ControlState.ENABLED
    assert repo.secret_scanning is ControlState.ENABLED
    assert repo.code_scanning is ControlState.ENABLED
    assert repo.dependabot_alerts is ControlState.ENABLED
    assert repo.default_branch == "main"
    assert repo.visibility is not None and repo.visibility.value == "private"
    offset = snapshot.generated_at.utcoffset()
    assert offset is not None and offset.total_seconds() == 0
    assert "token-visible" in snapshot.warnings[0]


def test_personal_identity_mismatch_stops_before_inventory() -> None:
    transport = FakeTransport({"/user": response({"login": "other"})})
    with pytest.raises(GitHubCollectionError, match="must match"):
        collect_live_snapshot(
            "example", client=GitHubClient(TOKEN, transport=transport), personal=True
        )
    assert transport.calls == [API_ORIGIN + "/user"]


def test_org_collection_supports_filtered_case_insensitive_names() -> None:
    routes = routes_for(repository())
    routes["/orgs/example/repos?type=all&sort=full_name&per_page=100"] = response(
        [
            repository("web"),
            repository("api"),
        ]
    )
    snapshot = collect(routes, repositories=[" API ", "api"])
    assert snapshot.collection_mode == "github_live_org"
    assert [repo.name for repo in snapshot.repositories] == ["api"]
    assert any("filter applied" in warning for warning in snapshot.warnings)


@pytest.mark.parametrize("status", [403, 404])
def test_permission_gaps_are_unknown_never_disabled(status: int) -> None:
    routes = routes_for(repository())
    for path in [
        "/repos/example/api",
        "/repos/example/api/branches/main",
        "/repos/example/api/code-scanning/default-setup",
        "/repos/example/api/vulnerability-alerts",
    ]:
        routes[path] = response({"message": TOKEN}, status=status)
    snapshot = collect(routes)
    repo = snapshot.repositories[0]
    assert (
        repo.branch_protection,
        repo.secret_scanning,
        repo.code_scanning,
        repo.dependabot_alerts,
    ) == (ControlState.UNKNOWN,) * 4
    assert all(TOKEN not in warning for warning in snapshot.warnings)
    assert sum(warning.startswith("api:") for warning in snapshot.warnings) == 4


def test_explicit_disabled_and_unconfigured_custom_scanning_remain_distinct() -> None:
    repo = repository(security_and_analysis={"secret_scanning": {"status": "disabled"}})
    routes = routes_for(repo)
    routes["/repos/example/api/branches/main"] = response({"protected": False})
    routes["/repos/example/api/code-scanning/default-setup"] = response({"state": "not-configured"})
    snapshot = collect(routes)
    assert snapshot.repositories[0].branch_protection is ControlState.DISABLED
    assert snapshot.repositories[0].secret_scanning is ControlState.DISABLED
    assert snapshot.repositories[0].code_scanning is ControlState.UNKNOWN
    assert any("advanced or third-party" in warning for warning in snapshot.warnings)


def test_absent_metadata_and_branch_are_not_invented() -> None:
    repo = repository(default_branch=None, visibility=None, security_and_analysis=None)
    routes = routes_for(repo)
    routes["/repos/example/api/code-scanning/default-setup"] = response({"state": "future-state"})
    snapshot = collect(routes)
    assert snapshot.repositories[0].branch_protection is ControlState.NOT_COLLECTED
    assert snapshot.repositories[0].default_branch is None
    assert snapshot.repositories[0].visibility is None
    assert snapshot.repositories[0].secret_scanning is ControlState.UNKNOWN


def test_non_boolean_branch_protection_is_unknown() -> None:
    routes = routes_for(repository())
    routes["/repos/example/api/branches/main"] = response({"protected": "true"})
    assert collect(routes).repositories[0].branch_protection is ControlState.UNKNOWN


def test_unicode_branch_is_quoted_as_one_path_component() -> None:
    repo = repository(default_branch="release/主分支")
    routes = routes_for(repo)
    routes["/repos/example/api/branches/release%2F%E4%B8%BB%E5%88%86%E6%94%AF"] = response(
        {"protected": True}
    )
    assert collect(routes).repositories[0].branch_protection is ControlState.ENABLED


@pytest.mark.parametrize("branch", [42, "bad\nbranch", "\ud800", "x" * 1025])
def test_invalid_branch_metadata_fails_without_traceback(branch: Any) -> None:
    with pytest.raises(GitHubCollectionError, match="default branch"):
        collect(routes_for(repository(default_branch=branch)))


@pytest.mark.parametrize("visibility", ["world", [], 42])
def test_invalid_visibility_is_safely_rejected(visibility: Any) -> None:
    with pytest.raises(GitHubCollectionError, match="visibility"):
        collect(routes_for(repository(visibility=visibility)))


@pytest.mark.parametrize(
    "payload", [[], {}, {"name": "../escape"}, repository(owner={"login": "other"})]
)
def test_invalid_or_cross_owner_repository_inventory_fails(payload: Any) -> None:
    routes = routes_for(repository())
    routes["/orgs/example/repos?type=all&sort=full_name&per_page=100"] = response([payload])
    with pytest.raises(GitHubCollectionError):
        collect(routes)


def test_missing_requested_and_duplicate_repositories_fail_instead_of_clean_empty_report() -> None:
    with pytest.raises(GitHubCollectionError, match="absent"):
        collect(routes_for(repository()), repositories=["missing"])
    routes = routes_for(repository())
    routes["/orgs/example/repos?type=all&sort=full_name&per_page=100"] = response(
        [
            repository(),
            repository("API"),
        ]
    )
    with pytest.raises(GitHubCollectionError, match="duplicate"):
        collect(routes)


def test_changed_identity_is_rejected() -> None:
    routes = routes_for(repository())
    routes["/repos/example/api"] = response(repository("renamed"))
    with pytest.raises(GitHubCollectionError, match="identity changed"):
        collect(routes)
    routes["/orgs/example"] = response({"login": "other"})
    with pytest.raises(GitHubCollectionError, match="unexpected organization"):
        collect(routes)


@pytest.mark.parametrize("owner", ["../escape", "bad owner", "", "-bad", "x" * 40])
def test_invalid_owner_never_sends_request(owner: str) -> None:
    transport = FakeTransport({})
    with pytest.raises(GitHubCollectionError, match="account name"):
        collect_live_snapshot(owner, client=GitHubClient(TOKEN, transport=transport))
    assert transport.calls == []


@pytest.mark.parametrize("payload, status", [([], 200), ({}, 403), ({}, 404)])
def test_unavailable_or_invalid_identity_is_a_safe_error(payload: Any, status: int) -> None:
    routes = {"/orgs/example": response(payload, status=status)}
    with pytest.raises(GitHubCollectionError):
        collect(routes)


def test_bad_control_object_is_rejected() -> None:
    routes = routes_for(repository())
    routes["/repos/example/api/branches/main"] = response([])
    with pytest.raises(GitHubCollectionError, match="branch object"):
        collect(routes)


def test_pagination_preserves_inventory_and_never_exposes_credentials() -> None:
    path = "/user/repos?affiliation=owner&per_page=100"
    next_url = API_ORIGIN + path + "&page=2"
    transport = FakeTransport(
        {
            path: response(
                [1], headers={"link": f'<{next_url}>; rel="next", <{next_url}>; rel="last"'}
            ),
            path + "&page=2": response([2]),
        }
    )
    client = GitHubClient(TOKEN, transport=transport)
    assert client.pages(path) == [1, 2]
    assert all(headers["Authorization"] == f"Bearer {TOKEN}" for headers in transport.headers)
    assert all(headers["X-GitHub-Api-Version"] == API_VERSION for headers in transport.headers)
    assert TOKEN not in repr(client)
    assert TOKEN not in repr(response({"secret": TOKEN}))


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.invalid/user/repos?per_page=100&page=2",
        "http://api.github.com/user/repos?per_page=100&page=2",
        "https://api.github.com:443/user/repos?per_page=100&page=2",
        "https://user:password@api.github.com/user/repos?per_page=100&page=2",
        "https://api.github.com/user/repos?per_page=100&page=2#fragment",
        "https://api.github.com/other?per_page=100&page=2",
        "https://api.github.com/user/repos?per_page=1&page=2",
        "https://api.github.com/user/repos?per_page=100&page=bad",
        "https://api.github.com/user/repos?per_page=100&page=%C2%B2",
        "https://api.github.com/user/repos?per_page=100&page=0",
        "https://api.github.com/user/repos?per_page=100&page=2&page=3",
        "https://[broken/user/repos?per_page=100&page=2",
    ],
)
def test_malicious_pagination_sends_no_second_request(target: str) -> None:
    path = "/user/repos?per_page=100"
    transport = FakeTransport({path: response([], headers={"link": f'<{target}>; rel="next"'})})
    with pytest.raises(GitHubCollectionError):
        GitHubClient(TOKEN, transport=transport).pages(path)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "link",
    [
        "malformed",
        '<https://api.github.com/user/repos>; rel="next", '
        '<https://api.github.com/user/repos>; rel="next"',
    ],
)
def test_invalid_link_is_not_silently_treated_as_end_of_inventory(link: str) -> None:
    transport = FakeTransport({"/user/repos": response([], headers={"link": link})})
    with pytest.raises(GitHubCollectionError):
        GitHubClient(TOKEN, transport=transport).pages("/user/repos")


def test_pagination_cycle_and_page_budget_fail() -> None:
    path = "/user/repos"
    transport = FakeTransport(
        {path: response([], headers={"link": f'<{API_ORIGIN}{path}>; rel="next"'})}
    )
    with pytest.raises(GitHubCollectionError, match="pagination"):
        GitHubClient(TOKEN, transport=transport).pages(path)
    assert len(transport.calls) == 1
    routes: dict[str, GitHubResponse] = {}
    for page in range(1, MAX_PAGES + 1):
        target = path if page == 1 else f"{path}?page={page}"
        routes[target] = response(
            [], headers={"link": f'<{API_ORIGIN}{path}?page={page + 1}>; rel="next"'}
        )
    transport = FakeTransport(routes)
    with pytest.raises(GitHubCollectionError, match="pagination"):
        GitHubClient(TOKEN, transport=transport).pages(path)
    assert len(transport.calls) == MAX_PAGES


@pytest.mark.parametrize("payload, status", [({}, 200), ([], 403), ([], 404), ([{}] * 1001, 200)])
def test_invalid_unavailable_or_oversized_inventory_is_rejected(payload: Any, status: int) -> None:
    transport = FakeTransport({"/user/repos": response(payload, status=status)})
    with pytest.raises(GitHubCollectionError):
        GitHubClient(TOKEN, transport=transport).pages("/user/repos")


@pytest.mark.parametrize(
    "status, headers, payload",
    [
        (401, {}, {"message": TOKEN}),
        (429, {}, {}),
        (403, {"x-ratelimit-remaining": "0"}, {}),
        (403, {"retry-after": "60"}, {}),
        (403, {}, {"message": "You have exceeded a secondary rate limit."}),
        (500, {}, {"message": TOKEN}),
        (301, {"location": "https://evil.invalid/"}, {}),
    ],
)
def test_auth_rate_limit_server_errors_and_redirects_stop_without_retry(
    status: int,
    headers: Mapping[str, str],
    payload: Any,
) -> None:
    transport = FakeTransport({"/user": response(payload, status, headers)})
    with pytest.raises(GitHubCollectionError) as caught:
        GitHubClient(TOKEN, transport=transport).get("/user")
    assert TOKEN not in str(caught.value)
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "body", [b"not json", b"\xff", b'{"x":1,"x":2}', b'{"x":NaN}', b"[" * 2000]
)
def test_malformed_json_cannot_leak_body(body: bytes) -> None:
    with pytest.raises(GitHubCollectionError, match="invalid JSON"):
        GitHubResponse(200, body=body).json()


def test_forbidden_ambiguous_bodies_stay_available_for_gap_mapping() -> None:
    for body in [b"not json", b"[]", b'{"message":42}']:
        transport = FakeTransport({"/user": GitHubResponse(403, body=body)})
        assert GitHubClient(TOKEN, transport=transport).get("/user").status == 403


def test_request_time_body_and_token_limits_fail_before_additional_effects() -> None:
    transport = FakeTransport({"/user": response({})})
    client = GitHubClient(TOKEN, transport=transport, max_requests=1)
    client.get("/user")
    with pytest.raises(GitHubCollectionError, match="budget"):
        client.get("/user")
    assert len(transport.calls) == 1
    with patch("ghorgsec.github_client.monotonic", return_value=0):
        timed = GitHubClient(TOKEN, transport=transport)
    with (
        patch("ghorgsec.github_client.monotonic", return_value=301),
        pytest.raises(GitHubCollectionError, match="budget"),
    ):
        timed.get("/user")
    oversized = FakeTransport({"/user": GitHubResponse(200, body=b"x" * (MAX_RESPONSE_BYTES + 1))})
    with pytest.raises(GitHubCollectionError, match="size limit"):
        GitHubClient(TOKEN, transport=oversized).get("/user")
    for token in ["", "line\nbreak", "\u00e9"]:
        with pytest.raises(GitHubCollectionError, match="valid GitHub token"):
            GitHubClient(token, transport=transport)
    with pytest.raises(GitHubCollectionError, match="positive"):
        GitHubClient(TOKEN, max_requests=0)


def test_transport_is_get_only_bounded_and_uses_a_redirect_blocker() -> None:
    raw = MagicMock()
    raw.__enter__.return_value = raw
    raw.read1.side_effect = [b'{"ok":true}', b""]
    raw.code = 200
    raw.headers = {"Link": "value"}
    with patch("ghorgsec.github_client.build_opener") as build:
        build.return_value.open.return_value = raw
        result = UrllibTransport().get(API_ORIGIN + "/user", {"Authorization": TOKEN}, 10, 100)
    request = build.return_value.open.call_args.args[0]
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == TOKEN
    assert isinstance(build.call_args.args[0], _NoRedirect)
    assert raw.read1.call_args_list[0].args == (101,)
    assert raw.read1.call_args_list[1].args == (90,)
    assert result.headers == {"link": "value"}
    assert result.json() == {"ok": True}


def test_urllib_redirect_handler_refuses_actual_redirect_without_forwarding_token() -> None:
    handler = _NoRedirect()
    parent = MagicMock()
    handler.add_parent(parent)
    headers = HTTPMessage()
    headers["Location"] = "https://evil.invalid/exfiltrate"
    request = Request(API_ORIGIN + "/user", headers={"Authorization": TOKEN})
    assert handler.http_error_302(request, io.BytesIO(), 302, "Found", headers) is None
    parent.open.assert_not_called()


def test_transport_sanitizes_io_errors_and_bounds_real_reads() -> None:
    with patch("ghorgsec.github_client.build_opener") as build:
        build.return_value.open.side_effect = URLError(TOKEN)
        with pytest.raises(GitHubCollectionError) as caught:
            UrllibTransport().get(API_ORIGIN + "/user", {}, 10, 100)
        assert TOKEN not in str(caught.value)
        build.return_value.open.side_effect = HTTPError(
            API_ORIGIN + "/user",
            403,
            TOKEN,
            Message(),
            io.BytesIO(b"{}"),
        )
        assert UrllibTransport().get(API_ORIGIN + "/user", {}, 10, 100).status == 403
        build.return_value.open.side_effect = None
        raw = build.return_value.open.return_value
        raw.read1.return_value = b"x" * 101
        with pytest.raises(GitHubCollectionError, match="size limit"):
            UrllibTransport().get(API_ORIGIN + "/user", {}, 10, 100)


def test_slow_stream_returns_control_to_deadline_without_retry() -> None:
    with (
        patch("ghorgsec.github_client.build_opener") as build,
        patch("ghorgsec.github_client.monotonic", side_effect=[0, 0, 11]),
    ):
        raw = build.return_value.open.return_value
        raw.read1.return_value = b"partial"
        with pytest.raises(GitHubCollectionError, match="read time budget"):
            UrllibTransport().get(API_ORIGIN + "/user", {}, 10, 100)
        raw.read1.assert_called_once()


@pytest.mark.parametrize(
    "args",
    [
        ["--live", "--fixture", "absent.json"],
        ["--user", "example"],
        ["--live", "--user", "example", "--org", "example"],
        ["--live"],
        ["--fixture", "absent.json", "--user", "example"],
    ],
)
def test_conflicting_cli_inputs_never_construct_a_client(args: list[str]) -> None:
    with patch("ghorgsec.cli.GitHubClient") as client:
        result = CliRunner().invoke(app, ["report", *args])
    assert result.exit_code == 2
    client.assert_not_called()


def test_offline_default_ignores_even_invalid_token_environment() -> None:
    with (
        patch("ghorgsec.cli.GitHubClient") as client,
        patch.dict("os.environ", {"GH_TOKEN": "bad\ntoken"}),
    ):
        result = CliRunner().invoke(app, ["report", "--org", "example", "--repo", "api"])
    assert result.exit_code == 0
    assert "offline_stub" in result.stdout
    client.assert_not_called()


def test_cli_live_requires_token_and_does_not_overwrite_output_on_error() -> None:
    with TemporaryDirectory() as directory, patch.dict("os.environ", {}, clear=True):
        path = Path(directory) / "existing.json"
        path.write_text("preserve me", encoding="utf-8")
        result = CliRunner().invoke(app, ["report", "--live", "--user", "example", "-o", str(path)])
        assert result.exit_code == 2
        assert path.read_text(encoding="utf-8") == "preserve me"
        assert "Error:" in result.stderr
        assert "Traceback" not in result.output


def test_cli_live_token_precedence_json_and_error_redaction() -> None:
    transport = FakeTransport(routes_for(repository(), personal=True))
    with (
        patch(
            "ghorgsec.cli.GitHubClient", return_value=GitHubClient(TOKEN, transport=transport)
        ) as client,
        patch.dict("os.environ", {"GH_TOKEN": TOKEN, "GITHUB_TOKEN": "fallback"}),
    ):
        result = CliRunner().invoke(
            app,
            ["report", "--live", "--user", "example", "--format", "json"],
        )
    client.assert_called_once_with(TOKEN)
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["organization"] == "example"
    assert payload["collection_mode"] == "github_live_user"
    assert TOKEN not in result.output
    with (
        patch(
            "ghorgsec.cli.GitHubClient",
            side_effect=GitHubCollectionError("GitHub authentication failed"),
        ) as client,
        patch.dict("os.environ", {"GH_TOKEN": "", "GITHUB_TOKEN": "fallback"}),
    ):
        result = CliRunner().invoke(app, ["report", "--live", "--org", "example"])
    client.assert_called_once_with("fallback")
    assert result.exit_code == 2
    assert "fallback" not in result.output
