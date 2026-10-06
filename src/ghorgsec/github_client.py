"""Bounded, GET-only GitHub REST client with an injectable transport."""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import Message
from http.client import HTTPException
from time import monotonic
from typing import IO, Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

API_ORIGIN = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REQUESTS = 4100
MAX_PAGES = 100
REQUEST_TIMEOUT_SECONDS = 10
COLLECTION_TIMEOUT_SECONDS = 300


class GitHubCollectionError(ValueError):
    """A safe, operator-facing error; never includes response bodies or tokens."""


@dataclass(frozen=True, slots=True)
class GitHubResponse:
    """Minimal HTTP result, kept in memory and never written into reports."""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    body: bytes = field(default=b"", repr=False)

    def json(self) -> Any:
        """Decode strict JSON without surfacing external content in an error."""
        try:
            return json.loads(
                self.body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeError, ValueError, RecursionError):
            raise GitHubCollectionError("GitHub returned invalid JSON.") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError("Non-finite JSON value")


class GitHubTransport(Protocol):
    """The only network operation required by the collector."""

    def get(
        self, url: str, headers: Mapping[str, str], timeout: float, max_bytes: int
    ) -> GitHubResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> None:
        # urllib otherwise forwards the Authorization header to a new origin.
        return None


class UrllibTransport:
    """HTTPS through the system trust store; redirects are deliberately refused."""

    def get(
        self, url: str, headers: Mapping[str, str], timeout: float, max_bytes: int
    ) -> GitHubResponse:
        request = Request(url, headers=dict(headers), method="GET")
        deadline = monotonic() + timeout
        try:
            try:
                response = build_opener(_NoRedirect()).open(request, timeout=timeout)
            except HTTPError as error:
                response = error
            with response:
                body = bytearray()
                while True:
                    if monotonic() >= deadline:
                        raise GitHubCollectionError(
                            "GitHub response exceeded the read time budget."
                        )
                    # read1 performs at most one buffered/raw read, so a slowly
                    # trickling body returns control for the deadline check.
                    chunk = response.read1(min(65536, max_bytes + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise GitHubCollectionError("GitHub response exceeded the size limit.")
                return GitHubResponse(
                    response.code,
                    {key.lower(): value for key, value in response.headers.items()},
                    bytes(body),
                )
        except GitHubCollectionError:
            raise
        except (URLError, OSError, ValueError, HTTPException):
            raise GitHubCollectionError(
                "GitHub request failed or timed out; no complete report was produced."
            ) from None


def _validate_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.netloc == "api.github.com"
            and parsed.path.startswith("/")
            and not parsed.fragment
            and "\\" not in url
            and not any(ord(char) < 33 for char in url)
        )
    except ValueError:
        valid = False
    if not valid:
        raise GitHubCollectionError("Refused a GitHub URL outside the allowed HTTPS origin.")


class GitHubClient:
    """Sequential REST reads with fixed origin, credential handling and budgets."""

    def __init__(
        self,
        token: str,
        *,
        transport: GitHubTransport | None = None,
        max_requests: int = MAX_REQUESTS,
    ) -> None:
        if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise GitHubCollectionError("A nonempty, valid GitHub token is required for --live.")
        if max_requests < 1:
            raise GitHubCollectionError("The GitHub request budget must be positive.")
        self._token = token
        self._transport = transport if transport is not None else UrllibTransport()
        self._max_requests = max_requests
        self._requests = 0
        self._deadline = monotonic() + COLLECTION_TIMEOUT_SECONDS

    def get(self, path_or_url: str) -> GitHubResponse:
        url = API_ORIGIN + path_or_url if path_or_url.startswith("/") else path_or_url
        _validate_url(url)
        if self._requests >= self._max_requests or monotonic() >= self._deadline:
            raise GitHubCollectionError("GitHub collection exceeded its request or time budget.")
        self._requests += 1
        response = self._transport.get(
            url,
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "ghorgsec",
            },
            timeout=min(REQUEST_TIMEOUT_SECONDS, max(0.1, self._deadline - monotonic())),
            max_bytes=MAX_RESPONSE_BYTES,
        )
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise GitHubCollectionError("GitHub response exceeded the size limit.")
        if response.status == 401:
            raise GitHubCollectionError("GitHub authentication failed; check the token.")
        if _rate_limited(response):
            raise GitHubCollectionError(
                "GitHub rate limit reached; retry later according to GitHub's limit headers."
            )
        if response.status not in (200, 204, 403, 404):
            raise GitHubCollectionError(
                f"GitHub returned HTTP {response.status}; no complete report was produced."
            )
        return response

    def pages(self, path: str) -> list[Any]:
        """Follow same-resource Link pagination or fail instead of silently truncating."""
        first_url = API_ORIGIN + path
        initial = urlsplit(first_url)
        url: str | None = first_url
        base_query = parse_qs(initial.query)
        items: list[Any] = []
        visited: set[str] = set()
        while url is not None:
            _validate_url(url)
            parsed = urlsplit(url)
            query = parse_qs(parsed.query)
            page = query.pop("page", ["1"])
            initial_query = {key: value for key, value in base_query.items() if key != "page"}
            if (
                parsed.path != initial.path
                or query != initial_query
                or len(page) != 1
                or re.fullmatch(r"[0-9]{1,3}", page[0]) is None
                or int(page[0]) < 1
                or url in visited
                or len(visited) >= MAX_PAGES
            ):
                raise GitHubCollectionError("GitHub pagination was invalid or exceeded its limit.")
            visited.add(url)
            response = self.get(url)
            if response.status != 200:
                raise GitHubCollectionError(
                    "GitHub repository inventory is unavailable; check access and target."
                )
            payload = response.json()
            if not isinstance(payload, list):
                raise GitHubCollectionError("GitHub returned an invalid repository inventory.")
            items.extend(payload)
            # The collector rejects >1000 repositories. Bound accumulation here too.
            if len(items) > 1000:
                raise GitHubCollectionError("GitHub inventory exceeds the 1000-repository limit.")
            url = _next_link(response.headers.get("link", ""))
        return items


def _rate_limited(response: GitHubResponse) -> bool:
    if response.status == 429:
        return True
    if response.status != 403:
        return False
    if response.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in response.headers:
        return True
    # Some secondary-limit responses have no limit header. Inspect, never print, the body.
    try:
        payload = response.json()
    except GitHubCollectionError:
        return False
    message = payload.get("message", "") if isinstance(payload, dict) else ""
    return isinstance(message, str) and any(
        marker in message.lower() for marker in ("rate limit", "abuse detection")
    )


def _next_link(header: str) -> str | None:
    if not header:
        return None
    next_url: str | None = None
    for part in re.split(r",\s*(?=<)", header):
        match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*', part)
        if match is None:
            raise GitHubCollectionError("GitHub returned an invalid pagination Link header.")
        if "next" in match[2].split():
            if next_url is not None:
                raise GitHubCollectionError("GitHub returned duplicate next-page links.")
            next_url = match[1]
    return next_url
