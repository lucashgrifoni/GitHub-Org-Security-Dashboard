"""Typer CLI for the read-only GitHub organization security dashboard."""

import os
import sys
from collections import Counter
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn, TextIO

import typer

from ghorgsec.collector import collect_org_security_snapshot
from ghorgsec.comparison import compare_snapshots
from ghorgsec.fixture_loader import FixtureLoadError, load_snapshot_fixture
from ghorgsec.github_client import GitHubClient, GitHubCollectionError
from ghorgsec.live_collector import collect_live_snapshot
from ghorgsec.models import OrgSecuritySnapshot
from ghorgsec.report import render_markdown_comparison, render_markdown_report
from ghorgsec.serialize import render_json_comparison, render_json_report

NEWLINE = "\n"


class OutputFormat(StrEnum):
    """Supported report output formats."""

    MD = "md"
    JSON = "json"


app = typer.Typer(
    help="Generate GitHub security reports. Offline by default; live reads require --live.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)


@app.callback()
def main() -> None:
    """Generate GitHub security reports with an explicit read-only live mode."""


@app.command()
def report(
    org: Annotated[
        str | None,
        typer.Option("--org", help="Organization name for a stub or explicit live report."),
    ] = None,
    repo: Annotated[
        list[str] | None,
        typer.Option(
            "--repo", help="Repository name to include, including in a fixture; repeat to select."
        ),
    ] = None,
    fixture: Annotated[
        Path | None,
        typer.Option(
            "--fixture",
            help="Local JSON fixture to render instead of synthetic repository names.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            help="Report output format.",
            case_sensitive=False,
        ),
    ] = OutputFormat.MD,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional local output path."),
    ] = None,
    live: Annotated[
        bool,
        typer.Option("--live", help="Read GitHub using GH_TOKEN or GITHUB_TOKEN (GET only)."),
    ] = False,
    user: Annotated[
        str | None,
        typer.Option("--user", help="Authenticated personal account; requires --live."),
    ] = None,
) -> None:
    """Render local input, or explicitly collect token-visible GitHub controls."""

    if fixture is not None and (live or user is not None):
        _fail("--live and --user cannot be combined with --fixture.")
    if user is not None and not live:
        _fail("--user requires --live; offline reports use --org or --fixture.")
    if user is not None and org is not None:
        _fail("Choose either --org or --user, not both.")
    if live:
        owner = user if user is not None else _require_org(org)
        try:
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
            snapshot = collect_live_snapshot(
                owner,
                client=GitHubClient(token),
                personal=user is not None,
                repositories=repo or [],
            )
        except GitHubCollectionError as error:
            _fail(str(error))
    elif fixture is not None:
        snapshot = _load_fixture_snapshot(fixture, org, repo)
    else:
        snapshot = collect_org_security_snapshot(org=_require_org(org), repositories=repo or [])
    rendered = _render(snapshot, output_format).rstrip(NEWLINE) + NEWLINE
    _write_output(rendered, output, (fixture,) if fixture is not None else (), "Report")


@app.command()
def compare(
    baseline: Annotated[Path, typer.Option("--baseline", help="Earlier local snapshot JSON.")],
    current: Annotated[Path, typer.Option("--current", help="Later local snapshot JSON.")],
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Comparison output format.", case_sensitive=False),
    ] = OutputFormat.MD,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Optional local comparison output path."),
    ] = None,
) -> None:
    """Compare supplied snapshot observations offline, without reading credentials."""

    try:
        comparison = compare_snapshots(
            load_snapshot_fixture(baseline), load_snapshot_fixture(current)
        )
    except (FixtureLoadError, ValueError) as error:
        _fail(str(error))
    rendered = (
        render_json_comparison(comparison)
        if output_format is OutputFormat.JSON
        else render_markdown_comparison(comparison)
    )
    _write_output(rendered, output, (baseline, current), "Comparison")


def _write_output(text: str, output: Path | None, inputs: tuple[Path, ...], label: str) -> None:
    rendered = text.rstrip(NEWLINE) + NEWLINE

    if output is None:
        write_report(rendered, sys.stdout)
        return

    try:
        if any(
            output.resolve() == source.resolve() or (output.exists() and output.samefile(source))
            for source in inputs
        ):
            _fail("--output must not overwrite the input fixture; choose another path.")

        # newline pins LF: without it write_text translates to the platform
        # line ending, so the same fixture produced a CRLF file on Windows and
        # an LF file on Linux, and the report hashed differently per platform.
        output.write_text(rendered, encoding="utf-8", newline="\n")
    except OSError as error:
        # A directory, a missing parent, a read-only location. Path.write_text
        # raises OSError and nothing caught it, so the CLI exited 1 with a
        # traceback while every other bad input reports Error: and exits 2.
        _fail(f"Unable to write report to {output}: {error.strerror or error}")

    typer.echo(f"{label} written to {output}")


def write_report(text: str, stream: TextIO) -> None:
    """Write UTF-8 and LF bytes when the stream provides a binary buffer.

    Bypassing the text wrapper preserves Unicode and prevents platform newline
    translation. Text-only streams receive the same text with one final newline.
    """

    text = text.rstrip(NEWLINE) + NEWLINE
    # Even a UTF-8 TextIOWrapper can translate LF to CRLF on Windows.
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        stream.flush()
        buffer.write(text.encode("utf-8"))
        buffer.flush()
        return

    stream.write(text)
    stream.flush()


def _render(snapshot: OrgSecuritySnapshot, output_format: OutputFormat) -> str:
    if output_format is OutputFormat.JSON:
        return render_json_report(snapshot)

    return render_markdown_report(snapshot)


def _load_fixture_snapshot(
    fixture: Path, org: str | None, repo: list[str] | None
) -> OrgSecuritySnapshot:
    if org is not None:
        # Previously accepted and then discarded: the report named the
        # organization from the JSON while the caller had typed another one.
        _fail("--org cannot be combined with --fixture; the organization comes from JSON.")

    try:
        snapshot = load_snapshot_fixture(fixture)
    except FixtureLoadError as error:
        _fail(str(error))

    if not repo:
        return snapshot
    requested = {name.strip().casefold() for name in repo}
    if "" in requested:
        _fail("--repo must be a nonempty repository name.")
    names = Counter(item.name.casefold() for item in snapshot.repositories)
    if requested - names.keys():
        _fail("A requested repository is absent from the snapshot; check --repo.")
    if any(names[name] > 1 for name in requested):
        _fail("Repository selection is ambiguous: snapshot names differ only in case.")
    return replace(
        snapshot,
        repositories=tuple(
            item for item in snapshot.repositories if item.name.casefold() in requested
        ),
        warnings=(
            *snapshot.warnings,
            "Repository filter applied to local snapshot; coverage describes selected "
            "repositories only. No new GitHub observations were collected.",
        ),
    )


def _require_org(org: str | None) -> str:
    if org is None or not org.strip():
        _fail("--org is required when --fixture is not provided.")

    return org


def _fail(message: str) -> NoReturn:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=2)
