"""Typer CLI for the read-only GitHub organization security dashboard."""

from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from ghorgsec.collector import collect_org_security_snapshot
from ghorgsec.fixture_loader import FixtureLoadError, load_snapshot_fixture
from ghorgsec.models import OrgSecuritySnapshot
from ghorgsec.report import render_markdown_report
from ghorgsec.serialize import render_json_report


class OutputFormat(StrEnum):
    """Supported report output formats."""

    MD = "md"
    JSON = "json"


app = typer.Typer(
    help="Generate offline GitHub organization security dashboard reports.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """Generate offline GitHub organization security dashboard reports."""


@app.command()
def report(
    org: Annotated[
        str | None,
        typer.Option("--org", help="Organization name for the local stub report."),
    ] = None,
    repo: Annotated[
        list[str] | None,
        typer.Option("--repo", help="Repository name to include in the stub snapshot."),
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
) -> None:
    """Render a Markdown or JSON report from local stub input or a JSON fixture."""

    snapshot = (
        _load_fixture_snapshot(fixture, repo)
        if fixture is not None
        else collect_org_security_snapshot(
            org=_require_org(org), repositories=repo or []
        )
    )
    rendered = _render(snapshot, output_format)

    if output is None:
        typer.echo(rendered)
        return

    output.write_text(rendered, encoding="utf-8")
    typer.echo(f"Report written to {output}")


def _render(snapshot: OrgSecuritySnapshot, output_format: OutputFormat) -> str:
    if output_format is OutputFormat.JSON:
        return render_json_report(snapshot)

    return render_markdown_report(snapshot)


def _load_fixture_snapshot(
    fixture: Path, repo: list[str] | None
) -> OrgSecuritySnapshot:
    if repo:
        _fail("--repo cannot be combined with --fixture; repositories come from JSON.")

    try:
        return load_snapshot_fixture(fixture)
    except FixtureLoadError as error:
        _fail(str(error))


def _require_org(org: str | None) -> str:
    if org is None or not org.strip():
        _fail("--org is required when --fixture is not provided.")

    return org


def _fail(message: str) -> NoReturn:
    typer.echo(f"Error: {message}", err=True)
    raise typer.Exit(code=2)
