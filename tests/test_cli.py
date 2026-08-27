"""Unit tests for the Typer CLI surface."""

import io
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from typer.testing import CliRunner

from ghorgsec.cli import app, write_report

runner = CliRunner()
BREAK = "\n"


def _valid_fixture_payload() -> dict[str, Any]:
    return {
        "organization": "example-org",
        "generated_at": "2026-05-18T12:00:00+00:00",
        "repositories": [
            {
                "name": "api",
                "default_branch": "main",
                "visibility": "private",
                "controls": {
                    "branch_protection": "enabled",
                    "secret_scanning": "enabled",
                    "code_scanning": "unknown",
                    "dependabot_alerts": "disabled",
                },
            }
        ],
    }


class CliTests(unittest.TestCase):
    def test_no_args_shows_help(self) -> None:
        # no_args_is_help renders help and exits 2 (Click's "missing command").
        result = runner.invoke(app, [])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("report", result.output)

    def test_report_with_org_renders_stub_markdown(self) -> None:
        result = runner.invoke(app, ["report", "--org", "example-org", "--repo", "api"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Collection mode: `offline_stub`", result.stdout)
        self.assertIn("| api |", result.stdout)
        self.assertIn("not_collected", result.stdout)

    def test_report_requires_org_when_no_fixture(self) -> None:
        result = runner.invoke(app, ["report"])
        self.assertEqual(result.exit_code, 2)
        self.assertIn("--org is required", result.stderr)

    def test_report_rejects_repo_combined_with_fixture(self) -> None:
        with TemporaryDirectory() as tmp:
            fixture_path = Path(tmp) / "snapshot.json"
            fixture_path.write_text(json.dumps(_valid_fixture_payload()), encoding="utf-8")

            result = runner.invoke(
                app,
                ["report", "--fixture", str(fixture_path), "--repo", "api"],
            )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("--repo cannot be combined with --fixture", result.stderr)

    def test_report_from_fixture_renders_markdown(self) -> None:
        with TemporaryDirectory() as tmp:
            fixture_path = Path(tmp) / "snapshot.json"
            fixture_path.write_text(json.dumps(_valid_fixture_payload()), encoding="utf-8")

            result = runner.invoke(app, ["report", "--fixture", str(fixture_path)])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Collection mode: `fixture_json`", result.stdout)
        self.assertIn(
            "| api | main | private | enabled | enabled | unknown | disabled |",
            result.stdout,
        )

    def test_report_invalid_fixture_reports_error(self) -> None:
        with TemporaryDirectory() as tmp:
            fixture_path = Path(tmp) / "broken.json"
            fixture_path.write_text("{ not json", encoding="utf-8")

            result = runner.invoke(app, ["report", "--fixture", str(fixture_path)])

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Invalid JSON fixture", result.stderr)

    def test_report_json_format_emits_valid_json(self) -> None:
        result = runner.invoke(
            app,
            ["report", "--org", "example-org", "--repo", "api", "--format", "json"],
        )

        self.assertEqual(result.exit_code, 0)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["organization"], "example-org")
        self.assertEqual(parsed["collection_mode"], "offline_stub")
        self.assertEqual(parsed["repositories"][0]["name"], "api")

    def test_report_rejects_unknown_format(self) -> None:
        result = runner.invoke(
            app,
            ["report", "--org", "example-org", "--format", "xml"],
        )

        self.assertEqual(result.exit_code, 2)

    def test_report_writes_output_file(self) -> None:
        with TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "report.md"
            result = runner.invoke(
                app,
                ["report", "--org", "example-org", "--repo", "api", "--output", str(output_path)],
            )

            self.assertEqual(result.exit_code, 0)
            self.assertIn(f"Report written to {output_path}", result.stdout)
            written = output_path.read_text(encoding="utf-8")

        self.assertIn("# GitHub Org Security Dashboard", written)
        self.assertIn("| api |", written)


    def test_write_report_survives_a_console_that_cannot_encode_the_content(self) -> None:
        """A stream whose code page cannot hold the report must still receive it.

        `--output` pins encoding="utf-8", but printing inherited the console
        code page. On cp1252 a CJK branch name or a non-Latin warning raised
        UnicodeEncodeError and exited with a raw traceback, bypassing the CLI's
        own Error:/exit-2 convention — the tool could produce a report it could
        not show.
        """

        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="cp1252", newline="")
        report = "branch: 主分支 | warning: Сканирование не выполнялось"

        write_report(report, console)

        written = raw.getvalue().decode("utf-8")
        self.assertEqual(written.rstrip("\n"), report)
        self.assertTrue(written.endswith("\n"))

    def test_write_report_uses_the_stream_directly_when_it_speaks_utf8(self) -> None:
        raw = io.BytesIO()
        console = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        write_report("plain ascii", console)
        console.flush()

        self.assertEqual(raw.getvalue().decode("utf-8"), "plain ascii\n")


    def test_write_report_falls_back_to_the_text_stream_without_a_buffer(self) -> None:
        """A non-UTF-8 stream with no binary buffer still gets the text.

        Nothing better is available in that case, so the write goes to the text
        stream as-is rather than being dropped.
        """

        class _NoBuffer(io.StringIO):
            encoding = "cp1252"

        stream = _NoBuffer()
        write_report("plain ascii", stream)

        self.assertEqual(stream.getvalue(), "plain ascii" + BREAK)


    def test_output_to_a_directory_reports_an_error_instead_of_a_traceback(self) -> None:
        """An unwritable --output path must use the CLI's own error contract.

        `Path.write_text` raises OSError, which nothing caught, so the CLI
        exited 1 with a raw traceback while every other bad input reports
        `Error:` and exits 2.
        """

        with TemporaryDirectory() as directory:
            result = runner.invoke(
                app, ["report", "--org", "acme", "--output", directory]
            )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error:", result.output)

    def test_output_into_a_missing_directory_reports_an_error(self) -> None:
        with TemporaryDirectory() as directory:
            target = Path(directory) / "no-such-dir" / "report.md"
            result = runner.invoke(
                app, ["report", "--org", "acme", "--output", str(target)]
            )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Error:", result.output)


    def test_org_cannot_be_combined_with_fixture(self) -> None:
        """--org with --fixture must be refused, not silently discarded.

        --repo was already refused for the same conflict. --org was accepted
        and then ignored: the report carried the organization named in the
        JSON, not the one the caller typed, with no indication the value had
        been dropped. On a report about who owns which posture, quietly
        answering about a different organization is the wrong failure.
        """

        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "snapshot.json"
            fixture.write_text(json.dumps(_valid_fixture_payload()), encoding="utf-8")

            result = runner.invoke(
                app,
                ["report", "--org", "typed-by-the-caller", "--fixture", str(fixture)],
            )

        self.assertEqual(result.exit_code, 2)
        self.assertIn("--org cannot be combined with --fixture", result.stderr)
        self.assertNotIn("typed-by-the-caller", result.stdout)


    def test_output_file_bytes_do_not_depend_on_the_platform(self) -> None:
        """--output must write LF everywhere, so the artifact hashes the same.

        `Path.write_text` translates to the platform line ending by default, so
        the same fixture produced a CRLF file on Windows and an LF file on
        Linux. The README advertises deterministic output for automation, and a
        consumer hashing the report as evidence would get a different digest
        per platform.
        """

        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "snapshot.json"
            fixture.write_text(json.dumps(_valid_fixture_payload()), encoding="utf-8")
            target = Path(directory) / "report.md"

            result = runner.invoke(
                app,
                ["report", "--fixture", str(fixture), "--output", str(target)],
            )
            self.assertEqual(result.exit_code, 0, result.output)

            written = target.read_bytes()

        self.assertNotIn(bytes([13, 10]), written)   # no CRLF
        self.assertIn(bytes([10]), written)          # but LF is present


if __name__ == "__main__":
    unittest.main()
