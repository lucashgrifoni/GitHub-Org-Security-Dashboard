"""Unit tests for local JSON fixture loading."""

import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from ghorgsec.fixture_loader import (
    FIXTURE_COLLECTION_MODE,
    FixtureLoadError,
    load_snapshot_fixture,
    parse_snapshot_fixture,
)
from ghorgsec.models import ControlState, Visibility
from ghorgsec.report import render_markdown_report


class FixtureLoaderTests(unittest.TestCase):
    def test_example_fixture_loads_and_renders_markdown_report(self) -> None:
        fixture_path = (
            Path(__file__).resolve().parents[1]
            / "examples"
            / "org-security-snapshot.json"
        )

        snapshot = load_snapshot_fixture(fixture_path)
        markdown = render_markdown_report(snapshot)

        self.assertEqual(snapshot.organization, "example-org")
        self.assertEqual(snapshot.collection_mode, FIXTURE_COLLECTION_MODE)
        self.assertEqual(len(snapshot.repositories), 3)
        self.assertEqual(
            snapshot.repositories[0].branch_protection,
            ControlState.ENABLED,
        )
        self.assertEqual(snapshot.repositories[0].default_branch, "main")
        self.assertEqual(snapshot.repositories[0].visibility, "private")
        self.assertEqual(snapshot.repositories[2].visibility, "public")
        self.assertIn("Local fixture only: no GitHub API calls", markdown)
        self.assertIn("Collection mode: `fixture_json`", markdown)
        self.assertIn(
            "| payments-api | main | private | enabled | enabled | enabled | enabled |",
            markdown,
        )

    def test_parse_snapshot_fixture_rejects_unknown_control_state(self) -> None:
        payload = _valid_fixture_payload()
        controls = payload["repositories"][0]["controls"]
        controls["branch_protection"] = "partially_enabled"

        with self.assertRaisesRegex(FixtureLoadError, "branch_protection"):
            parse_snapshot_fixture(payload)

    def test_parse_snapshot_fixture_requires_timezone(self) -> None:
        payload = _valid_fixture_payload()
        payload["generated_at"] = "2026-05-18T12:00:00"

        with self.assertRaisesRegex(FixtureLoadError, "timezone"):
            parse_snapshot_fixture(payload)

    def test_generated_at_accepts_zulu_suffix(self) -> None:
        payload = _valid_fixture_payload()
        payload["generated_at"] = "2026-05-18T12:00:00Z"

        snapshot = parse_snapshot_fixture(payload)

        self.assertEqual(snapshot.generated_at.utcoffset(), timedelta(0))

    def test_generated_at_rejects_non_string(self) -> None:
        payload = _valid_fixture_payload()
        payload["generated_at"] = 1234567890

        with self.assertRaisesRegex(FixtureLoadError, "generated_at"):
            parse_snapshot_fixture(payload)

    def test_generated_at_rejects_unparseable_value(self) -> None:
        payload = _valid_fixture_payload()
        payload["generated_at"] = "not-a-datetime"

        with self.assertRaisesRegex(FixtureLoadError, "valid ISO datetime"):
            parse_snapshot_fixture(payload)

    def test_fixture_rejects_non_object_payload(self) -> None:
        with self.assertRaisesRegex(FixtureLoadError, "fixture must be a JSON object"):
            parse_snapshot_fixture(["not", "an", "object"])

    def test_fixture_requires_organization(self) -> None:
        payload = _valid_fixture_payload()
        del payload["organization"]

        with self.assertRaisesRegex(FixtureLoadError, "organization"):
            parse_snapshot_fixture(payload)

    def test_repositories_must_be_a_list(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"] = {"api": {}}

        with self.assertRaisesRegex(FixtureLoadError, "repositories must be a JSON array"):
            parse_snapshot_fixture(payload)

    def test_repository_must_be_an_object(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"] = ["api"]

        with self.assertRaisesRegex(FixtureLoadError, r"repositories\[0\] must be a JSON object"):
            parse_snapshot_fixture(payload)

    def test_duplicate_repository_names_are_rejected(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"].append(dict(payload["repositories"][0]))

        with self.assertRaisesRegex(FixtureLoadError, "name must be unique"):
            parse_snapshot_fixture(payload)

    def test_repository_requires_name(self) -> None:
        payload = _valid_fixture_payload()
        del payload["repositories"][0]["name"]

        with self.assertRaisesRegex(FixtureLoadError, "name must be a non-empty string"):
            parse_snapshot_fixture(payload)

    def test_controls_block_must_be_an_object(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"][0]["controls"] = "enabled"

        with self.assertRaisesRegex(FixtureLoadError, "controls must be a JSON object"):
            parse_snapshot_fixture(payload)

    def test_missing_control_state_is_rejected(self) -> None:
        payload = _valid_fixture_payload()
        del payload["repositories"][0]["controls"]["secret_scanning"]

        with self.assertRaisesRegex(FixtureLoadError, "secret_scanning"):
            parse_snapshot_fixture(payload)

    def test_visibility_accepts_allowlisted_internal_value(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"][0]["visibility"] = "internal"

        snapshot = parse_snapshot_fixture(payload)

        self.assertEqual(snapshot.repositories[0].visibility, Visibility.INTERNAL)

    def test_visibility_rejects_value_outside_allowlist(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"][0]["visibility"] = "secret"

        with self.assertRaisesRegex(
            FixtureLoadError, "visibility must be one of: public, private, internal"
        ):
            parse_snapshot_fixture(payload)

    def test_visibility_rejects_empty_string(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"][0]["visibility"] = "  "

        with self.assertRaisesRegex(FixtureLoadError, "visibility must be a non-empty string"):
            parse_snapshot_fixture(payload)

    def test_optional_metadata_rejects_empty_string(self) -> None:
        payload = _valid_fixture_payload()
        payload["repositories"][0]["default_branch"] = "   "

        with self.assertRaisesRegex(FixtureLoadError, "default_branch must be a non-empty string"):
            parse_snapshot_fixture(payload)

    def test_warnings_must_be_a_list(self) -> None:
        payload = _valid_fixture_payload()
        payload["warnings"] = "just a string"

        with self.assertRaisesRegex(FixtureLoadError, "warnings must be a JSON array"):
            parse_snapshot_fixture(payload)

    def test_warning_entries_must_be_non_empty_strings(self) -> None:
        payload = _valid_fixture_payload()
        payload["warnings"] = ["ok", "  "]

        with self.assertRaisesRegex(FixtureLoadError, r"warnings\[1\]"):
            parse_snapshot_fixture(payload)

    def test_user_warnings_are_preserved_and_deduplicated(self) -> None:
        payload = _valid_fixture_payload()
        payload["warnings"] = ["custom warning", "custom warning"]

        snapshot = parse_snapshot_fixture(payload)

        self.assertIn("custom warning", snapshot.warnings)
        self.assertEqual(snapshot.warnings.count("custom warning"), 1)

    def test_controls_can_be_provided_inline_without_controls_block(self) -> None:
        payload = _valid_fixture_payload()
        repo = payload["repositories"][0]
        inline = dict(repo["controls"])
        del repo["controls"]
        repo.update(inline)

        snapshot = parse_snapshot_fixture(payload)

        self.assertEqual(snapshot.repositories[0].branch_protection, ControlState.ENABLED)
        self.assertEqual(snapshot.repositories[0].dependabot_alerts, ControlState.DISABLED)

    def test_load_snapshot_fixture_missing_file_raises(self) -> None:
        with self.assertRaisesRegex(FixtureLoadError, "Unable to read fixture file"):
            load_snapshot_fixture(Path("does-not-exist-12345.json"))

    def test_load_snapshot_fixture_invalid_json_raises(self) -> None:
        with TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.json"
            broken.write_text("{ not valid", encoding="utf-8")

            with self.assertRaisesRegex(FixtureLoadError, "Invalid JSON fixture"):
                load_snapshot_fixture(broken)


    def test_duplicate_json_key_is_rejected_instead_of_silently_taking_the_last(self) -> None:
        """A fixture that states a control twice must not be read as either value.

        ``json.loads`` keeps the last occurrence, so a document saying
        ``disabled`` and then ``enabled`` rendered as enabled, rated the
        repository strong and reported 100% coverage — the stronger reading of a
        document that contradicts itself. The loader already refuses duplicate
        repository names; a duplicate key carrying a control state is the same
        problem one level down.
        """

        raw = (
            '{"organization": "acme",'
            ' "generated_at": "2026-05-18T12:00:00+00:00",'
            ' "repositories": [{"name": "payments-api", "controls": {'
            ' "branch_protection": "disabled",'
            ' "branch_protection": "enabled",'
            ' "secret_scanning": "enabled",'
            ' "code_scanning": "enabled",'
            ' "dependabot_alerts": "enabled"}}]}'
        )

        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "duplicate.json"
            fixture.write_text(raw, encoding="utf-8")

            with self.assertRaises(FixtureLoadError) as caught:
                load_snapshot_fixture(fixture)

        self.assertIn("branch_protection", str(caught.exception))

    def test_deeply_nested_fixture_fails_as_a_load_error_not_a_recursion_error(self) -> None:
        """Nesting past the interpreter limit must use the loader's own error.

        ``json.loads`` raises ``RecursionError``, which is not a
        ``JSONDecodeError``, so it escaped the handler and reached the CLI as a
        raw traceback with exit 1. Every other malformed fixture reports
        ``Error:`` and exits 2, so a caller branching on exit codes saw a
        different answer for one shape of bad input.
        """

        raw = "[" * 20_000 + "]" * 20_000

        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "deep.json"
            fixture.write_text(raw, encoding="utf-8")

            with self.assertRaises(FixtureLoadError) as caught:
                load_snapshot_fixture(fixture)

        self.assertIn("nested too deeply", str(caught.exception))

    def test_fixture_that_is_not_utf8_text_fails_as_a_load_error(self) -> None:
        """Bytes that are not UTF-8 must use the loader's own error.

        ``read_text(encoding="utf-8")`` raises ``UnicodeDecodeError``, which
        subclasses ``ValueError`` rather than ``OSError``, so the existing
        handler missed it and the CLI exited 1 with a raw traceback.
        """

        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "binary.json"
            fixture.write_bytes(bytes([0xFF, 0xFE, 0x00, 0x01]) + b"not utf-8")

            with self.assertRaises(FixtureLoadError) as caught:
                load_snapshot_fixture(fixture)

        self.assertIn("not valid UTF-8", str(caught.exception))




def _valid_fixture_payload() -> dict[str, Any]:
    return {
        "organization": "example-org",
        "generated_at": "2026-05-18T12:00:00+00:00",
        "repositories": [
            {
                "name": "api",
                "controls": {
                    "branch_protection": "enabled",
                    "secret_scanning": "enabled",
                    "code_scanning": "unknown",
                    "dependabot_alerts": "disabled",
                },
            }
        ],
    }


if __name__ == "__main__":
    unittest.main()
