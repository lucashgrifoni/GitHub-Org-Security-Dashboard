# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- A fixture nested past the interpreter's recursion limit now fails as a fixture load error
  rather than a `RecursionError` traceback with exit 1. It was the one malformed input out of
  ten that did not report `Error:` and exit 2.
- Fixture loading now rejects a JSON object that states the same key twice instead of silently
  keeping the last occurrence. A fixture saying a control was `disabled` and then `enabled` was
  read as enabled, rated the repository `strong` and reported 100% coverage — the stronger
  reading of a document that contradicts itself. Duplicate repository names were already
  rejected; this applies the same rule to the keys inside them.
- Fixed the CLI crashing when the report contains characters the console cannot encode.
  `--output` pins `encoding="utf-8"`, but printing inherited the console code page, so a CJK
  branch name, a non-Latin warning or a non-ASCII repository name wrote to a file fine while
  printing raised `UnicodeEncodeError` and exited 1 with a raw traceback, bypassing the CLI's
  own `Error:`/exit-2 convention. stdout now receives UTF-8 bytes when the stream cannot encode
  them, so the report is never silently mangled to fit a terminal.
- Posture summary now reports `not_assessed` instead of `0%` for a control no repository
  reported on. A control nobody collected and a control disabled everywhere rendered
  identically, which is the misleading 0% that excluding `not_collected` from the denominator
  exists to prevent, and it contradicted the risk table, which already answers
  `not_assessed` for the same snapshot. Markdown only; the JSON contract is unchanged.
- Pointed the `[project.urls]` links at the renamed repository
  (`GitHub-Org-Security-Dashboard`). The distribution name stays `ghorgsec`; only the
  repository was renamed, and these URLs ship in the wheel metadata.
- Bumped `actions/checkout` to v7.0.1 and `actions/setup-python` to v7.0.0, updating each
  SHA pin together with the comment naming its version.
- Fixed Markdown report rendering so a fixture value carrying line breaks can no longer forge
  document structure. `_escape_cell` and `_escape_inline` guarded only their own delimiter, and
  warnings were rendered with no escaping at all, so a crafted `organization`, repository `name`,
  `default_branch` or warning could inject Markdown headings and split a table row — pushing other
  repositories out of the rendered posture table. Values are now folded onto a single line before
  rendering; the data is still shown, it just cannot forge structure. The JSON output was never
  affected. Regression test included.
- Added `.gitattributes` normalizing all text to LF, so line endings no longer depend on each
  contributor's `core.autocrlf` setting.
- Corrected the `[project.urls]` Homepage, Repository, and Changelog links, which pointed at a
  non-existent `lucasgrifoni` account instead of `lucashgrifoni`. These ship in the wheel metadata.
- Raised the `[dev]` extra pytest constraint to `>=9.0.3,<10.0`. The previous `<9.0` upper bound
  resolved to pytest 8.4.2, which is affected by PYSEC-2026-1845 (UNIX `/tmp/pytest-of-{user}`
  directory handling; local DoS or possible privilege escalation) and made the 9.0.3 fix
  uninstallable from the declared range. Test-only dependency; runtime chain was unaffected.
- Added deterministic per-repository risk rating (`risk.py`) with a documented rubric and a `Repository Risk` report section.
- Added posture summary (`summary.py`) with per-control state counts and `not_collected`-excluded coverage.
- Added deterministic JSON output (`serialize.py`) via `report --format json`.
- Constrained repository `visibility` to an allowlist (`public`, `private`, `internal`) validated at fixture load.
- Added dev tooling: `[dev]` extra plus ruff, mypy (strict), pytest, and coverage configuration.
- Added hardened CI workflow (SHA-pinned actions, least-privilege permissions) and Dependabot config.
- Added `py.typed` marker and richer package metadata (license expression, classifiers, URLs, keywords).
- Expanded test suite to cover the CLI, negative/edge cases, summary, risk, and serialization.
- Rendered fixture repository `default_branch` and `visibility` in Markdown reports.
- Added local JSON fixture ingestion for simulated repository security controls.
- Added a synthetic example fixture and tests for fixture parsing and report rendering.
- Added technical specification, offline collector skeleton, Markdown report,
  CLI entry point, and unit tests.
- Added baseline security and contribution documentation.
