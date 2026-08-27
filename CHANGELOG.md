# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

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
