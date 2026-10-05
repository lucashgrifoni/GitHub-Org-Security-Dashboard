# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Clarified alpha readiness for offline reports and the planned live-collection work.
- Corrected module usage prerequisites: setting `PYTHONPATH=src` does not install Typer.
- Limited the offline guarantee to CLI use and unit tests; installation, builds and
  dependency audits can use external services. Stub timestamps vary between calls.

## 0.2.0 - 2026-10-05

- Added collection completeness to repository risk: `assessment_status` and
  `not_collected_controls`, shown in Markdown and JSON without changing scores.
- Added `assessed` and `coverage_status` to JSON coverage so consumers can distinguish
  an uncollected control from a collected control with 0% enabled coverage.
- Refused mixed inline and nested control states instead of silently selecting one source.
- Rejected non-finite JSON constants and unpaired Unicode surrogates, and handled Python's
  integer digit limit through the fixture error contract. Invalid input is rejected before
  an existing output file is opened.
- Prevented `--output` from overwriting its input fixture, including hard-link aliases.
- Made stdout and file output byte-identical for a fixture: UTF-8, LF and one final newline.
- Added 21 regression cases for fixture and output integrity and collection completeness,
  including Windows newline translation through a UTF-8 stdout stream.
- Added build and dependency-audit tools to the documented development extra.
- Made dependency auditing strict: a package that cannot be audited blocks the gate.
  Added an offline regression using a simulated 404 response through pip-audit.
- Expanded CI to Ubuntu/Python 3.12 and 3.13 and Windows/Python 3.12. The protected check
  aggregates every quality lane and the build, installed-wheel and dependency-audit job.
- Updated both CodeQL steps to v4.38.2 with verified commit pins, granted the analysis job
  read access to workflow metadata and grouped future GitHub Actions dependency updates.
- Defined the maintainer as the code owner for source, workflows and release scripts.

- `--output` now writes LF on every platform. `Path.write_text` translates to the platform line
  ending by default, so the same fixture produced a CRLF file on Windows and an LF file on
  Linux, and a consumer hashing the report as evidence got a different digest per platform.
- Exported `RealCollectionDisabledError` from the package. `allow_network` is a keyword argument
  on an exported function, so the exception is reachable from the public API, but catching it
  meant importing from `ghorgsec.collector`, a module `__all__` does not advertise, while the
  package's other custom exception was exported.
- `--org` combined with `--fixture` is now refused, matching `--repo`. It was accepted and then
  discarded, so the report named the organization from the JSON while the caller had typed
  another one, with nothing saying the value had been dropped.
- A fixture file that is not valid UTF-8 text now reports `Error:` and exits 2 instead of a raw
  `UnicodeDecodeError` traceback. It subclasses `ValueError`, not `OSError`, so the existing
  read handler never saw it.
- An unwritable `--output` path now reports `Error:` and exits 2 instead of a raw traceback with
  exit 1. A directory, a missing parent directory or a read-only location all raised an
  uncaught `OSError`.
- Added a CodeQL workflow (`.github/workflows/codeql.yml`) running on push, pull request and
  weekly. Actions are SHA-pinned with the version named in a comment, `security-events: write`
  is scoped to the analyze job rather than the workflow, and there is no autobuild step because
  Python needs none.
- Documented the behaviour changes above in `README.md` and `docs/SPEC.md`: `not_assessed`
  coverage, duplicate-key and depth rejection, the uniform `Error:`/exit-2 contract, single-line
  flattening of rendered values, and UTF-8 stdout. The changelog recorded them; the docs a user
  actually reads did not.
- A fixture nested past the interpreter's recursion limit now fails as a fixture load error
  rather than a `RecursionError` traceback with exit 1. It was the one malformed input out of
  ten that did not report `Error:` and exit 2.
- Fixture loading now rejects a JSON object that states the same key twice instead of silently
  keeping the last occurrence. A fixture saying a control was `disabled` and then `enabled` was
  read as enabled, rated the repository `strong` and reported 100% coverage: the stronger
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
  `default_branch` or warning could inject Markdown headings and split a table row, pushing other
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
