# Contributing

## Development Setup

Use Python 3.12 or newer.

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy
python -m coverage run -m pytest
python -m coverage report
```

Antes de propor mudancas de empacotamento ou release, valide o build e as dependencias:

```bash
python -m build
python -m pip_audit
```

## Contribution Rules

- Do not add real GitHub API calls as default behavior.
- Keep collectors mockable and safe to run without network access.
- Do not log tokens, private repository names, organization identifiers, or
  sensitive audit details.
- Add tests for every collected control and report rendering change.

