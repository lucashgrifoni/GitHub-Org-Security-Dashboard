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
python scripts/audit_environment.py
```

O extra `[dev]` instala as ferramentas desses comandos. A auditoria inclui as dependencias
runtime e de desenvolvimento. O script fixa as versoes instaladas antes de chamar pip-audit,
sem repetir a resolucao de dependencias. Um pacote que nao puder ser auditado faz o check
falhar; um resultado parcial nao e aceito como sucesso. O pacote local e revisado como codigo, pois nao vem
de um indice publicado. O job de pacote tambem instala o wheel em um ambiente novo e executa
`scripts/smoke_installed.py` com uma fixture sintetica.

## Contribution Rules

- Submit changes through a pull request against `main`. The maintainer reviews
  contributions, and the required CI and CodeQL checks must pass before merge.
- This project does not require a DCO sign-off. Keep commit authorship accurate.
- Do not add real GitHub API calls as default behavior.
- Keep collectors mockable and safe to run without network access.
- Do not log tokens, private repository names, organization identifiers, or
  sensitive audit details.
- Add tests for every collected control and report rendering change.
