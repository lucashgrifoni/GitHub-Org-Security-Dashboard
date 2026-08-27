# GitHub Org Security Dashboard

Skeleton read-only para consolidar um painel de controles de seguranca por repositorio em uma organizacao GitHub, com saida em Markdown ou JSON. Inclui sumario de postura e classificacao de risco deterministica por repositorio.

## Status

Este projeto ainda nao coleta dados reais. O collector atual e offline, nao acessa GitHub, nao exige token e gera relatorios a partir de nomes sinteticos ou fixtures JSON locais. Todo numero exibido (cobertura, score de risco) deriva apenas de entradas locais fornecidas pelo usuario.

## Escopo atual

- CLI minima com Typer (`report`).
- Modelo tipado de organizacao, repositorio e controles de seguranca.
- Collector stub seguro, offline por padrao.
- Loader de fixture JSON local com validacao de contrato.
- `visibility` validada contra allowlist (`public`, `private`, `internal`).
- Sumario de postura: cobertura por controle, com `not_collected` excluido do denominador.
- Classificacao de risco deterministica por repositorio (rubrica documentada).
- Saida em Markdown ou JSON deterministico.
- Testes unitarios sem chamadas de rede; ruff, mypy estrito e cobertura configurados.

## Fora de escopo por enquanto

- Chamar APIs reais do GitHub.
- Ler tokens, secrets ou credenciais.
- Persistir dados coletados de organizacoes reais.
- Avaliar branch protection, code scanning, secret scanning ou Dependabot com dados reais.

## Setup

Requer Python 3.12.

```bash
python -m pip install -e .
```

Para desenvolvimento (ruff, mypy, pytest, coverage):

```bash
python -m pip install -e ".[dev]"
```

## Uso

Gerar um relatorio Markdown com dados sinteticos/stub:

```bash
ghorgsec report --org example-org --repo api --repo web
```

Gerar a partir de uma fixture JSON local:

```bash
ghorgsec report --fixture examples/org-security-snapshot.json
```

Saida JSON deterministica (snapshot + sumario + risco), util para automacao:

```bash
ghorgsec report --fixture examples/org-security-snapshot.json --format json
```

Escrever em arquivo:

```bash
ghorgsec report --fixture examples/org-security-snapshot.json -o report.md
```

Sem instalacao local, a CLI tambem roda com `PYTHONPATH=src`:

```bash
python -m ghorgsec report --org example-org --repo api
```

### Opcoes do comando `report`

- `--org`: nome da organizacao para o relatorio stub (obrigatorio sem `--fixture`).
- `--repo`: nome de repositorio a incluir no stub (repetivel; nao combinavel com `--fixture`).
- `--fixture`: fixture JSON local a renderizar.
- `--format`: `md` (padrao) ou `json`.
- `--output` / `-o`: caminho de saida local opcional.

## Fixture JSON

A fixture deve ser local, sintetica e sem dados sensiveis. O loader exige `organization`, `generated_at` com timezone e uma lista `repositories` com os controles modelados. `default_branch` e `visibility` sao metadados opcionais; quando presente, `visibility` deve ser `public`, `private` ou `internal`:

```json
{
  "organization": "example-org",
  "generated_at": "2026-05-18T12:00:00+00:00",
  "repositories": [
    {
      "name": "payments-api",
      "default_branch": "main",
      "visibility": "private",
      "controls": {
        "branch_protection": "enabled",
        "secret_scanning": "enabled",
        "code_scanning": "enabled",
        "dependabot_alerts": "enabled"
      }
    }
  ]
}
```

Estados de controle aceitos: `enabled`, `disabled`, `unknown` e `not_collected`.

## Sumario de postura

O relatorio inclui uma secao `Posture Summary` com contagem por estado de cada controle e a cobertura de "enabled". O denominador da cobertura exclui `not_collected`, para que um snapshot parcial nao reporte 0% enganoso.

## Risco por repositorio

Cada repositorio recebe uma classificacao deterministica a partir dos controles modelados:

- `disabled` -> 2 pontos; `unknown` -> 1 ponto; `enabled` -> 0; `not_collected` -> excluido.
- Faixas sobre os controles avaliados: score 0 -> `strong`; 1-2 -> `moderate`; >= 3 -> `weak`; nenhum avaliado -> `not_assessed`.

E uma ajuda de transparencia para o skeleton, nao uma avaliacao de risco real: nunca inventa dados.

## Qualidade

```bash
python -m ruff check .
python -m mypy
python -m coverage run -m pytest
python -m coverage report
```

CI (`.github/workflows/ci.yml`) executa lint, type-check estrito e testes com cobertura, com actions pinadas por commit SHA e permissoes minimas.

## Estrutura

- `docs/SPEC.md`: especificacao tecnica curta.
- `examples/org-security-snapshot.json`: fixture local sintetica.
- `src/ghorgsec/models.py`: dataclasses e enums do dominio.
- `src/ghorgsec/collector.py`: collector offline/stub.
- `src/ghorgsec/fixture_loader.py`: loader de snapshot a partir de JSON local.
- `src/ghorgsec/summary.py`: agregacao de postura.
- `src/ghorgsec/risk.py`: classificacao de risco deterministica.
- `src/ghorgsec/report.py`: relatorio Markdown.
- `src/ghorgsec/serialize.py`: serializacao JSON deterministica.
- `src/ghorgsec/cli.py`: comandos Typer.
- `tests/`: testes unitarios.
