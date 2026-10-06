# GitHub Org Security Dashboard

CLI read-only para consolidar controles de seguranca por repositorio GitHub, com saida
em Markdown ou JSON, sumario de postura e uma rubrica de risco documentada.

## Status

O codigo atual inclui coleta real opcional em `api.github.com`. Sem `--live`, a CLI continua
offline e usa nomes sinteticos ou fixtures locais, sem ler token. O modo live exige uma
credencial e consulta somente os repositorios visiveis a ela. O projeto permanece alpha.
As versoes anteriores a 0.3.0 oferecem apenas os modos offline.

### Uso e divulgacao

A alpha pode gerar relatorios locais e observar controles em uma conta pessoal autenticada
ou organizacao autorizada. O modo pessoal foi exercitado em uma conta propria, com comparacao
independente dos controles deste repositorio. O fluxo organizacional tem testes com respostas
simuladas; uma execucao em organizacao real ainda precisa ser validada.

A CI cobre Ubuntu/Python 3.12 e 3.13 e Windows/Python 3.12. Divulgue os limites de coleta:
o inventario depende do token; branch protection cobre a default branch; configuracoes
avancadas de code scanning podem ficar como `unknown`. O relatorio nao certifica seguranca,
ausencia de vulnerabilidades ou conformidade. Consulte o [contrato live](docs/LIVE_COLLECTION.md).

## Escopo atual

- CLI minima com Typer (`report`).
- Modelo tipado de organizacao, repositorio e controles de seguranca.
- Collector stub seguro, offline por padrao.
- Collector live opt-in, com inventario paginado e gaps por controle.
- Loader de fixture JSON local com validacao de contrato.
- `visibility` validada contra allowlist (`public`, `private`, `internal`).
- Sumario de postura: cobertura por controle, com `not_collected` excluido do denominador.
- Classificacao de risco deterministica por repositorio (rubrica documentada).
- Saida em Markdown ou JSON deterministico.
- Testes unitarios sem chamadas de rede; ruff, mypy estrito e cobertura configurados.

## Limites do produto

- Nenhuma alteracao de configuracao de repositorios pela coleta.
- Sem GitHub Enterprise Server, UI web, banco de dados, agendamento ou telemetria.
- Sem coleta de conteudo de secrets, alertas ou vulnerabilidades.
- Sem conclusao de cobertura integral da conta/organizacao ou qualidade de enforcement.

## Setup

A CI do código-fonte também executa um [piloto de higiene de segredos](docs/secrets-hygiene-pilot.md)
com Gitleaks e secguard. Ele começa em modo de relatório; falhas de execução
continuam fazendo o job falhar. A CLI ghorgsec mantém seu uso offline descrito acima.

Requer Python 3.12 ou mais recente. O projeto esta em fase alpha.

Clone o repositorio e entre na pasta antes de instalar:

```bash
git clone https://github.com/lucashgrifoni/GitHub-Org-Security-Dashboard.git
cd GitHub-Org-Security-Dashboard
python -m venv .venv
```

Ative o ambiente com `.venv\Scripts\Activate.ps1` no PowerShell ou `source .venv/bin/activate` no Linux.

```bash
python -m pip install -e .
```

Para desenvolvimento (ruff, mypy, pytest, coverage, build e pip-audit):

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

Depois da instalacao, a CLI tambem pode ser chamada como modulo Python:

```bash
python -m ghorgsec report --org example-org --repo api
```

Definir `PYTHONPATH=src` apenas torna o codigo fonte importavel; isso nao instala o Typer
nem suas dependencias. Use a instalacao acima antes de executar os exemplos.

### Opcoes do comando `report`

- `--org`: organizacao para o stub ou para `--live`; obrigatorio sem `--fixture`/`--user`.
- `--user`: conta pessoal autenticada, apenas com `--live`; nao combinavel com `--org`.
- `--live`: habilita leituras na API GitHub usando `GH_TOKEN` ou `GITHUB_TOKEN`.
- `--repo`: nome repetivel; no stub inclui nomes, no live filtra o inventario visivel ao token.
- `--fixture`: fixture JSON local a renderizar.
- `--format`: `md` (padrao) ou `json`.
- `--output` / `-o`: caminho de saida local opcional.

`--fixture` nao aceita `--org`, `--repo`, `--user` ou `--live`. Codigo de saida 0 indica
relatorio gerado, mesmo com controles `unknown`; nao funciona como gate de seguranca.
Erros de entrada, autenticacao, coleta ou arquivo retornam `Error:` e codigo 2.

### Coleta real

Use apenas alvos proprios ou autorizados. Disponibilize um token por `GH_TOKEN` ou
`GITHUB_TOKEN`; `GH_TOKEN` nao vazio tem precedencia. O token nao e parametro da CLI,
nao e salvo no relatorio e so e lido com `--live`.

Se o GitHub CLI ja estiver autenticado, no PowerShell:

```powershell
$env:GH_TOKEN = gh auth token --hostname github.com
ghorgsec report --live --user SEU_LOGIN --format json -o pessoal.json
Remove-Item Env:GH_TOKEN
```

Substitua `SEU_LOGIN` pelo login correspondente ao token. O modo pessoal usa o inventario
autenticado, incluindo os repositorios privados visiveis a credencial. Sem `--repo`,
coleta todos os repositorios desse inventario dentro dos limites documentados.

Para filtrar repositorios de uma organizacao autorizada:

```bash
ghorgsec report --live --org example-org --repo api --repo web -o postura.md
```

Uma credencial fine-grained pode usar permissoes de repositorio `Metadata: read`,
`Contents: read` e `Administration: read`, nos repositorios selecionados. Permissoes,
papel do usuario e disponibilidade dos recursos afetam os campos retornados. Quando
a API omite um controle ou recusa acesso, o relatorio preserva `unknown`.
O [contrato live](docs/LIVE_COLLECTION.md) relaciona cada endpoint, estado e limite.

Relatorios reais podem conter nomes de repositorios privados e sua postura. Escolha
um destino local adequado e revise o conteudo antes de compartilhar. Nao use esses
relatorios como fixtures publicas.

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

A fixture aceita ainda um array opcional `warnings` com avisos nao vazios, renderizados na secao `Warnings` junto ao aviso automatico de que nenhuma chamada ao GitHub foi feita. Avisos repetidos sao deduplicados.

O loader recusa uma fixture que declare a mesma chave JSON duas vezes: `json.loads` manteria a ultima ocorrencia, entao um documento que diz `disabled` e depois `enabled` seria lido como habilitado. Nomes de repositorio duplicados ja eram recusados; e a mesma regra um nivel abaixo. Uma fixture aninhada alem do limite de recursao tambem e recusada. Toda entrada malformada reporta `Error: ...` e sai com codigo 2.

Valores de texto sao achatados em uma linha ao renderizar Markdown, para que uma quebra de linha em um nome ou aviso nao injete titulos nem parta a tabela de postura.

Os controles tambem podem ser escritos diretamente no objeto do repositorio, sem `controls`.
A fixture deve escolher uma das duas representacoes por repositorio; misturar as duas e recusado,
mesmo quando os valores coincidem. O parser recusa `NaN`, `Infinity`, inteiros alem do limite do
Python e texto com surrogates Unicode isolados.

### Reprodutibilidade e arquivos de saida

Para a mesma fixture, stdout e `--output` produzem os mesmos bytes UTF-8, com LF e uma unica
quebra de linha final. O modo stub registra a hora da execucao, portanto varia entre chamadas.
`--output` recusa o caminho da fixture de entrada, inclusive aliases por caminho resolvido ou
hard link, para preservar a fonte do relatorio. Um arquivo de relatorio existente em outro
caminho e substituido; escolha um novo nome se precisar preservar a versao anterior.

## Sumario de postura

O relatorio inclui uma secao `Posture Summary` com contagem por estado de cada controle e a cobertura de "enabled". O denominador da cobertura exclui `not_collected`, para que um snapshot parcial nao reporte 0% enganoso.

Quando nenhum repositorio reportou estado conhecido para um controle, o denominador e zero e a cobertura aparece como `not_assessed`. Um controle que ninguem coletou e um controle desligado em todo lugar sao afirmacoes diferentes, e antes as duas renderizavam como `0%`.

No JSON, cada controle inclui `assessed` (denominador) e `coverage_status` (`assessed` ou
`not_assessed`). O campo numerico `coverage_percent` preserva o valor `0` quando o denominador
e zero para manter compatibilidade. Consumidores devem consultar `coverage_status` antes de
interpretar esse numero. `unknown` participa do denominador e da pontuacao; significa que a
entrada registrou um estado indeterminado, enquanto `not_collected` fica excluido.

## Risco por repositorio

Cada repositorio recebe uma classificacao deterministica a partir dos controles modelados:

- `disabled` -> 2 pontos; `unknown` -> 1 ponto; `enabled` -> 0; `not_collected` -> excluido.
- Faixas sobre os controles avaliados: score 0 -> `strong`; 1-2 -> `moderate`; >= 3 -> `weak`; nenhum avaliado -> `not_assessed`.

Essa rubrica resume os estados observados ou fornecidos. Ela nao mede explorabilidade,
impacto de vulnerabilidades ou qualidade dos controles.

Cada linha de risco mostra a quantidade de controles nao coletados e `assessment_status`:
`complete`, `partial` ou `not_assessed`. Uma classificacao `strong` em uma avaliacao `partial`
descreve apenas os controles informados. `complete` significa que nenhum controle ficou como
`not_collected`; controles `unknown` continuam explicitamente indeterminados.

## Qualidade

```bash
python -m ruff check .
python -m mypy
python -m coverage run -m pytest
python -m coverage report
python -m build
python scripts/audit_environment.py
```

CI (`.github/workflows/ci.yml`) executa lint, type-check estrito e testes com cobertura, com actions pinadas por commit SHA e permissoes minimas.

O uso da CLI sem `--live` e os testes automatizados sao offline. Clonar, instalar, preparar o build e auditar
dependencias podem acessar GitHub, o indice de pacotes e o servico de advisories. O modo
offline da CLI nao abrange essas etapas de preparacao e validacao.

A matriz inclui Ubuntu/Python 3.12, Ubuntu/Python 3.13 e Windows/Python 3.12. O job de pacote
audita dependencias, gera wheel e sdist e exercita o wheel instalado em um ambiente separado,
com a rede bloqueada durante o uso da CLI. O check obrigatorio `Lint, type-check, test` depende
de todos esses jobs. CodeQL usa o conjunto `security-extended` em um workflow separado.

### Verificar artefatos de release

O workflow de release gera wheel, sdist e um SBOM do runtime resolvido em Ubuntu/Python
3.12. As attestations vinculam os pacotes a esse build e ao SBOM. O SBOM descreve esse
ambiente; dependencias condicionais de outros sistemas podem ser diferentes. Uma
attestation valida confirma origem e integridade, sem certificar seguranca do codigo.

Depois de baixar o wheel de 0.3.0, verifique sua origem com o GitHub CLI:

```bash
gh attestation verify ghorgsec-0.3.0-py3-none-any.whl --repo lucashgrifoni/GitHub-Org-Security-Dashboard --signer-workflow lucashgrifoni/GitHub-Org-Security-Dashboard/.github/workflows/release.yml --source-ref refs/tags/v0.3.0 --deny-self-hosted-runners
```

O manifesto de evidencias da release informa a revisao do fonte e os digests. A verificacao
de publicacao tambem exige que a revisao corresponda ao build. Consulte a [documentacao
de attestations do GitHub](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Estrutura

- `docs/SPEC.md`: especificacao tecnica curta.
- `examples/org-security-snapshot.json`: fixture local sintetica.
- `src/ghorgsec/models.py`: dataclasses e enums do dominio.
- `src/ghorgsec/collector.py`: collector offline/stub.
- `src/ghorgsec/github_client.py`: transporte GET, origem e limites da API.
- `src/ghorgsec/live_collector.py`: inventario e estados de controles reais.
- `src/ghorgsec/fixture_loader.py`: loader de snapshot a partir de JSON local.
- `src/ghorgsec/summary.py`: agregacao de postura.
- `src/ghorgsec/risk.py`: classificacao de risco deterministica.
- `src/ghorgsec/report.py`: relatorio Markdown.
- `src/ghorgsec/serialize.py`: serializacao JSON deterministica.
- `src/ghorgsec/cli.py`: comandos Typer.
- `tests/`: testes unitarios.
- `scripts/smoke_installed.py`: validacao do wheel instalado fora da arvore de fontes.
- `scripts/audit_environment.py`: auditoria das versoes instaladas, incluindo dependencias transitivas.
