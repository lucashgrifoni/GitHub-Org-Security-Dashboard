# Especificacao Tecnica - GitHub Org Security Dashboard

## Objetivo

Criar uma base Python 3.12 para um dashboard read-only de postura de seguranca de repositorios GitHub em nivel organizacional, com saida inicial em Markdown.

## Requisitos

- Fornecer uma CLI minima via Typer.
- Representar organizacao, repositorios e controles de seguranca com modelos tipados.
- Gerar relatorio Markdown e JSON a partir de um snapshot em memoria.
- Carregar snapshots simulados a partir de fixtures JSON locais, com validacao de contrato.
- Derivar sumario de postura e classificacao de risco por repositorio de forma deterministica.
- Manter o collector offline/stub por padrao.
- Nao acessar GitHub real, nao exigir token e nao coletar dados reais nesta fase.
- Incluir testes unitarios para o comportamento seguro padrao.

## Controles Modelados

Cada repositorio expoe:

- default branch, quando informado pela fixture;
- visibility, quando informada pela fixture, restrita a `public`, `private` ou `internal`;
- branch protection;
- secret scanning;
- code scanning;
- Dependabot alerts.

No modo stub, metadados e controles sem coleta real aparecem como `not_collected`, pois nao ha integracao real. No modo fixture, metadados sao lidos de um arquivo JSON local quando presentes, e os controles devem usar estados permitidos pelo modelo: `enabled`, `disabled`, `unknown` ou `not_collected`.

## Saida e Agregacao

- O relatorio pode ser renderizado em Markdown (padrao) ou JSON deterministico (`--format json`).
- O sumario de postura conta os estados de cada controle e calcula a cobertura de `enabled`, excluindo `not_collected` do denominador. Quando nenhum repositorio reportou estado conhecido para um controle, o denominador e zero e a cobertura aparece como `not_assessed`, nao como `0%`: um controle que ninguem coletou nao e um controle desligado.
- A classificacao de risco por repositorio e deterministica: `disabled`=2, `unknown`=1, `enabled`=0, `not_collected` excluido; faixas 0=`strong`, 1-2=`moderate`, >=3=`weak`, nenhum avaliado=`not_assessed`.
- O JSON preserva `coverage_percent` numerico e acrescenta `assessed` e `coverage_status` por controle. Denominador zero tem `coverage_status=not_assessed`.
- O risco inclui `not_collected_controls` e `assessment_status` (`complete`, `partial`, `not_assessed`). `unknown` participa da avaliacao; `complete` descreve coleta, sem afirmar que todos os estados sao conhecidos ou habilitados.
- A CLI produz os mesmos bytes em stdout e arquivo para a mesma fixture, com UTF-8, LF e uma unica quebra de linha final. O stub usa a hora corrente no snapshot.

## Fixture JSON Local

A fixture e uma fonte sintetica para simular dados de repositorios e controles sem usar tokens, rede ou GitHub API real. O loader exige:

- `organization`: nome nao vazio da organizacao simulada;
- `generated_at`: datetime ISO com timezone;
- `repositories`: lista de repositorios com `name` unico e um objeto `controls` com os controles modelados;
- `default_branch`: branch padrao opcional por repositorio;
- `visibility`: visibilidade opcional por repositorio;
- `warnings`: lista opcional de avisos nao vazios.

O loader tambem recusa um objeto JSON que declare a mesma chave duas vezes. `json.loads` manteria a ultima ocorrencia, entao uma fixture que diz `disabled` e depois `enabled` seria lida como habilitada: a leitura mais forte de um documento que se contradiz. Uma fixture aninhada alem do limite de recursao do interpretador tambem e recusada como erro de carregamento, e nao como traceback.

Controles inline sao aceitos quando nao ha objeto `controls`. A mistura das duas representacoes
e recusada, pois poderia descartar silenciosamente um estado informado. `NaN`, `Infinity`,
inteiros alem do limite de conversao do Python e texto com surrogates isolados sao recusados.

Valores textuais renderizados no Markdown sao achatados em uma linha. Sem isso, uma quebra de linha em `organization`, `name`, `default_branch` ou num aviso injeta titulos e parte uma linha de tabela, empurrando repositorios para fora do relatorio renderizado. O dado continua visivel; apenas deixa de forjar estrutura.

O `collection_mode` do snapshot carregado por fixture e sempre `fixture_json`, independentemente do conteudo do arquivo, para evitar relatorios que aparentem ter vindo de coleta real.

## Decisoes de Seguranca

- O caminho padrao e offline e deterministico.
- A CLI nao possui parametro de token.
- Qualquer tentativa programatica de habilitar rede no collector falha explicitamente.
- Relatorios sao derivados apenas de entradas fornecidas localmente pelo usuario.
- Erros de leitura, parsing e validacao de fixtures reportam `Error: ...` e saem com codigo 2.
- Erros de gravacao reportam `Error: ...` e saem com codigo 2. A saida nao pode sobrescrever a fixture de entrada, inclusive por hard link ou caminho resolvido.
- A saida para stdout usa UTF-8 mesmo quando o console nao consegue codificar o conteudo, para que nomes de repositorio nunca sejam mutilados em silencio.
- O modo fixture adiciona aviso explicito de que nenhuma chamada GitHub foi feita.

## Criterios de Aceite

- `python -m coverage run -m pytest` passa (com `pythonpath=src` via configuracao).
- `python -m ruff check .` e `python -m mypy` (estrito) passam.
- `python -m build` gera sdist e wheel; o wheel inclui `py.typed`.
- Nenhum teste ou comando padrao chama GitHub, internet ou API externa.
- `ghorgsec report --fixture examples/org-security-snapshot.json` gera Markdown a partir de dados sinteticos locais.
- `ghorgsec report --fixture examples/org-security-snapshot.json --format json` gera JSON valido e deterministico.
- O README documenta claramente as limitacoes e o modo seguro atual.
- A CI valida Ubuntu/Python 3.12 e 3.13 e Windows/Python 3.12, alem de build, auditoria de dependencias e uso do wheel instalado sem rede.
- O check protegido `Lint, type-check, test` so passa quando todas as combinacoes e o job de pacote passam.

## Evolucao Planejada

- Adicionar cliente GitHub read-only isolado por interface.
- Exigir token apenas quando uma coleta real for implementada e explicitamente solicitada.
- Cobrir rate limit, paginacao, erros de autorizacao e redacao de dados sensiveis.
- Expandir relatorios para severidade, evidencias e gaps por controle.
