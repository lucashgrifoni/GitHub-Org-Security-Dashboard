# Especificacao Tecnica - GitHub Org Security Dashboard

## Objetivo

Fornecer uma CLI Python 3.12 read-only para postura de repositorios GitHub de organizacao
ou conta pessoal autenticada, com saida Markdown e JSON e coleta offline por padrao.

## Requisitos

- Fornecer uma CLI minima via Typer.
- Representar organizacao, repositorios e controles de seguranca com modelos tipados.
- Gerar relatorio Markdown e JSON a partir de um snapshot em memoria.
- Carregar snapshots simulados a partir de fixtures JSON locais, com validacao de contrato.
- Derivar sumario de postura e classificacao de risco por repositorio de forma deterministica.
- Separar sugestoes de revisao de configuracao de lacunas de evidencia no relatorio.
- Comparar dois snapshots JSON locais do mesmo owner sem chamadas de rede.
- Manter o collector offline/stub por padrao.
- Acessar GitHub real somente com `--live`, token explicito por ambiente e alvo autorizado.
- Exigir token somente no modo live; preservar o collector stub e fixtures sem rede.
- Isolar transporte GET por interface e tratar paginacao, limites, erros e gaps de acesso.
- Incluir testes unitarios para o comportamento seguro padrao.

## Controles Modelados

Cada repositorio expoe:

- default branch, quando informada pela fonte;
- visibility, quando informada pela fonte, restrita a `public`, `private` ou `internal`;
- branch protection;
- secret scanning;
- code scanning;
- Dependabot alerts.

No modo stub, metadados e controles sem coleta real aparecem como `not_collected`, pois nao ha integracao real. No modo fixture, metadados sao lidos de um arquivo JSON local quando presentes, e os controles devem usar estados permitidos pelo modelo: `enabled`, `disabled`, `unknown` ou `not_collected`.

No modo live, o [contrato de coleta](LIVE_COLLECTION.md) define endpoint, permissao,
limite, estado e erro por controle. A lista contem apenas repositorios visiveis ao token.
`github_live_user` usa a conta autenticada; `github_live_org` usa uma organizacao.
O campo JSON `organization` continua contendo o owner, preservando o schema existente.

## Saida e Agregacao

- O relatorio pode ser renderizado em Markdown (padrao) ou JSON deterministico (`--format json`).
- O sumario de postura conta os estados de cada controle e calcula a cobertura de `enabled`, excluindo `not_collected` do denominador. Quando nenhum repositorio reportou estado conhecido para um controle, o denominador e zero e a cobertura aparece como `not_assessed`, nao como `0%`: um controle que ninguem coletou nao e um controle desligado.
- A classificacao de risco por repositorio e deterministica: `disabled`=2, `unknown`=1, `enabled`=0, `not_collected` excluido; faixas 0=`strong`, 1-2=`moderate`, >=3=`weak`, nenhum avaliado=`not_assessed`.
- O JSON preserva `coverage_percent` numerico e acrescenta `assessed` e `coverage_status` por controle. Denominador zero tem `coverage_status=not_assessed`.
- O risco inclui `not_collected_controls` e `assessment_status` (`complete`, `partial`, `not_assessed`). `unknown` participa da avaliacao; `complete` descreve coleta, sem afirmar que todos os estados sao conhecidos ou habilitados.
- A CLI produz os mesmos bytes em stdout e arquivo para a mesma fixture, com UTF-8, LF e uma unica quebra de linha final. O stub usa a hora corrente no snapshot.
- O JSON acrescenta `next_steps` com repository, control, state e action, sem mudar scores.
  disabled gera review_configuration; unknown gera verify_access; not_collected gera
  collect_evidence; enabled nao gera item. Markdown separa esses tres grupos.

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

HTML e sintaxe Markdown em nomes, metadados e avisos sao renderizados como texto
literal em CommonMark com tabelas. Code spans usam delimitadores maiores que os
backticks da entrada. O JSON mantem os valores originais. Extensoes de visualizadores
ficam fora desse contrato de apresentacao.

## Comparacao Local

`compare --baseline arquivo.json --current arquivo.json` usa o mesmo loader estrito
do relatorio. Aceita `--format md|json` e `--output`, e nunca le credenciais.
O JSON de comparacao tem schema_version=1 e collection_mode=local_snapshot_comparison.
Ele inclui owner, baseline_at, current_at, warnings, summary, added_repositories,
missing_repositories e changes. Cada change tem repository, control, before, after
e classification. Summary conta controles alterados e inalterados em repositorios
presentes nos dois arquivos. Metadados de score e sumario da entrada sao ignorados.

Owners e nomes sao comparados exatamente, sem resolver renomeacoes. O current precisa
ter data igual ou posterior ao baseline; datas iguais geram aviso. As classes sao:
enabled_observed (disabled para enabled), disabled_observed (enabled para disabled),
evidence_gained (lacuna para conhecido), evidence_lost (conhecido para lacuna),
gap_changed (unknown versus not_collected) e scope_changed (outra default branch).
scope_changed tem precedencia para branch protection, inclusive quando o estado nao
muda. Estados iguais em escopo igual contam como inalterados.

Presenca em apenas um snapshot nao prova criacao ou exclusao. Avisos das duas fontes
continuam no resultado, identificados como baseline/current. Arquivos locais nao
comprovam proveniencia, remediacao ou enforcement. O comando preserva as duas entradas
contra sobrescrita por caminho resolvido ou hard link e usa o contrato Error:/exit 2.

## Decisoes de Seguranca

- A CLI e offline por padrao. A mesma fixture produz a mesma saida; o stub registra a hora corrente.
- A CLI nao possui parametro de token.
- O collector stub antigo continua recusando `allow_network=True`; o collector live e separado.
- Cliente live: GET HTTPS em api.github.com, sem redirects, sem token nos erros/relatorios.
- A autenticacao pessoal confere o owner; controle inacessivel permanece `unknown`.
- Limites e falhas de inventario impedem um relatorio live silenciosamente truncado.
- Erros de leitura, parsing e validacao de fixtures reportam `Error: ...` e saem com codigo 2.
- Erros de gravacao reportam `Error: ...` e saem com codigo 2. A saida nao pode sobrescrever a fixture de entrada, inclusive por hard link ou caminho resolvido.
- A saida para stdout usa UTF-8 mesmo quando o console nao consegue codificar o conteudo, para que nomes de repositorio nunca sejam mutilados em silencio.
- O modo fixture adiciona aviso explicito de que nenhuma chamada GitHub foi feita.

## Criterios de Aceite

- `python -m coverage run -m pytest` passa (com `pythonpath=src` via configuracao).
- `python -m ruff check .` e `python -m mypy` (estrito) passam.
- `python -m build` gera sdist e wheel; o wheel inclui `py.typed`.
- A CLI sem `--live` e os testes automatizados nao chamam APIs externas. Clone, instalacao,
  build, auditoria de dependencias e uso `--live` podem acessar servicos externos.
- `ghorgsec report --fixture examples/org-security-snapshot.json` gera Markdown a partir de dados sinteticos locais.
- `ghorgsec report --fixture examples/org-security-snapshot.json --format json` gera JSON valido e deterministico.
- O README documenta claramente as limitacoes e o modo seguro atual.
- O modo live pessoal e exercitado em conta autorizada e comparado com leituras independentes.
- Testes de contrato cobrem organizacao, conta, filtros, paginacao, origin/redirect,
  autenticacao, redacao, rate limits, limites de recursos e gaps de controles.
- A CI valida Ubuntu/Python 3.12 e 3.13 e Windows/Python 3.12, alem de build, auditoria de dependencias e uso do wheel instalado sem rede.
- O check protegido `Lint, type-check, test` so passa quando todas as combinacoes e o job de pacote passam.

## Evolucao Planejada

- Validar E2E em uma organizacao real autorizada; o fluxo tem testes sinteticos atualmente.
- Ampliar evidencia de code scanning avancado sem confundir historico de analises com
  configuracao atual ou enforcement.
- Qualquer ampliacao de formatos ou severidade exige necessidade demonstrada e criterios
  de aceite; os quatro controles, estados e rubricagem atuais permanecem o limite desta fase.
