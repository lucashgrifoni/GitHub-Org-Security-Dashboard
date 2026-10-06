# Contrato de coleta real

A partir de 0.3.0, `report --live` consulta `api.github.com` por HTTPS usando somente GET.
O modo offline continua padrao. Nao ha parametro de token, cache, telemetria ou alteracao
de configuracao de repositorios. A coleta pessoal foi exercitada em conta propria;
o fluxo de organizacao foi validado com respostas simuladas e ainda requer E2E em
organizacao autorizada.

## Alvo e credencial

`--user` deve coincidir com o login de `GET /user`. A lista vem de `GET /user/repos`,
com `affiliation=owner` e `visibility=all`. `--org` verifica o login em `GET /orgs/{org}`
e lista `GET /orgs/{org}/repos?type=all`. Nomes e proprietarios sao validados antes de
consultar os controles. `--repo` e um filtro sobre esse inventario; um nome ausente
gera erro, em vez de um relatorio vazio que pareca completo.

O cliente usa `GH_TOKEN` nao vazio, seguido por `GITHUB_TOKEN`, somente com `--live`.
Para fine-grained tokens, a selecao de repositorios e as permissoes read abaixo
delimitam a coleta. O collector nao aumenta permissoes nem cria credenciais.

| Leitura | Permissao de repositorio fine-grained | Dado utilizado |
| --- | --- | --- |
| Inventario e metadados de repositorio | Metadata: read | nome, owner, default branch, visibility |
| Branch padrao | Contents: read | protected |
| Default setup e vulnerability-alerts | Administration: read | state ou status HTTP |
| security_and_analysis em metadados | depende de papel admin/owner/security manager | secret_scanning.status |

O papel do usuario, acesso do token e disponibilidade do recurso sao condicoes diferentes.
Um token pode listar um repositorio e ainda nao conseguir observar seus controles.
O inventario nao comprova acesso a todos os repositorios da conta ou organizacao.

## Estados e fontes

| Controle | Fonte consultada | Interpretacao |
| --- | --- | --- |
| branch_protection | GET /repos/{owner}/{repo}/branches/{default_branch} | protected=true: enabled; false: disabled; ausencia/403/404: unknown; sem default branch: not_collected |
| secret_scanning | GET /repos/{owner}/{repo}, security_and_analysis.secret_scanning.status | enabled/disabled apenas quando explicitos; omitido ou inacessivel: unknown |
| code_scanning | GET /repos/{owner}/{repo}/code-scanning/default-setup | configured: enabled; not-configured/ausente/403/404: unknown |
| dependabot_alerts | GET /repos/{owner}/{repo}/vulnerability-alerts | 204: enabled; 403/404 ou resposta sem confirmacao: unknown |

Default setup nao configurado nao exclui advanced setup ou ferramentas de terceiros.
Esta versao nao inspeciona workflows nem usa analises historicas para afirmar configuracao
atual. Da mesma forma, um `404` em vulnerability-alerts pode representar recurso desabilitado
ou acesso insuficiente. Ele permanece `unknown`, mesmo quando a lista de repositorios funciona.
`advanced_security` e `dependabot_security_updates` nao substituem esses quatro controles.

`enabled` descreve a configuracao observada por essas fontes. Nao comprova enforcement,
execucao bem-sucedida de analises, ausencia de findings ou seguranca do repositorio.
Branch protection cobre somente a default branch. Gaps aparecem em `warnings` por
repositorio e controle. As consultas sao sequenciais e o snapshot nao e atomico.

## Limites e falhas

- API REST fixada em `2026-03-10`; origem unica `https://api.github.com`.
- Redirecionamentos sao recusados para preservar o destino da credencial. Em repositorio
  transferido ou renomeado, atualize o alvo e execute novamente.
- Paginacao usa `Link: rel="next"`, mantendo origem, recurso e filtros. Ciclos,
  links malformados, destinos inesperados ou limites excedidos encerram a coleta.
- Limites: 1000 repositorios, 100 paginas, 4100 requisicoes e 8 MiB por resposta.
- Timeout de operacoes de rede de ate 10 segundos, prazo de leitura por resposta e
  orcamento de 300 segundos verificado entre requisicoes. Resolucao DNS e operacoes
  bloqueantes usam o comportamento do sistema; esse orcamento nao e um SLA de duracao.
- Sem retries automaticos. Rate limit (429 ou 403 com indicador de limite) encerra a
  coleta; respeite os headers de espera do GitHub antes de nova tentativa.
- 401, falha de transporte, resposta inesperada ou JSON/metadados invalidos encerram
  a coleta. 403/404 por controle geram gaps; 403/404 do inventario encerram a coleta.
- Falhas de coleta retornam codigo 2 e preservam um arquivo de saida existente.
  Nenhum relatorio parcial e apresentado como coleta concluida.

Erros nao incluem token, body remoto ou headers. O cliente reduz respostas a metadados
e estados; nao consulta conteudo de secrets ou alertas de vulnerabilidade. A resposta
de GET /user e usada apenas para conferir o login; os demais dados de perfil nao sao
incluidos no relatorio.
TLS usa o trust store do sistema. Um token com permissoes maiores continua capaz de outros
atos fora desta ferramenta; prefira uma credencial com os acessos de leitura necessarios.

## Compatibilidade dos relatorios

Os modos sao `github_live_user` e `github_live_org`. O campo JSON historico `organization`
preserva seu nome e contem o owner solicitado, inclusive no modo pessoal. Consulte
`collection_mode` para distinguir conta e organizacao. No Markdown, conta pessoal
aparece como `Personal account`. Os modos `offline_stub` e `fixture_json` permanecem.

Estados, scores, schema dos controles e formato dos relatorios continuam compativeis.
Fixtures carregadas sempre recebem `fixture_json`; carregar um JSON de coleta nao
constitui uma nova observacao live. O collector antigo ainda recusa `allow_network=True`;
a API nova e `collect_live_snapshot(owner, client=GitHubClient(token), personal=...)`.

## Referencias

- [Inventario, metadados e vulnerability-alerts](https://docs.github.com/en/rest/repos/repos)
- [Branches e campo protected](https://docs.github.com/en/rest/branches/branches)
- [Default setup de code scanning](https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration)
- [Versoes da API](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [Paginacao, erros e rate limits](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api)
