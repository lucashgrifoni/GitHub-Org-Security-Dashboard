# Higiene de segredos na CI

O workflow [secrets-hygiene.yml](../.github/workflows/secrets-hygiene.yml) executa
Gitleaks 8.30.1 no historico Git e entrega o relatorio redigido ao secguard 0.4.0.
O job `Secrets hygiene gate` falha com achados ativos a partir de high, falha do
scanner, erro de processamento ou ausencia de decisao valida. Um resultado BLOCK
nao e convertido em sucesso.

A observacao do piloto foi revista antes da promocao: a execucao do PR26 em
2026-10-16 registrou PASS, zero achados ativos e zero dispensas. Isso descreve
aquela execucao e seu historico disponivel, sem comprovar ausencia universal de
segredos ou substituir resposta a um eventual incidente.

## Fontes e retencao

O scanner tem versao e checksum fixados; o action usa um commit completo. A
configuracao estende as regras padrao do Gitleaks e desativa exclusoes locais e
comentarios de allow. A coleta termina antes da avaliacao. Exports normalizados
sao retidos mesmo quando o gate falha; dados brutos ficam temporarios no runner.

Os testes controlados constroem um exemplo ficticio durante o job para verificar
BLOCK, PASS, erro operacional e erro de processamento. Esses valores nao sao
credenciais de autenticacao. Testar o exit esperado do avaliador e diferente de
afirmar que o historico real esta livre de qualquer segredo.

## Protecao de merge

O check `Secrets hygiene gate` deve ser obrigatorio em main, junto de
`Lint, type-check, test` e `CodeQL analyze`, com atualizacao obrigatoria da branch
e protecao tambem para administradores. A configuracao efetiva fica no GitHub;
o YAML sozinho nao comprova que a protecao de branch esta ativa.

Qualquer excecao a um finding exige classificacao, justificativa, owner e validade
antes de uma alteracao revisada da politica. Nao ha dispensas configuradas nesta
entrega. Erros operacionais e ausencia de relatorio nao admitem conversao em PASS.
Uma correcao nao deve esconder o alerta nem enfraquecer o scanner para obter verde.

Este controle verifica o codigo-fonte do projeto. A CLI continua produzindo
relatorios de postura e nao passa a coletar conteudo de segredos dos alvos.

## Recuperacao

Preserve os relatorios e investigue a causa de uma falha. Nao substitua a evidencia
por uma execucao antiga. Uma reversao exige nova alteracao revisada e deve manter
os demais checks obrigatorios e a trilha de decisao.

Referencias: [Secrets Hygiene Kit](https://github.com/lucashgrifoni/secrets-hygiene-kit),
[Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) e
[uso seguro de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use).
