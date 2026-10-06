# Piloto de higiene de segredos

A CI deste repositório executa Gitleaks 8.30.1 no histórico Git e entrega o
relatório redigido ao secguard 0.4.0. O piloto observa a decisão em `high`;
achados aparecem nos relatórios e no resumo da execução. Nesta fase, um BLOCK
por finding é informativo. Falha do scanner, erro de processamento e ausência
de decisão válida fazem o job falhar.

O workflow fica em [secrets-hygiene.yml](../.github/workflows/secrets-hygiene.yml).
O scanner tem versão e checksum fixados; o action usa um commit completo.
A configuração estende as regras padrão do Gitleaks e desativa exclusões locais
e comentários de allow. A coleta termina antes de o relatório ser avaliado.

A execução também cria um exemplo fictício local para verificar BLOCK, PASS,
erro operacional do scanner e erro de processamento do secguard. Os valores
fictícios são construídos durante o job e nunca usados para autenticação.
Somente os exports normalizados são anexados; o relatório bruto do scanner
permanece temporário.

## Revisão do piloto

Abra a execução **Secrets hygiene pilot** e confira:

1. O scanner terminou sem erro e gerou um relatório desta execução.
2. O resumo identifica o modo de relatório e a decisão PASS ou BLOCK.
3. O teste controlado registrou exits 1, 0 e 2 para os casos esperados.
4. Os artefatos normalizados permitem revisar achados e orientação de resposta.

A ausência de achados descreve a execução desse scanner e o histórico disponível.
Ela não comprova ausência universal de segredos. Antes de tornar a decisão um
bloqueio obrigatório de merge, revise os resultados e eventuais exceções com
validade. O piloto é um check adicional; as proteções atuais de main continuam
exigindo os checks de qualidade e CodeQL.

A CLI ghorgsec mantém seu contrato de processar fixtures locais. Este piloto
pertence à CI do código-fonte do projeto; nenhuma coleta de organização foi
adicionada ao produto.

## Recuperação

Se a integração precisar ser retirada, reverta a PR do piloto. Não use um
relatório antigo para substituir uma execução que falhou e não transforme ERROR
ou NO-REPORTS em PASS. A release imutável 0.4.0 do Kit permanece disponível.

Referências: [Secrets Hygiene Kit](https://github.com/lucashgrifoni/secrets-hygiene-kit),
[Gitleaks 8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) e
[uso seguro de GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use).
