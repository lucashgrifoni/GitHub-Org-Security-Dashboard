# Build e inventario de runtime

Os lockfiles fixam versoes e hashes das dependencias Python de desenvolvimento,
build e runtime. A resolucao universal inclui markers de plataforma; a instalacao
aplica os markers do Python/sistema usado. A CI exercita Ubuntu/Python 3.12 e3.13
e Windows/Python 3.12, incluindo uso do wheel instalado com rede bloqueada.

## Ambiente de desenvolvimento fixado

Em uma venv nova, a partir da raiz do repositorio:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m pytest
python -m ruff check .
python -m mypy
python scripts/audit_environment.py
```

O build usa o backend ja instalado pelo lockfile, sem resolver uma segunda arvore
de dependencias em um ambiente isolado temporario:

```bash
python -m build --no-isolation
```

A release fixa `SOURCE_DATE_EPOCH` ao timestamp do commit de origem. Isso controla
os inputs Python e timestamps; nao congela automaticamente o runner, sistema
operacional, versao do interpretador nem todo comportamento futuro do indice.
Uma alegacao de reproducao de bytes requer comparar os artefatos reconstruidos.

## Instalacao e SBOM

Em uma segunda venv limpa, instale `requirements-runtime.lock` com
`--require-hashes --report runtime-install.json`; depois instale o wheel com
`--no-deps --report application-install.json`. Ambos os reports devem descrever
o mesmo ambiente. Execute `pip check` e o smoke instalado antes de usar os reports
como evidencia de instalacao real. Reports de dry-run nao comprovam instalacao.

Na venv de desenvolvimento, informe o caminho concreto do wheel e dos reports:

```bash
python scripts/build_sbom.py --report runtime-install.json --report application-install.json --wheel dist/ghorgsec-0.4.0-py3-none-any.whl --output runtime.cdx.json
```

O gerador recusa hash de aplicacao divergente, componentes duplicados/yanked,
dependencias ativas ausentes/incompativeis e componentes fora do grafo de runtime.
Avalia markers PEP508 e extras para o ambiente registrado. Licencas usam expressoes
SPDX quando declaradas; metadados legados e classifiers conservam nomes/familias,
sem inventar um identificador SPDX ou parecer juridico. Ausencia de declaracao
aparece como `not-declared`.

O SBOM CycloneDX1.6 inclui a aplicacao, hashes SHA-256 dos arquivos instalados
conforme os reports, licencas declaradas e arestas de dependencia. Os hashes sao
dos arquivos de distribuicao, e nao de todos os arquivos extraidos no disco.
O escopo e aquele runtime/Python/sistema; um SBOM Linux nao inventaria componentes
condicionais de Windows. A CI retém um inventario por combinacao testada, com o
hash do wheel construido naquela combinacao. Esses inventarios de qualificacao
nao devem ser apresentados como se todos descrevessem o mesmo arquivo publicado.

A release gera e atesta o inventario de seu runtime Ubuntu/Python3.12 e a
proveniencia dos pacotes. Inventario, auditoria de vulnerabilidades, proveniencia
e comprovacao de uso sao evidencias distintas.

## Atualizar os lockfiles

Regere os dois arquivos com uv, revise as mudancas e execute a matriz novamente:

```bash
uv pip compile pyproject.toml --universal --python-version 3.12 --generate-hashes --no-annotate --no-build --default-index https://pypi.org/simple --output-file requirements-runtime.lock
uv pip compile pyproject.toml --universal --python-version 3.12 --extra dev --generate-hashes --no-annotate --no-build --default-index https://pypi.org/simple --output-file requirements-dev.lock
```

Referencias: [installation reports do pip](https://pip.pypa.io/en/stable/reference/installation-report/),
[locking com uv](https://docs.astral.sh/uv/pip/compile/) e
[CycloneDX](https://cyclonedx.org/specification/overview/).

## Suporte e recuperacao

Lucas Henrique Grifoni mantem o codigo, decide releases e recebe incidentes pelo
canal privado descrito em [SECURITY.md](../SECURITY.md). Nao ha servico hospedado,
on-call contratado ou alteracao de configuracao dos alvos. Erros da CLI retornam
codigo 2 e mensagens sanitizadas; o operador preserva o snapshot e o stderr
necessarios para reproduzir a falha, sem compartilhar credenciais ou nomes privados.

Se uma versao causar regressao, interrompa seu uso e preserve os outputs em outro
diretorio. Instale o wheel da release anterior verificada em uma venv separada,
confira seu hash/atestado e execute primeiro o exemplo sintetico offline. A versao
0.3.0 nao possui compare nem filtro de fixture; mantenha os snapshots originais
para retomar a analise depois da correcao. Nao ha migracao de banco nem estado
remoto para reverter. Corrija a fonte por nova PR com os mesmos checks obrigatorios;
publique uma nova versao, sem mover tags ou substituir artefatos antigos.
