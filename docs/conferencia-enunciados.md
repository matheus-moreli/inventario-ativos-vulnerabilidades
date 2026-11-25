# Conferência do Trabalho 2

| Requisito | Parte do projeto a demonstrar |
|---|---|
| CRUD, validação e busca herdados do Trabalho 1 | Menu em `apresentacao/interface_rica.py`, busca por ID ou hostname, cadastro com vulnerabilidades iniciais, edição e exclusão confirmada. |
| Equipamentos como objetos | Classe `Equipamento`, subclasses em `dominio/modelos.py` e reconstrução do objeto pelo tipo ao carregar. |
| JSON em lista | `RepositorioJSON`. Carrega a base antiga do Trabalho 1 e salva a estrutura atual com objetos e dependências. |
| Docker na UFU | Dockerfile e configuração Compose desta revisão. O [registro de 23/11](evidencias-docker-2026-11-23.md) documenta V1 e V3, cada uma acima de 24h. A revisão com Compose tem sua própria execução. |
| Álgebra linear | `dominio/risco.py`, painel de análise, demonstração numérica e testes do [modelo de risco](modelo-de-risco.md). |

A API versionada, o contrato OpenAPI e a execução por Pytest aplicam conteúdos
da Sprint 5 ao mesmo inventário. Consulte o [guia de implantação](implantacao-2217.md)
para executar e demonstrar o projeto.
