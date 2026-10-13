# Requisitos do inventário — versão 1.0

Base: Trabalho 1 e Trabalho 2 da disciplina. Escopo: inventário local de ativos de tecnologia, vulnerabilidades e risco por dependência. Identificadores abaixo permitem rastrear cada regra até critérios e testes.

## Histórias de usuário

- **HU-01:** Como responsável pelo inventário, quero cadastrar um ativo com identificação, tipo e responsável para saber o que precisa ser protegido. Relacionada a RF-01, RF-02 e RF-06.
- **HU-02:** Como analista, quero buscar e atualizar ativos para manter o inventário correto. Relacionada a RF-03 e RF-04.
- **HU-03:** Como analista, quero excluir um ativo com confirmação e remover seus vínculos para não deixar informação órfã. Relacionada a RF-05 e RF-07.
- **HU-04:** Como responsável por segurança, quero registrar vulnerabilidades e consultar riscos próprios e herdados para priorizar tratamento. Relacionada a RF-06, RF-08 e RF-09.

## Requisitos funcionais

| ID | Regra verificável | Código | Critério |
|---|---|---|---|
| RF-01 | Cadastrar ativo com ID inteiro positivo único, nome único, responsável, localização, tipo enumerado e criticidade. | `Inventario.cadastrar_ativo` | CA-01, CA-02 |
| RF-02 | Oferecer pelo menos quatro tipos de ativo com código inteiro e classe derivada correspondente. | `modelos.TipoAtivo`, `criar_ativo` | CA-03 |
| RF-03 | Consultar por ID e filtrar por parte do nome, tipo e criticidade, sem alterar dados. | `Inventario.consultar_por_id`, `filtrar_ativos` | CA-04, CA-05 |
| RF-04 | Atualizar apenas campos informados, mantendo ID, vulnerabilidades e histórico. | `Inventario.atualizar_ativo` | CA-06, CA-07 |
| RF-05 | Excluir ativo somente após confirmação e remover suas vulnerabilidades e dependências de outros ativos. | `Inventario.excluir_ativo` | CA-08, CA-09 |
| RF-06 | Cadastrar vulnerabilidade em ativo existente, inclusive durante o cadastro inicial, com CVE, CWE, CVSS, descrição, fonte, impacto, prioridade, tratamento, status e verificação. | `Inventario.cadastrar_vulnerabilidade`, `interface` | CA-10, CA-11 |
| RF-07 | Consultar, atualizar e excluir vulnerabilidades ligadas ao ativo sem duplicar CVE no mesmo ativo. | `Inventario.consultar_vulnerabilidades` e operações relacionadas | CA-10, CA-11 |
| RF-08 | Persistir coleção como lista JSON de objetos e reconstituir as subclasses ao carregar; arquivo inválido não é sobrescrito. | `persistencia`, `modelos` | CA-12, CA-13 |
| RF-09 | Calcular risco próprio `Mv` e risco efetivo `r=(I-A)^-1Mv`, verificando invertibilidade antes da solução. | `risco.calcular_riscos` | CA-14, CA-15 |
| RF-10 | Manter no Docker um modo de serviço sem entrada interativa e responder consultas de saúde e riscos. | `ServicoInventario`, `Dockerfile` | CA-16 |

## Requisitos não funcionais

| ID | Regra verificável | Evidência |
|---|---|---|
| RNF-01 Segurança | Entradas inválidas são rejeitadas com mensagem de domínio, sem aceitar CVSS fora de 0–10, nomes repetidos ou correção sem verificação. | `test_sprint2.py`; matriz de validações |
| RNF-02 Integridade | Base JSON inválida impede o início e não é substituída; exclusão exige confirmação. | Testes de carga e exclusão |
| RNF-03 Testabilidade | Testes automatizados executam sem alterar a base demonstrativa e CI verifica testes e estilo em cada PR. | `python -m unittest -v`; Actions |
| RNF-04 Operação | Container responde `/saude` e `/riscos` sem teclado; permanência de 24 h exige prova no servidor da disciplina. | Workflow Docker; `evidencia-docker-24h.md` |

## Regras de negócio

RN-01: IDs positivos e nomes normalizados devem ser únicos. RN-02: CVE é único dentro do mesmo ativo. RN-03: vulnerabilidade corrigida requer verificação não pendente. RN-04: dependências apontam para ativos existentes, têm peso entre 0 inclusive e 1 exclusivo, e a soma por ativo é menor que 1. RN-05: remoção confirmada elimina vínculos que apontem para o ativo removido.

## Controle da especificação

Versão 1.0, 13/10/2026. Texto confrontado com o código e os critérios de aceitação. Revisão por outro integrante, onde exigida pelo card S2_06, ainda depende de participação humana e não é declarada como realizada.
