# Conferência dos enunciados oficiais — 13/10/2026

Fontes lidas: **1ª Atividade Avaliativa, versão 2.0 (2026/2)**, páginas 1–4, **2ª Atividade Avaliativa (Sprints 3–5)**, páginas 1–4, e **Aula CIBER Risco**, 36 slides enviados pelo docente. O segundo enunciado preserva os requisitos do primeiro. Esta conferência trata os itens da Tabela 1 de cada enunciado como critérios obrigatórios; o checklist e os exemplos da aula ajudam a conferir a implementação.

## Trabalho 1 — Tabela 1

| Nº | Exigência | Evidência na branch `melhoria-trabalho-2-completo` | Estado |
|---|---|---|---|
| 1 | Menu e tratamento de entradas | `interface.py` oferece menu, valida campos vazios/tipos e captura erros de domínio | Presente |
| 2 | Enum com quatro ou mais tipos e códigos inteiros | `modelos.TipoAtivo` contém seis categorias `IntEnum` | Presente |
| 3 | Cadastro com ID único, campos mínimos e vulnerabilidades iniciais, salvo em texto | `interface.cadastrar_ativo_tela` pergunta por vulnerabilidades iniciais; `Inventario.cadastrar_ativo`; `RepositorioJSON.salvar` | Presente |
| 4 | Busca por ID ou nome/hostname | `Inventario.consultar_por_id` e `Inventario.filtrar_ativos` | Presente |
| 5 | Atualização de ativo | `Inventario.atualizar_ativo` e tela correspondente | Presente |
| 6 | Exclusão com vulnerabilidades associadas | `Inventario.excluir_ativo` remove o objeto que contém as vulnerabilidades e limpa dependências recebidas | Presente |
| 7 | Cadastro posterior de vulnerabilidade com descrição, categoria, severidade e status | `Inventario.cadastrar_vulnerabilidade` armazena descrição, CWE, severidade numérica CVSS e status | Presente |
| 8 | Consulta com descrição, severidade e status; mensagem quando vazia | `interface.mostrar_vulnerabilidades` rotula `Severidade (CVSS)` e informa ausência | Presente |
| 9 | Dicionário para organização/busca | `RepositorioJSON.carregar` indexa objetos por ID em `dict` | Presente |
| 10 | Mais de duas branches e merge | Histórico contém merges `5605234`, `11cfee2`, `aa87d1a`, `e6ceeea`; PRs #1 e #2 anteriores estão integradas | Presente no histórico Git |

## Trabalho 2 — Tabela 1 e Seção 2

| Nº | Exigência | Evidência | Estado |
|---|---|---|---|
| 1 | Cada ativo como objeto de classe base e tipos derivados | `Equipamento` e seis subclasses em `modelos.py`; `Inventario`, `InterfaceTerminal`, `RepositorioJSON`, `AnalisadorRisco` e `Aplicacao` organizam o programa. Funções auxiliares de entrada/saída e adaptadores preservam compatibilidade com o Trabalho 1 | Presente; herança, polimorfismo e fluxo principal orientado a objetos verificados |
| 2 | Arquivo JSON formado por array de objetos | `dados/inventario.json` começa com `[` e `RepositorioJSON.salvar` serializa lista; subclasses são reconstituídas | Presente |
| 3 | Aplicação no Docker ativa por no mínimo 24 h no servidor do docente | `Dockerfile` e comando `docker run -dit ... python app.py` em `evidencia-docker-24h.md`. A versão final `4e9d6ad` iniciou em container isolado no Docker Desktop em 13/10 às 22:06:25 BRT, com menu completo, volume e zero reinícios na primeira inspeção | **Não comprovado integralmente**: ainda não há 24 h verificadas nem execução no servidor do docente |
| 4 | M, v, A, b=Mv, invertibilidade de I−A, solução e consulta de b/x | `risco.py` monta uma coluna por CVE, inclusive quando afeta dois ativos; calcula κ∞(I−A), verifica pivôs e resolve por Gauss; `InterfaceTerminal.mostrar_riscos_tela` consulta; `test_risco.py` reproduz o cenário de V2 compartilhada da aula, a solução manual e a matriz singular | Presente nos 53 testes locais e na imagem Docker `4e9d6ad` |

As dependências são persistidas no mesmo JSON do ativo. A soma dos pesos por linha é limitada a menos de 1, condição suficiente de invertibilidade; a verificação explícita também existe. O CVSS é usado como severidade numérica e deve ser igual para a mesma CVE em dois ativos. O número de condição da norma infinita é calculado e mostrado com aviso acima de `10^8`; o slide de exemplo usa a norma 2, portanto seus valores numéricos de κ não são idênticos. O fator de exposição `F` é uma **extensão ilustrativa** da aula e uma dica no enunciado, sem pesos de exposição definidos nos dados. A V4 sem equipamento no slide demonstra uma coluna nula; o Trabalho 1 pede cadastro de vulnerabilidades associadas a ativos, então a interface não cria vulnerabilidades avulsas.

## Limites da conclusão

- O código melhorado está publicado na **PR #3 em rascunho**; a `main` ainda não contém essas mudanças. A recomendação do README para executar a versão final da `main` só valerá após integração.
- O CI da PR testa Python e estilo. O build e teste de fumaça Docker foram feitos no Docker Desktop local; eles não comprovam 24 horas no servidor do docente.
- A exigência do Trabalho 2 sobre apresentação individual e domínio do conteúdo depende de Matheus demonstrar e explicar o programa; não pode ser certificada pelo repositório.
- Este documento não atribui nota. A avaliação e o prazo final são do docente.
