# Especificação do inventário — versão 1.0

**Data:** 13/10/2026. **Responsável:** Matheus Moreli Durão Silva. **Estado:** revisão técnica contra código concluída; revisão humana externa dos cenários do S2_06 pendente.

## Objetivo, atores e limites

O analista de inventário mantém ativos, vulnerabilidades e dependências para consultar risco próprio e efetivo. O operador usa o menu; o avaliador ou monitor pode consultar o serviço HTTP somente leitura no Docker. A aplicação usa arquivos locais e não autentica usuários. Não faz varredura de rede, consulta automática a CVE, gestão de credenciais nem substitui um sistema corporativo.

## Entradas, saídas e modelo

Entrada do menu: ID, nome, responsável, localização, tipo `TipoAtivo`, criticidade e dados de vulnerabilidades. Entrada persistida: lista JSON de objetos. Saídas: mensagens de cadastro/erro, lista e filtros, histórico, matrizes e vetores de risco. No serviço: `/saude` e `/riscos`, ambos JSON e somente leitura.

`Ativo` contém `id`, `nome`, `responsavel`, `localizacao`, `tipo`, `criticidade`, lista de `vulnerabilidades`, `historico` e `dependencias`. Cada dependência contém `ativo_id` e `peso`. `Vulnerabilidade` contém CVE, CWE, CVSS, descrição, fonte, data da fonte, impacto, prioridade, tratamento, status e verificação. A coleção em memória usa ID como chave e objetos `Ativo` ou derivados como valores; o arquivo é uma lista JSON. Os tipos concretos estão em `modelos.py`.

## Regras e arquitetura

Os requisitos RF-01 a RF-10 e RNF-01 a RNF-04 estão em [requisitos.md](requisitos.md). A matriz de entrada, tratamento e mensagens está em [matriz-validacoes.md](matriz-validacoes.md). O modelo de domínio é orientado a objetos: `Inventario` concentra operações, `Ativo` e subclasses representam os equipamentos, `Vulnerabilidade` representa o achado, `RepositorioJSON` preserva os objetos, `AnalisadorRisco` calcula riscos e `Aplicacao` coordena a execução. As funções dos módulos de inventário, risco e persistência preservam compatibilidade com as entregas anteriores. O terminal mantém helpers de entrada e apresentação; não armazena regras de negócio.

No cálculo, `M` é a incidência ativo × vulnerabilidade, `v` contém severidades CVSS e `p=Mv` é o risco próprio. A matriz `A` guarda a fração de risco transmitida por dependências. Se `I-A` é invertível, resolve-se `(I-A)r=p` por eliminação de Gauss. Matriz singular gera erro em vez de número incorreto.

## Rastreabilidade e aceitação

Cada RF da tabela de requisitos aponta para código e um CA. [criterios_aceitacao.md](criterios_aceitacao.md) contém casos de sucesso, erro e borda do CRUD e casos do Trabalho 2. `test_sprint2.py`, `test_risco.py` e `test_servico.py` verificam os caminhos principais. O CI executa testes, estilo e um ensaio curto do container; 24 horas no servidor da disciplina exigem a prova separada em [evidencia-docker-24h.md](evidencia-docker-24h.md).

## Histórico da versão

1.0 — consolidação dos requisitos das Sprints 1 e 2 e extensão explícita do Trabalho 2. Não há aprovação de outro integrante registrada nesta versão.
