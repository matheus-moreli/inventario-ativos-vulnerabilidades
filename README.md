# Inventário de Ativos e Vulnerabilidades

Projeto acadêmico em Python para registrar ativos de tecnologia e as vulnerabilidades associadas a eles. Ele foi desenvolvido para as Sprints 1 e 2 da disciplina e funciona inteiramente no terminal do Windows, sem bibliotecas externas, internet, banco de dados ou interface gráfica.

O objetivo é demonstrar os fundamentos de Python em um problema realista: saber quais equipamentos e sistemas existem, quem é responsável por eles, qual é sua importância para a segurança e quais falhas precisam de tratamento.

## Links importantes

- Código e programa executável: <https://github.com/matheus-moreli/inventario-ativos-vulnerabilidades>
- Entregáveis individuais de todos os cards: <https://github.com/matheus-moreli/entregaveis-inventario-ativos-vulnerabilidades>

O repositório atual contém o programa final, o banco JSON, os testes e o guia consolidado. O segundo repositório foi criado apenas para os PDFs, fontes LaTeX, scripts individuais e imagens de evidência de cada card.

## O que o programa controla

Um **ativo** é qualquer recurso de tecnologia que precisa ser acompanhado: notebook, servidor, roteador, aplicação web, banco de dados ou software licenciado.

Uma **vulnerabilidade** é uma fraqueza identificada em um ativo. O programa registra, por exemplo, CVE, CWE, nota CVSS, impacto, prioridade, tratamento, status e a forma de verificar que o tratamento funcionou.

O sistema permite:

- cadastrar, listar, buscar, atualizar e remover ativos;
- cadastrar, consultar, atualizar e remover vulnerabilidades;
- vincular cada vulnerabilidade ao ativo afetado;
- filtrar ativos por nome, tipo e importância para a segurança;
- consultar vulnerabilidades pela lista, por ID do ativo ou com filtros avançados;
- aceitar CVSS com ponto ou vírgula decimal, como 9.8 ou 9,8;
- impedir ID de ativo repetido e CVE repetido no mesmo ativo;
- exigir evidência antes de marcar uma vulnerabilidade como corrigida;
- manter um histórico simples das alterações feitas em cada ativo;
- salvar as mudanças em um arquivo JSON local.

Esta é uma aplicação didática. Ela não realiza varredura automática de rede, não consulta o NVD automaticamente, não possui login, não armazena senhas e não substitui uma ferramenta profissional de gestão de vulnerabilidades.

## Requisitos

Para executar o programa, são necessários:

- Windows;
- Python 3;
- PowerShell ou Prompt de Comando;
- Git apenas se a intenção for clonar o repositório.

O programa usa somente módulos que já acompanham o Python. Não existe etapa de instalar pacotes com pip.

### Confirmar se o Python está instalado

Abra o PowerShell e execute:

~~~powershell
python --version
~~~

Se aparecer uma versão do Python 3, está pronto. Caso o comando não seja reconhecido, instale o Python pelo site oficial e marque a opção para adicioná-lo ao PATH durante a instalação.

## Como obter o projeto

### Opção 1 — Clonar com Git

No PowerShell, escolha uma pasta onde deseja guardar projetos e execute:

~~~powershell
git clone https://github.com/matheus-moreli/inventario-ativos-vulnerabilidades.git
cd inventario-ativos-vulnerabilidades
~~~

Clonar significa baixar uma cópia do repositório e também o histórico de versões. A pasta criada terá o nome inventario-ativos-vulnerabilidades.

### Opção 2 — Baixar sem Git

1. Abra o repositório no navegador.
2. Clique em Code.
3. Clique em Download ZIP.
4. Extraia o arquivo ZIP.
5. Abra o PowerShell dentro da pasta extraída.

Para abrir o PowerShell em uma pasta pelo Explorador de Arquivos, clique na barra de endereço, escreva powershell e pressione Enter.

## Como iniciar o programa

Dentro da pasta do projeto, execute:

~~~powershell
python app.py
~~~

O programa carrega automaticamente o arquivo dados/inventario.json e mostra a quantidade de ativos disponíveis. A base inicial foi preparada para demonstração, com seis ativos e cinco vulnerabilidades.

Para encerrar, selecione Sair no menu principal. O programa tenta salvar os dados automaticamente depois de cada cadastro, atualização ou remoção. Ao sair, ele tenta salvar novamente. Caso haja falha de gravação, a tela oferece a escolha entre tentar salvar de novo ou sair conscientemente sem salvar as alterações mais recentes.

## Navegação no terminal

O menu principal e todas as listas de opções são controlados pelo teclado.

| Tecla | O que faz |
|---|---|
| Seta para cima | Move a seleção para a opção anterior. |
| Seta para baixo | Move a seleção para a próxima opção. |
| Enter | Confirma a opção selecionada ou abre o item escolhido. |
| Seta para a esquerda | Volta ao campo anterior de um formulário ou cancela uma tela simples. |
| Seta para a direita | Avança no formulário somente quando o campo obrigatório já foi preenchido. |
| Backspace | Apaga caracteres para corrigir um texto. |

As opções padronizadas, como tipo de ativo, importância, prioridade e status, são escolhidas por setas. Não é necessário decorar nem digitar textos como Crítica ou Em tratamento.

Nas telas de remoção, a escolha inicial é sempre Cancelar. Isso evita apagar um registro por pressionar Enter sem conferir o alvo.

## Menu principal, opção por opção

| Opção | Função |
|---|---|
| Cadastrar ativo | Cria um ativo com ID, nome, responsável, localização, tipo e importância para a segurança. |
| Listar ativos | Mostra todos os ativos cadastrados e suas informações principais. |
| Buscar ativo | Permite procurar por ID ou filtrar por nome, tipo e importância. |
| Atualizar ativo | Altera os campos permitidos de um ativo existente. |
| Remover ativo | Exclui um ativo depois de confirmação explícita. As vulnerabilidades ligadas a ele também são removidas. |
| Cadastrar vulnerabilidade | Registra uma vulnerabilidade para um ativo já existente. |
| Consultar vulnerabilidades | Exibe a lista completa, as vulnerabilidades de um ativo específico ou um filtro avançado. |
| Atualizar vulnerabilidade | Altera descrição, prioridade, tratamento, status e verificação. |
| Remover vulnerabilidade | Exclui uma vulnerabilidade após confirmação explícita. |
| Mostrar resumo do inventário | Mostra o total de ativos e de vulnerabilidades. |
| Sair | Encerra o programa de maneira segura. |

## Primeiro roteiro de uso

Este roteiro permite apresentar o projeto sem precisar cadastrar tudo do zero.

1. Execute python app.py.
2. Selecione Listar ativos para visualizar os seis registros de demonstração.
3. Selecione Consultar vulnerabilidades e escolha Ver vulnerabilidades cadastradas.
4. Use as setas para abrir uma vulnerabilidade e visualizar todos os seus dados.
5. Volte com Enter ou com a seta para a esquerda.
6. Escolha Ver vulnerabilidades de um ativo por ID e informe 2 para ver o servidor web.
7. Escolha Buscar ativo, depois Filtrar por nome, tipo ou importância do ativo.
8. Pesquise por SRV para encontrar o servidor web; também é possível filtrar por tipo ou importância.
9. Abra Mostrar resumo do inventário para ver os totais.

## Como cadastrar um ativo

Ao escolher Cadastrar ativo, a tela pede:

1. **ID**: número inteiro positivo e único. Exemplo: 20.
2. **Nome ou hostname**: identificação legível. Exemplo: NB-SECRETARIA-01.
3. **Responsável**: equipe ou pessoa responsável. Exemplo: Equipe de Suporte.
4. **Setor ou localização**: local em que o ativo está. Exemplo: Secretaria Acadêmica.
5. **Tipo de ativo**: selecionado por setas entre Notebook, Servidor, Roteador, Aplicação Web, Banco de Dados e Software Licenciado.
6. **Importância para a segurança**: selecionada entre Baixa, Média, Alta e Crítica.

O ID não pode ser alterado depois do cadastro. Ele representa a identidade do ativo dentro do inventário. Se o ID tiver sido informado errado, remova o registro e cadastre-o novamente.

## Como cadastrar uma vulnerabilidade

Antes de cadastrar uma vulnerabilidade, o ativo afetado precisa existir. A tela solicita:

1. ID do ativo afetado;
2. CVE no formato CVE-AAAA-NÚMERO, por exemplo CVE-2024-1234;
3. CWE no formato CWE-NÚMERO, por exemplo CWE-79;
4. nota CVSS entre 0.0 e 10.0;
5. descrição clara da falha;
6. fonte verificável, como uma URL ou órgão de referência;
7. data da fonte no formato dd/mm/aaaa;
8. impacto no ativo;
9. prioridade;
10. tratamento planejado;
11. status;
12. forma de verificação.

O CVSS pode ser informado como 9.8 ou 9,8. O programa converte a vírgula para ponto antes de validar o número.

Se o status for Corrigida, a verificação não pode ficar como Pendente. É necessário informar uma evidência, como atualização conferida, teste realizado ou versão corrigida validada.

O CVE é a identidade da vulnerabilidade dentro do ativo e não é alterado depois do cadastro. Um mesmo CVE pode existir em ativos diferentes, mas não pode aparecer duas vezes no mesmo ativo.

## Base demonstrativa

O arquivo dados/inventario.json já contém exemplos seguros para praticar a navegação e os filtros:

| ID | Ativo | Tipo | Importância | Situação demonstrada |
|---|---|---|---|---|
| 1 | NB-LAB-01 | Notebook | Média | Vulnerabilidade corrigida. |
| 2 | SRV-WEB-01 | Servidor | Crítica | Vulnerabilidade em tratamento. |
| 3 | RT-FILIAL-01 | Roteador | Alta | Vulnerabilidade aberta. |
| 4 | APP-PORTAL-01 | Aplicação Web | Alta | Vulnerabilidade corrigida. |
| 5 | DB-ESTOQUE-01 | Banco de Dados | Crítica | Nenhuma vulnerabilidade cadastrada. |
| 6 | SW-OFFICE-01 | Software Licenciado | Baixa | Risco aceito temporariamente. |

Esses dados são exemplos de apresentação. Eles podem ser alterados ou removidos durante a demonstração. Para voltar à versão original baixada do GitHub, descarte suas mudanças locais com cuidado ou faça uma nova cópia do repositório.

## Onde os dados ficam salvos

O arquivo dados/inventario.json funciona como o banco de dados simples do projeto.

- Ele é texto em formato JSON.
- É atualizado quando uma operação altera os dados.
- Pode ser aberto em um editor de texto, mas é mais seguro alterar registros pelo programa.
- Se o JSON estiver corrompido ou tiver formato inválido, o programa interrompe a execução e não sobrescreve o arquivo por acidente.

Antes de testar cadastros e remoções livremente, faça uma cópia do arquivo inventario.json. Assim, é possível restaurar a base de demonstração caso necessário.

## Como executar os testes

Os testes verificam regras do sistema sem modificar o arquivo real de dados.

~~~powershell
python -m unittest -v test_sprint2.py
~~~

Atualmente, a suíte possui 33 testes. Ela cobre cadastro e busca, IDs e CVEs repetidos, validações de CVE, CWE, CVSS e data, JSON inválido, atualização sem alteração parcial, navegação por setas, cancelamento, confirmação de remoção, consulta de vulnerabilidades, tratamento de falha ao salvar e outros comportamentos importantes.

Se todos passarem, o final exibirá OK.

## Estrutura do projeto

| Arquivo ou pasta | Responsabilidade |
|---|---|
| app.py | Ponto de entrada. Define o caminho do JSON e inicia o programa. |
| interface.py | Menus, leitura do teclado, mensagens e formulários do terminal. |
| inventario.py | Regras de negócio, validações e operações de cadastro, consulta, atualização e remoção. |
| modelos.py | Classes Ativo e Vulnerabilidade, enumeração dos tipos e listas de opções padronizadas. |
| persistencia.py | Leitura e gravação do arquivo JSON. |
| dados/inventario.json | Base local com os ativos e vulnerabilidades. |
| test_sprint2.py | Testes automatizados com unittest. |
| guia_sprint1.tex | Fonte LaTeX do guia consolidado das Sprints 1 e 2. |
| guia_sprint1.pdf | PDF pronto para leitura, estudo e apresentação. |

## Entregáveis das Sprints

Além deste repositório do programa final, cada card possui seu material individual no repositório de entregáveis.

- Sprint 1: cards S1_01 a S1_20, com PDFs, fontes LaTeX e scripts Python quando solicitados.
- Sprint 2: cards S2_01 a S2_19, com PDFs, fontes LaTeX e imagens de verificação quando aplicáveis.
- Guia consolidado: o arquivo guia_sprint1.pdf deste repositório explica a lógica de todas as Sprints em uma sequência única.

Os materiais individuais estão disponíveis em:

<https://github.com/matheus-moreli/entregaveis-inventario-ativos-vulnerabilidades>

## Branches e histórico

A branch principal é a main. Ela contém a versão completa do programa pronta para execução e apresentação.

As branches de funcionalidade preservam o histórico de aprendizagem e dos Pull Requests realizados durante o desenvolvimento. O código final integrado deve ser executado sempre a partir da main.

## Problemas comuns

### O comando python não funciona

Instale o Python 3 ou reinicie o terminal depois da instalação. Em alguns computadores, o comando py também pode estar disponível:

~~~powershell
py app.py
~~~

### O programa fecha logo ao iniciar

Verifique se o comando foi executado dentro da pasta do projeto e se o arquivo dados/inventario.json existe. Se o arquivo estiver inválido, restaure uma cópia válida do repositório.

### As setas não funcionam

Execute pelo PowerShell ou Prompt de Comando do Windows. A navegação foi feita para o terminal do Windows.

### Não consigo usar a seta direita

Ela não serve para pular campos obrigatórios. Preencha o campo atual e tente novamente. Para corrigir uma informação anterior, use a seta para a esquerda.

### Não consigo marcar uma vulnerabilidade como corrigida

Informe uma verificação diferente de Pendente. O sistema exige evidência para evitar que uma falha seja considerada resolvida sem comprovação.

### Quero recomeçar os dados de demonstração

Restaure uma cópia anterior do arquivo dados/inventario.json ou faça uma nova cópia do repositório. Nunca apague arquivos sem confirmar o caminho escolhido.

## Sugestão de apresentação

1. Explique o problema: ativos importantes podem ter vulnerabilidades e precisam ser acompanhados.
2. Mostre os ativos de demonstração.
3. Abra uma vulnerabilidade pela lista, sem digitar um CVE.
4. Mostre a consulta por ID do ativo.
5. Cadastre ou atualize um registro.
6. Demonstre a validação com um CVSS inválido e depois com 9,8.
7. Inicie uma remoção e cancele para demonstrar a confirmação segura.
8. Execute os testes e mostre o resultado OK.
9. Mostre o guia PDF e o repositório separado de entregáveis.

Com esse roteiro, é possível demonstrar tanto o funcionamento do programa quanto as decisões de implementação exigidas nas Sprints.
