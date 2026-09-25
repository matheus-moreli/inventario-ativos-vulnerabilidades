# Inventário de Ativos e Vulnerabilidades

Projeto de terminal em Python desenvolvido para as Sprints 1 e 2. Ele registra ativos de TI e as vulnerabilidades associadas a cada ativo, preservando os dados em um arquivo JSON local.

## Requisitos

- Windows;
- Python 3 instalado;
- nenhuma biblioteca externa ou acesso à internet.

O projeto usa apenas módulos que já acompanham o Python. A interface usa o teclado do terminal do Windows.

## Como executar

Abra o PowerShell na pasta do projeto e execute:

```powershell
python app.py
```

Na primeira execução, a base começa vazia. Os dados são salvos em `dados/inventario.json` depois de cada cadastro, atualização ou remoção.

## Como usar o terminal

| Tecla | Ação |
|---|---|
| Seta para cima / baixo | Muda a opção selecionada nos menus. |
| Enter | Confirma a opção ou abre o registro escolhido. |
| Seta para a esquerda | Volta ao campo anterior ou cancela uma operação. |
| Seta para a direita | Avança somente quando o campo obrigatório já tem uma resposta. |
| Backspace | Corrige o texto de um campo. |

As categorias de ativo, importância, prioridade e status são selecionadas pelas setas. A confirmação de remoção começa em **Cancelar**, evitando que um Enter acidental apague dados.

## O que o sistema faz

- Cadastra, lista, busca, atualiza e remove ativos.
- Registra vulnerabilidades com CVE, CWE, CVSS, fonte, data, impacto, prioridade, tratamento, status e verificação.
- Aceita CVSS com ponto ou vírgula decimal: `9.8` e `9,8` representam a mesma nota.
- Consulta vulnerabilidades de três formas: lista geral, lista de um ativo pelo ID e filtro avançado.
- Exige evidência antes de marcar uma vulnerabilidade como `Corrigida`.
- Mantém histórico das alterações de cada ativo.
- Impede IDs repetidos e CVEs repetidos no mesmo ativo.

O ID do ativo e o CVE de uma vulnerabilidade não são alterados. Se for necessário corrigir um deles, o registro deve ser removido e cadastrado novamente.

## Dados e segurança

O arquivo `dados/inventario.json` é a base local do projeto. Quando o conteúdo estiver inválido ou corrompido, o programa não o sobrescreve. Quando não consegue salvar, informa o problema e permite tentar novamente ou sair sem gravar as alterações mais recentes.

O programa não solicita ou armazena senhas, tokens ou chaves. Esta versão não possui interface gráfica, login, banco de dados, varredura automática ou integração com APIs externas.

## Como testar

```powershell
python -m unittest -v test_sprint2.py
```

Os testes automatizados usam dados temporários e não alteram `dados/inventario.json`. Eles verificam regras de ativos e vulnerabilidades, validações, persistência JSON, consulta por lista e por ID, navegação/cancelamento, confirmação de remoção e tratamento de falha ao salvar.

## Organização dos arquivos

- `app.py`: ponto de entrada do programa.
- `interface.py`: menus, leitura do teclado e mensagens do terminal.
- `inventario.py`: validações e operações CRUD.
- `modelos.py`: classes `Ativo` e `Vulnerabilidade`, enumerações e listas padronizadas.
- `persistencia.py`: leitura e gravação do JSON.
- `dados/inventario.json`: dados cadastrados durante o uso.
- `test_sprint2.py`: testes automatizados.
- `guia_sprint1.tex` e `guia_sprint1.pdf`: guia consolidado de estudo e apresentação das Sprints 1 e 2.

## Roteiro curto de demonstração

1. Execute `python app.py`.
2. Cadastre um ativo e uma vulnerabilidade vinculada a ele.
3. Informe `9,8` como CVSS para demonstrar a validação brasileira.
4. Consulte a vulnerabilidade pela lista, sem digitar o CVE.
5. Mostre a consulta por ID do ativo.
6. Tente repetir um ID ou usar uma nota CVSS inválida.
7. Inicie uma remoção, cancele e depois confirme conscientemente.
