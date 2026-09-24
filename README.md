# Inventário de Ativos e Vulnerabilidades

Projeto de terminal em Python desenvolvido para as Sprints 1 e 2.

## Como executar

Na pasta do projeto, execute:

```powershell
python app.py
```

O arquivo `dados/inventario.json` será criado quando houver dados para salvar.

## Como testar

```powershell
python -m unittest -v test_sprint2.py
```

Os testes não usam o JSON real do projeto e não precisam de internet nem de bibliotecas externas.

## Organização

- `app.py`: inicia o programa.
- `interface.py`: menu, perguntas e mensagens do terminal.
- `inventario.py`: regras, validações e operações CRUD.
- `modelos.py`: classes `Ativo` e `Vulnerabilidade`, enum e listas padronizadas.
- `persistencia.py`: leitura e gravação no JSON.
- `test_sprint2.py`: testes automatizados das regras principais.
- `DOCUMENTACAO_SPRINT2.md`: requisitos, critérios de aceite e roteiro de demonstração.

## O que o sistema faz

Cadastra, lista, busca, atualiza e exclui ativos. Também cadastra, consulta, atualiza e remove vulnerabilidades com CVE, CWE, CVSS, fonte, data, impacto, prioridade, tratamento, status e verificação. O ID do ativo e o CVE de uma vulnerabilidade não mudam; atualizações ficam registradas em histórico.

## Segurança e escopo

O programa não solicita ou armazena senhas, tokens ou chaves. Esta versão é local e não inclui interface gráfica, login, varredura automática nem integração com APIs externas.
