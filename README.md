# Inventário de Ativos e Vulnerabilidades — UFU

O Trabalho 2 evolui o inventário do Trabalho 1. O menu cadastra e consulta
equipamentos e vulnerabilidades. Cada tipo de equipamento tem sua classe,
a base é salva em JSON e o risco efetivo é calculado por álgebra linear.

## Rodar no Windows

Abra `iniciar.bat`. Na primeira execução ele cria `.venv`, instala as
dependências do programa e do Pytest e abre o menu. É necessário Python 3.10
ou superior e acesso ao índice de pacotes para a instalação inicial.

```powershell
.\iniciar.bat --testes
.\iniciar.bat --instalar
```

Em Linux ou em um ambiente Python já preparado:

```sh
python -m pip install -r requirements.txt -r requirements-dev.txt
python app.py
python app.py --testes
```

## Código em quatro blocos

| Bloco | O que explicar |
|---|---|
| [Entrada e telas](app.py) | `app.py` escolhe terminal ou serviço. `apresentacao/interface_rica.py` liga os menus às operações e `navegacao.py` trata as teclas e os formulários. |
| [Equipamentos e regras](dominio/inventario.py) | `modelos.py` define equipamentos e vulnerabilidades. `Inventario` localiza, valida e aplica as alterações. |
| [Persistência](infraestrutura/persistencia.py) | Reconstrói objetos do JSON e salva uma lista de registros em arquivo temporário antes da troca atômica. O menu publica a alteração em memória depois da gravação. A base do Trabalho 1 pode ser lida diretamente. |
| [Álgebra linear](dominio/risco.py) | Monta M, v e A, calcula b = F·Mv (F é o fator de exposição de cada tipo, definido por polimorfismo) e resolve (I − A)x = b. A fatoração é reutilizada e a solução é conferida pelo resíduo. |

## Testes

Os testes ficam em `tests/`. Rode `python app.py --testes` ou `python -m pytest`.

## Demonstração

1. Busque um ativo por ID e depois por hostname. Mostre a ficha e as
   vulnerabilidades. Faça uma mudança na base de demonstração e reabra o
   programa para conferir o JSON.
2. Abra **Análise matemática e simulações**. Mostre o risco próprio,
   a parcela herdada, o risco efetivo e a conta detalhada de um equipamento.
   O [modelo de risco](docs/modelo-de-risco.md) traz um exemplo completo com
   três equipamentos e um ciclo.
3. Mostre o volume e a [evidência das 24 horas na UFU](docs/evidencias-docker-2026-11-23.md).
   A V3 estava ativa havia **5 dias, 23 h, 13 min e 55 s** na coleta de 23/11/2026,
   com zero reinícios registrados. Isso comprova o requisito para a versão
   publicada. O [novo Compose](docs/implantacao-2217.md) pertence à revisão
   local e sua execução ainda precisa ser validada.

A API de consulta usa a mesma base. `GET /openapi.json` publica o contrato,
`GET /saude` mostra a saúde e as rotas protegidas
`/v1/ativos` e `/v1/riscos` consultam ativos e risco. O CRUD é feito pelo menu.

[Guia do terminal](docs/interface-terminal.md) ·
[Conferência dos enunciados](docs/conferencia-enunciados.md)
