# Sprint 4 - evidências e estado da entrega

## Implementado no projeto

- Arquitetura em camadas: terminal em `interface.py`, regras em `inventario.py`,
  objetos em `modelos.py`, JSON em `persistencia.py` e cálculo matemático em
  `risco.py`.
- Painel de dependências e riscos com simulação de CVSS sem persistir mudanças.
- Retorno com a seta para a esquerda nas telas simples de filtro e dependência,
  além dos formulários que já mantinham essa navegação.
- Testes automatizados para persistência, regras, interface, riscos, matrizes,
  condicionamento e simulação.

## Docker e servidor

Os cards de Docker, monitoramento, Linux e integração recebem documentação e
arquivos de preparação no repositório de entregáveis. Por orientação do aluno,
nenhum container, compose ou servidor foi executado nesta etapa. Portanto não
há declaração de deploy nem de execução contínua que não tenha acontecido.

## Como validar

Na raiz do projeto, execute:

```powershell
python -m unittest -v
python -m flake8 .
```

O primeiro comando testa o comportamento. O segundo confere o estilo definido
em `.flake8`. Para usar a tela, execute `python app.py` no Windows e navegue
com as setas.
