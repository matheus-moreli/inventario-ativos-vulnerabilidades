# Implantação e demonstração — porta 2217

A aplicação tem dois modos: HTTP de consulta somente leitura e terminal Rich com CRUD completo.

## Executar localmente

```sh
python -m pip install -r requirements.txt -r requirements-dev.txt
python app.py
python app.py --testes
```

A interface de terminal oferece CRUD, categorias personalizadas (código >=100), campos adicionais,
matrizes e simulação. Cada tipo personalizado aparece como objeto da classe
`EquipamentoPersonalizado` e mantém nome e código no próprio JSON do ativo.
Categorias não vinculadas a nenhum ativo não são persistidas.

## Implantação com Docker Compose

O projeto Compose, o contêiner e a imagem usam o identificador
`trab02_2026_2_12621cbs217`. O volume nomeado preserva o JSON em
`/app/dados`. O serviço publica a porta **2217** no loopback do servidor.
O acesso remoto segue pelo túnel SSH da disciplina.

Para uma instalação nova, execute na raiz do projeto:

```sh
docker compose config --quiet
docker compose build
docker compose run --rm --no-deps inventario python -m infraestrutura.preparar_acesso
docker compose up -d
docker compose ps inventario
curl --fail http://127.0.0.1:2217/saude
docker compose exec inventario python app.py
```

O comando de preparação solicita o segredo da API sem eco e cria o arquivo
no volume. Execute-o uma vez por volume. O último comando abre o menu de
CRUD e risco. O serviço HTTP continua atendendo enquanto o menu é usado.
Use uma sessão de escrita por vez.

Para testar em outra porta, defina `INVENTARIO_PORTA_EXTERNA` e escolha outro
nome de projeto com `docker compose -p`. Isso cria outro volume e outro
contêiner. A implantação antiga já registrada usa a porta 2217. Consulte
a instância existente antes de escolher a porta de uma implantação nova.

## Consultas HTTP

| Rota | Resultado |
|---|---|
| `GET /saude` | Estado, tempo de atividade e quantidade de ativos. |
| `GET /openapi.json` | Contrato OpenAPI para importar em ferramentas de documentação ou testes. |
| `GET /v1/ativos?busca=srv&pagina=1&limite=10&ordenar=risco` | Página de ativos cujo hostname contém `srv`, por risco efetivo decrescente. |
| `GET /v1/riscos` | IDs, matrizes, severidades, riscos próprio e efetivo e alerta de condicionamento. |

As rotas da versão 1 exigem `Authorization: Bearer <segredo>`. Erros da
versão 1 seguem Problem Details. A rota `/riscos` continua atendendo os
clientes da versão anterior.

## Evidência de funcionamento contínuo

Registre data, hora e ID do contêiner logo após iniciar e novamente depois
de pelo menos 24 horas. Compare a imagem, o horário de início e o contador
de reinicializações.

```sh
docker compose ps inventario
docker inspect "$(docker compose ps -q inventario)" --format \
'id={{.Id}} imagem={{.Image}} inicio={{.State.StartedAt}} ativo={{.State.Running}} reinicios={{.RestartCount}} saude={{.State.Health.Status}}'
docker compose logs --tail 20 inventario
curl --fail http://127.0.0.1:2217/saude
```

O registro histórico de V1, V2 e V3 está em
[evidências Docker de 23/11](evidencias-docker-2026-11-23.md).

## Dados do Trabalho 1

O JSON antigo, com os ativos em um objeto indexado por ID, pode ser lido diretamente.
Após uma gravação bem-sucedida, os dados ficam no formato atual, uma lista de objetos
JSON. As dependências começam vazias nos registros antigos.

## Modelo acadêmico

A matriz M (ativos por CVEs distintas), o vetor v (CVSS por CVE), a matriz A
(dependências), b=F·Mv e (I-A)x=b são derivados dos dados persistidos.
F é a diagonal dos fatores de exposição, definidos pelo tipo de cada equipamento
e não gravados no JSON. Com F=I, o caso se reduz a b=Mv.
O índice de risco efetivo pode superar 10 e não é uma nota CVSS.
Vulnerabilidades corrigidas ainda participam do cálculo base por exigência do
modelo cadastral; risco residual seria uma análise separada.
Campos adicionais são descritivos e não alteram pesos matemáticos automaticamente.

## Limitações conscientes

- Inserir um novo *tipo* pelo terminal cria uma instância de uma subclasse
  personalizada genérica; criar nova subclasse com regras específicas exige código.
- A aplicação recebe CVSS informado pelo usuário e não calcula vetor CVSS oficial.
- O terminal tem navegação por setas e Esc/0 para voltar; cada formulário pode ser cancelado sem gravação.
- O modo HTTP é somente leitura. O CRUD está no menu de terminal.
