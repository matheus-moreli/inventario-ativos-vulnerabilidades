# Implantação e demonstração — porta 2217

A aplicação tem dois modos: HTTP de consulta somente leitura e terminal Rich com CRUD completo.

## Executar localmente

```sh
python -m pip install -r requirements.txt
python app.py
python app.py --testes
```

A interface de terminal oferece CRUD, categorias personalizadas (código >=100), campos adicionais,
matrizes e simulação. Cada tipo personalizado aparece como objeto da classe
`EquipamentoPersonalizado` e mantém nome e código no próprio JSON do ativo.
Categorias não vinculadas a nenhum ativo não são persistidas.

## Implantação no servidor da disciplina

Usar apenas os recursos do próprio aluno, nunca `docker system prune`.
A porta é **2217 no host e 2217 no container**. O arquivo de dados do projeto
é copiado para o volume na primeira inicialização (quando o volume estiver vazio).

```sh
git clone https://github.com/matheus-moreli/inventario-ativos-vulnerabilidades.git
cd inventario-ativos-vulnerabilidades
sudo docker build -t inventario-ativos-2217:1 .
sudo docker run -d --name inventario-2217 --restart unless-stopped \
  -p 2217:2217 -e INVENTARIO_PORTA=2217 \
  -v inventario-2217-dados:/app/dados inventario-ativos-2217:1
sudo docker ps --filter name=inventario-2217
curl --fail http://127.0.0.1:2217/saude
curl --fail http://127.0.0.1:2217/riscos
```

Para abrir o **menu completo** sem derrubar o serviço:

```sh
sudo docker exec -it inventario-2217 python app.py
```

Não executar duas sessões interativas que alterem os mesmos dados simultaneamente:
cada menu mantém a base em memória, podendo sobrescrever mudanças feitas em outra sessão.
O serviço HTTP relê o JSON e funciona em paralelo como consulta.

## Evidência das 24 horas

No início e após mais de 24 horas reais, coletar:

```sh
sudo docker inspect inventario-2217 --format \
'inicio={{.State.StartedAt}} ativo={{.State.Running}} reinicios={{.RestartCount}} saude={{.State.Health.Status}}'
sudo docker logs --tail 20 inventario-2217
curl --fail http://127.0.0.1:2217/saude
```

Verificar que é **o mesmo container**, com `RestartCount=0`, sem reinícios
e com tempo superior a 24 horas; guardar evidências com data/hora.
A publicação na porta 2217 não garante acesso externo: VPN/firewall precisam permitir.

## Modelo acadêmico

A matriz M (ativos por CVEs distintas), o vetor v (CVSS por CVE), a matriz A
(dependências), b=Mv e (I-A)x=b são derivados dos dados persistidos.
O índice de risco efetivo pode superar 10 e não é uma nota CVSS.
Vulnerabilidades corrigidas ainda participam do cálculo base por exigência do
modelo cadastral; risco residual seria uma análise separada.
Campos adicionais são descritivos e não alteram pesos matemáticos automaticamente.

## Limitações conscientes

- Inserir um novo *tipo* pelo terminal cria uma instância de uma subclasse
  personalizada genérica; criar nova subclasse com regras específicas exige código.
- A aplicação recebe CVSS informado pelo usuário e não calcula vetor CVSS oficial.
- O terminal tem navegação por setas e Esc/0 para voltar; cada formulário pode ser cancelado sem gravação.
- O modo HTTP oferece apenas /saude e /riscos, não CRUD remoto.
