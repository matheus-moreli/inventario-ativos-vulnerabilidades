# Evidência do container por 24 horas

## O que já pode ser verificado

O workflow `verificar.yml` constrói a imagem, inicia o container, consulta `/saude` e `/riscos` e confirma que o processo continua em execução. Essa verificação dura minutos e **não comprova 24 horas**.

## Execução no servidor da disciplina

No servidor disponibilizado pelo docente, com Docker e uma cópia deste repositório:

```sh
docker build -t inventario-ativos .
docker run -d --name inventario-ativos-24h --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v "$PWD/dados:/app/dados" inventario-ativos
curl -fsS http://127.0.0.1:8080/saude
```

Grave o identificador da imagem, horário de início e estado do container. Após pelo menos 24 horas corridas no mesmo servidor, sem reinício do container, repita a coleta:

```sh
docker image inspect inventario-ativos --format '{{.Id}}'
docker inspect inventario-ativos-24h \
  --format 'inicio={{.State.StartedAt}} ativo={{.State.Running}} reinicios={{.RestartCount}} saude={{.State.Health.Status}}'
curl -fsS http://127.0.0.1:8080/saude
curl -fsS http://127.0.0.1:8080/riscos
```

Guarde as duas saídas completas e a identificação do servidor. O critério de aceite é: mesmo container e imagem, intervalo superior a 24 horas entre início e coleta final, `ativo=true`, `reinicios=0`, `saude=healthy`, e consultas respondendo corretamente. Um `restart` durante o período reinicia a contagem. Credenciais e dados privados do servidor não devem aparecer na evidência pública.

**Estado atual:** pendente de execução no servidor do docente. Não há evidência de 24 horas neste repositório.
