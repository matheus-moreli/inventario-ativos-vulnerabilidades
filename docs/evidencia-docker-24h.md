# Evidência do programa completo no container por 24 horas

## Estado atual

O workflow `verificar.yml` executa testes Python e flake8. Em 13/10/2026, o Docker Desktop deste PC foi localizado. A imagem candidata foi construída localmente, executou 50 testes no container (2 testes específicos de Windows foram pulados no Linux), e uma execução temporária respondeu a `/saude` e `/riscos` com seis ativos e chegou ao estado `healthy`. Isso prova build e funcionamento básico, mas não comprova 24 horas. O procedimento abaixo mantém o **menu completo de cadastro, consulta, atualização, remoção, vulnerabilidades e riscos** aberto no container. O modo HTTP somente leitura não é usado como substituto do programa completo.

O container local anterior `inventario-ativos-24h` iniciou em **13/10/2026 11:24:50 BRT** e ainda estava ativo, com **zero reinícios**, na coleta de **13/10/2026 21:42 BRT** (aproximadamente 10 h 17 min). Sua imagem contém código anterior à PR #3. Ele foi preservado; essa contagem não vale como prova da versão nova nem da hospedagem no servidor do docente.

Depois dos testes e da revisão, a versão nova do commit `3395957` iniciou em outro container local, `inventario-ativos-trabalho2-novo`, em **13/10/2026 21:46:48 BRT** (`2026-10-14T00:46:48.968560529Z`). Ela usa `python app.py`, volume próprio `inventario-trabalho2-novo-dados` e política `unless-stopped`. A primeira inspeção registrou `running=true`, `RestartCount=0`, seis ativos no JSON e o menu completo nos logs. A marca de 24 horas desta versão só poderá ser aferida após **14/10/2026 21:46:48 BRT**, desde que permaneça sem reinícios. Essa execução é no PC do aluno, não no servidor do docente.

## Execução no servidor da disciplina

No servidor disponibilizado pelo docente, com Docker e uma cópia da branch aprovada:

```sh
docker build -t inventario-ativos .
docker run -dit --no-healthcheck --name inventario-ativos-24h \
  --restart unless-stopped -v inventario-dados:/app/dados \
  inventario-ativos python app.py
docker inspect inventario-ativos-24h \
  --format 'inicio={{.State.StartedAt}} ativo={{.State.Running}} reinicios={{.RestartCount}} imagem={{.Image}}'
docker logs inventario-ativos-24h
```

A opção `-dit` mantém a entrada e um terminal abertos; o menu fica aguardando comandos em vez de receber EOF. `--no-healthcheck` desativa o teste HTTP da imagem, pois esse modo usa o terminal, não a rota `/saude`. O volume nomeado preserva o JSON e evita permissão de escrita incompatível com o UID não privilegiado do container.

Para demonstrar as operações, execute `docker attach inventario-ativos-24h`, use o menu e desprenda-se com **Ctrl+P, Ctrl+Q**. Não escolha `Sair` nem interrompa o processo durante as 24 horas. Confirme após uma alteração que o JSON persistido contém o novo registro:

```sh
docker exec inventario-ativos-24h python -c "import json; print(len(json.load(open('/app/dados/inventario.json', encoding='utf-8'))))"
```

Após pelo menos 24 horas no mesmo servidor, recolha novamente:

```sh
docker inspect inventario-ativos-24h \
  --format 'inicio={{.State.StartedAt}} ativo={{.State.Running}} reinicios={{.RestartCount}} imagem={{.Image}}'
docker logs inventario-ativos-24h
```

Guarde as duas saídas completas, horário da coleta, identificação do servidor e um registro da operação de CRUD feita via menu. O critério de aceite é: mesmo container e imagem, início há pelo menos 24 horas, `ativo=true`, `reinicios=0`, menu funcional e dados persistidos. Um reinício durante o período recomeça a contagem. Credenciais e dados privados do servidor não devem aparecer na evidência pública.

**Estado atual:** build, testes, serviço HTTP e menu completo locais verificados; versão nova em execução no Docker Desktop. Ainda faltam 24 horas verificadas e a hospedagem no servidor do docente. Não há evidência de 24 horas neste repositório.
