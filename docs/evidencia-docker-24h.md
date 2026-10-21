# Evidência do programa completo no container por 24 horas

## Estado atual

O workflow `verificar.yml` executa testes Python e flake8. Em 13/10/2026, o Docker Desktop deste PC foi localizado. A imagem final `4e9d6ad` foi construída localmente, executou 53 testes no container (2 testes específicos de Windows foram pulados no Linux), e uma execução temporária respondeu a `/saude` e `/riscos` com seis ativos e chegou ao estado `healthy`. Isso prova build e funcionamento básico, mas não comprova 24 horas. O procedimento abaixo mantém o **menu completo de cadastro, consulta, atualização, remoção, vulnerabilidades e riscos** aberto no container. O modo HTTP somente leitura não é usado como substituto do programa completo.

O container local anterior `inventario-ativos-24h` iniciou em **13/10/2026 11:24:50 BRT** e ainda estava ativo, com **zero reinícios**, na coleta de **13/10/2026 21:42 BRT** (aproximadamente 10 h 17 min). Sua imagem contém código anterior à PR #3. Ele foi preservado; essa contagem não vale como prova da versão nova nem da hospedagem no servidor do docente.

Depois dos testes e da revisão, a versão nova do commit `3395957` iniciou em outro container local, `inventario-ativos-trabalho2-novo`, em **13/10/2026 21:46:48 BRT** (`2026-10-14T00:46:48.968560529Z`). Ela usa `python app.py`, volume próprio `inventario-trabalho2-novo-dados` e política `unless-stopped`. A primeira inspeção registrou `running=true`, `RestartCount=0`, seis ativos no JSON e o menu completo nos logs. Essa execução é no PC do aluno, não no servidor do docente.

Após conferir o material de risco da aula, o commit final `4e9d6ad` iniciou em um **terceiro container isolado**, `inventario-ativos-trabalho2-aula`, em **13/10/2026 22:06:25 BRT** (`2026-10-14T01:06:25.405335648Z`). Usa `python app.py`, imagem `inventario-ativos-trabalho2:4e9d6ad`, volume exclusivo `inventario-trabalho2-aula-dados` e política `unless-stopped`. A inspeção inicial mostrou `running=true`, `RestartCount=0`, seis ativos no JSON e menu completo nos logs. Os dois containers anteriores foram preservados.

### Conferência de 19/10/2026

Na conferência automática de **19/10/2026 às 22:14 BRT**, a API do Docker Desktop estava indisponível (`dockerDesktopLinuxEngine` sem pipe). O aplicativo Docker Desktop foi iniciado para inspecionar o estado persistido, sem remover containers nem volumes. A inspeção posterior do container final mostrou:

- mesmo ID `3eb83a71dad6c7dadd343be9c8065b9591e758d8e18d3f4c789ca5ad34c815f6` e imagem `inventario-ativos-trabalho2:4e9d6ad`;
- `State.StartedAt=2026-10-20T01:15:22.961694147Z` (**19/10/2026 22:15:22 BRT**), `Running=true` e `RestartCount=0`;
- logs com duas inicializações do menu completo e JSON do volume com seis ativos.

O `StartedAt` mudou em relação a 13/10. Portanto, **não há prova de 24 horas contínuas da execução iniciada em 13/10**, apesar do ID e da imagem preservados e do contador de reinícios em zero. O contador sozinho não comprova continuidade após reiniciar o Docker Desktop. Não há evidência de quando o Docker Desktop ficou indisponível; não se afirma a duração da execução anterior.

### Conferência de 20/10/2026

Em **20/10/2026 às 22:18 BRT**, após mais de 24 horas corridas desde a inspeção anterior, a API do Docker Desktop estava novamente indisponível. O aplicativo foi aberto apenas para inspecionar o estado persistido. O mesmo ID e imagem voltaram com `State.StartedAt=2026-10-21T01:19:12.638904366Z` (**20/10/2026 22:19:12 BRT**), `Running=true` e `RestartCount=0`. Os logs mostram três inicializações do menu completo; o JSON do volume ainda contém seis ativos. A execução iniciada em 19/10 **também não tem prova de 24 horas contínuas**. A próxima contagem só pode ser conferida após **21/10/2026 22:19:12 BRT**, se o `StartedAt` permanecer igual. Não se conhece o instante em que o Docker Desktop parou; não se atribui duração à execução anterior.

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

**Estado atual:** build, testes, serviço HTTP e menu completo locais verificados; versão final `4e9d6ad` novamente em execução no Docker Desktop desde 20/10 às 22:19:12 BRT. Ainda faltam 24 horas contínuas verificadas dessa execução e a hospedagem no servidor do docente. Não há evidência de 24 horas neste repositório.
