# Evidência do programa completo no container por 24 horas

## Estado atual

O workflow `verificar.yml` executa testes Python e flake8. O build do Docker e a execução de 24 horas no servidor da disciplina ainda não têm resultado publicado. O procedimento abaixo mantém o **menu completo de cadastro, consulta, atualização, remoção, vulnerabilidades e riscos** aberto no container. O modo HTTP somente leitura não é usado como substituto do programa completo.

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

**Estado atual:** pendente de build e execução no servidor do docente. Não há evidência de 24 horas neste repositório.
