# Evidências de execução do Docker — Trabalho 2 (UFU)

**Consolidação:** 23/11/2026
**Projeto:** Inventário de Ativos e Vulnerabilidades — Sprints 3, 4 e 5
**Requisito:** aplicação em container Docker em execução por pelo menos 24 horas, em servidor estável.
**Origem dos dados:** saídas dos comandos `docker inspect`, `docker ps` e `curl /saude`, fornecidas pelo responsável pelo projeto. Este documento não é um log gerado automaticamente pelo Docker.

## 1. Histórico das versões

Horários convertidos de UTC para Brasília (UTC−03). Durações da V1 e V2 calculadas pela diferença entre `StartedAt` e `FinishedAt`. Duração da V3 obtida do campo `tempo_ativo_segundos` do serviço no momento da consulta.

| Versão | Imagem | Início em Brasília | Encerramento ou referência | Duração observada | Reinícios contabilizados |
|---|---|---|---|---|---:|
| V1 | `inventario-ativos-2217:1` | 10/11/2026 21:31:35 | 17/11/2026 19:43:31 | **6 dias, 22h, 11min e 56s** | 0 |
| V2 | `inventario-ativos-2217:2` | 17/11/2026 19:45:46 | 17/11/2026 20:19:00 | **33min e 14s** | 0 |
| V3 | `inventario-ativos-2217:3` | 17/11/2026 20:19:54 | consulta estimada em 23/11/2026 19:33:49 | **5 dias, 23h, 13min e 55s** | 0 |

**Soma dos períodos registrados:** 12 dias, 21h, 59min e 5s. **Não** representa uma execução contínua única: houve intervalos entre as versões. Cada uma das versões V1 e V3 **isoladamente** superou 24 horas.

## 2. Evidência primária — Docker inspect

Consulta realizada no servidor em 23/11/2026:

```text
Container=/inventario-2217-v1 | Criado=2026-11-11T00:31:34.92912098Z | Inicio=2026-11-11T00:31:35.07539976Z | Fim=2026-11-17T22:43:31.54419874Z | Estado=exited | Reinicios=0
Container=/inventario-2217-v2 | Criado=2026-11-17T22:45:46.716548256Z | Inicio=2026-11-17T22:45:46.946286998Z | Fim=2026-11-17T23:19:00.600821969Z | Estado=exited | Reinicios=0
Container=/inventario-2217 | Criado=2026-11-17T23:19:53.899774357Z | Inicio=2026-11-17T23:19:54.051038188Z | Fim=0001-01-01T00:00:00Z | Estado=running | Reinicios=0
```

Na V1 e V2, `exited` reflete a parada das versões antigas durante as atualizações planejadas; o código exato de saída não é necessário para comprovar a duração. O contador zero de reinícios indica apenas ausência de reinícios registrados pelo Docker nessas instâncias.

## 3. Evidência primária — resposta da API na V3

```json
{"estado": "ativo", "inicio_utc": "2026-11-17T23:19:54.541723+00:00", "tempo_ativo_segundos": 515635, "ativos": 6}
```

**Conversão:** 515.635 segundos = 5 dias, 23 horas, 13 minutos e 55 segundos. A data da consulta foi inferida a partir do horário interno de início somado ao tempo ativo informado; não é um carimbo externo independente.

Na listagem `docker ps -a` de 23/11, a V3 aparecia como `Up 5 days (healthy)`, publicada somente em `127.0.0.1:2217->2217/tcp`. O volume `inventario-2217-dados` estava montado em `/app/dados`.

## 4. Verificações funcionais anteriores

- O serviço informou **6 ativos** na base persistente.
- A V3 passou **83 testes**, com **2 ignorados** por serem específicos do Windows (85 testes no total).
- `/riscos` retornou `HTTP 401` sem a credencial e `HTTP 200` com credencial correta.
- A rota-isca `/admin` retornou `HTTP 404` e produziu `alerta_rota_isca` no registro de auditoria.
- `inventario.json` e `auditoria-acessos.jsonl` foram verificados com permissões `600` durante a V2.
- As versões antigas foram preservadas como `inventario-2217-v1` e `inventario-2217-v2` para consulta histórica.

**Limitação:** as verificações funcionais acima foram observadas em momentos específicos. Elas não demonstram ausência total de interrupções, conectividade externa ou disponibilidade de toda a infraestrutura compartilhada.

## 5. Como o avaliador pode verificar, sem alterar o ambiente

Em sessão autorizada no servidor da UFU:

```bash
sudo docker inspect inventario-2217-v1 inventario-2217-v2 inventario-2217 --format 'Container={{.Name}} | Imagem={{.Config.Image}} | Inicio={{.State.StartedAt}} | Fim={{.State.FinishedAt}} | Estado={{.State.Status}} | Reinicios={{.RestartCount}}'
```

```bash
curl -s http://127.0.0.1:2217/saude
```

O segundo comando retorna o estado e a duração **atuais**, que naturalmente serão diferentes dos valores históricos citados aqui.

## 6. Escopo e integridade

Este registro foi consolidado com base em resultados de terminal apresentados em 23/11/2026. O commit deste documento **não prova sozinho** a execução do serviço; os dados de `docker inspect` e do endpoint `/saude` são as evidências técnicas reproduzíveis. Nenhuma credencial, senha, log de terceiros ou conteúdo do inventário foi incluído. Esta documentação não exige modificar código, recriar containers ou interromper a aplicação.
