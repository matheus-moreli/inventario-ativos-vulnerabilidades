# Evidência de execução no servidor da UFU

| Data | Registro | Resultado |
|---|---|---|
| 12/11/2026 | Percurso da Sprint 4, cards S4_15–S4_20. O registro original foi salvo como `~/evidencia-24h-2217.txt` no servidor. | Contêiner `inventario-2217` iniciado em 10/11. Na coleta, 46 h 26 min 14 s de atividade, zero reinicializações, estado saudável, HTTP 200 e seis ativos. |
| 17/11/2026 | Transcrição do terminal da UFU, comando `sudo docker run --rm inventario-ativos-2217:3 python app.py --testes`. | 85 testes, 83 aprovados e dois pulados por serem específicos do Windows. O comando executa um contêiner temporário de testes. |

Registros consultados: `percursos_sprint4_duas_folhas.pdf` e a transcrição do terminal de 17/11 às 23h16 UTC.

A coleta de 23/11 ampliou o registro. A V1 chegou a 6 dias, 22 h, 11 min e
56 s. A V3 estava ativa havia 5 dias, 23 h, 13 min e 55 s. Cada versão
superou 24 horas por conta própria. **O requisito do Trabalho 2 já tem
evidência para a versão publicada.** As [saídas do servidor de 23/11](evidencias-docker-2026-11-23.md)
foram registradas no [commit `ecf4571`](https://github.com/matheus-moreli/inventario-ativos-vulnerabilidades/commit/ecf4571e882e659ab8be29596e34dcdf1e3e3924).

## Implantação definitiva — 25/11/2026

- Commit da aplicação: bb40a384.
- Container: trab02_2026_2_12621cbs217.
- Imagem: f08d46e482ff.
- Porta: 2217.
- Backup JSON validado e restaurado.
- Seis ativos recuperados.
- Falha inicial de autenticação identificada e corrigida.
- Início definitivo: 25/11/2026 às 21:27:21 (Brasília).
- Estado inicial: healthy, zero reinicializações.
- Monitoramento automático a cada 60 segundos.
- Containers anteriores preservados para avaliação.
- Previsão de conclusão das 24 horas: 26/11/2026 às 21:27:21.

A comprovação das 24 horas da versão definitiva permanece pendente até a coleta final.
