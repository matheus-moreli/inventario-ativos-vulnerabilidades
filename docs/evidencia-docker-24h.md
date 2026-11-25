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

A pendência é validar o Compose da revisão local. Se ela for implantada,
o [guia de implantação](implantacao-2217.md) mostra como registrar o ID,
a imagem, o horário de início, o estado e os reinícios da nova instância.
