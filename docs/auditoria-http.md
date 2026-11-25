# Auditoria defensiva do serviço HTTP

O inventário registra eventos **do próprio serviço HTTP na porta 2217**,
sem interceptar conexões SSH, sem tentar identificar alunos e sem capturar senhas.

## Registros persistentes

Ao iniciar com `python app.py --servico`, os eventos são gravados em
`/app/dados/auditoria-acessos.jsonl` dentro do volume Docker já utilizado.
Pode-se alterar o destino com `INVENTARIO_AUDITORIA_ARQUIVO`.

Cada linha JSON contém data UTC, IP observado na conexão, método HTTP,
rota (sem parâmetros de consulta), status HTTP e classificação.
GET /saude bem-sucedido do loopback interno é ignorado para não poluir
os logs com healthchecks. Cinco respostas de erro da mesma origem em
até 60 segundos emitem um alerta (com intervalo mínimo entre alertas).
O histórico rotaciona em arquivos de 512 KiB com até três backups,
limitando o uso de disco a aproximadamente 2 MiB.

As origens podem ser endereços internos de NAT, como `172.17.0.1`.
**IP não identifica uma pessoa**, e esse log não representa autenticação
SSH ou outros serviços hospedados na máquina.

## Consultar sem modificar

```bash
sudo docker exec inventario-2217 tail -n 20 /app/dados/auditoria-acessos.jsonl
```

Se nenhum acesso relevante aconteceu desde a atualização, o arquivo
ainda pode não existir. O log **não é publicado em endpoint HTTP**.
Não exponha IPs em relatórios públicos. Use retenção e acesso
restritos conforme regras da disciplina.

## Implantação

A funcionalidade só passa a operar quando uma nova imagem for construída
e o container for atualizado. Apenas executar `git pull` no host
**não modifica** o container já em funcionamento.
Preserve o volume `inventario-2217-dados` e registre uma nova evidência
da execução se o container for recriado; essa ação reinicia a contagem
de tempo da instância, mas não invalida evidências anteriores.

Antes de colocar monitoramento adicional na rede do
servidor compartilhado, obtenha autorização da administração.
