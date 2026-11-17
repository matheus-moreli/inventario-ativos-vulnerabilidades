# Duas camadas: rotas-isca e senha na API

Implementação **restrita à aplicação HTTP própria na porta 2217**.
Não intercepta SSH, conexões de outros alunos ou dados de outras portas.
As rotas-isca `/admin`, `/login`, `/wp-admin`, `/painel` e `/.env`
retornam 404 e geram `alerta_rota_isca` no JSONL, sem pedir
ou armazenar credenciais. **Honeypot é um alerta, não um bloqueio.**

A rota `/riscos` exige um cabeçalho `Authorization: Bearer <senha>`.
Sem a senha correta, responde 401; `/saude` permanece acessível
sem senha para a verificação de saúde do Docker.

## Preparar a senha antes da troca de container

A senha é lida do arquivo `/app/dados/senha-acesso` no volume
`inventario-2217-dados`. Se não existir ou estiver vazio, a
**nova versão não inicia** (falha fechada).

Criar no container v2 atual, digitando a senha sem eco no terminal:

```bash
sudo docker exec -it inventario-2217 python -c 'import getpass,os; p="/app/dados/senha-acesso"; s=getpass.getpass("Senha de acesso: "); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600); os.write(fd,s.encode()); os.close(fd); os.chmod(p,0o600)'
```

O arquivo continua persistente após recriar o container. **Não**
grave senhas no Git, na linha de comandos ou em URLs.

Para implantação, teste primeiro a nova imagem separadamente,
sem mexer na v2. Depois pare a v2 e rode com publicação no loopback:

```bash
sudo docker run -d --name inventario-2217 --restart unless-stopped -p 127.0.0.1:2217:2217 -e INVENTARIO_PORTA=2217 -v inventario-2217-dados:/app/dados inventario-ativos-2217:3
```

Com a porta no loopback, para acessar de outro computador da UFU,
use um túnel SSH autenticado:
```bash
ssh -L 2217:127.0.0.1:2217 12621CBS217@10.0.99.150
```

Depois faça o pedido pelo `http://127.0.0.1:2217` na estação
que abriu o túnel, passando o cabeçalho Authorization. O túnel
protege a senha em trânsito. **Não** envie a senha por HTTP em
texto claro diretamente pela rede da faculdade.

**Nota:** senha curta ou previsível, incluindo `Camila123`,
não é segura; escolha uma senha única e forte. Esta proteção
se aplica **à API HTTP**, não ao acesso via SSH, `docker exec`
ou aos administradores do host compartilhado.

A trilha de auditoria não guarda cabeçalhos nem parâmetros de URL.
O IP registrado pode ser o da ponte Docker, não o usuário real.
