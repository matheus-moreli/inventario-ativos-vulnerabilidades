# Especificação resumida - Sprint 2

Este documento reúne a evidência pedida nos cards S2_04, S2_06, S2_07, S2_12 e S2_14. Ele descreve o programa que está no repositório; não cria funcionalidades escondidas.

## Escopo e termos

- **Ativo:** equipamento, sistema ou serviço acompanhado pela organização.
- **Vulnerabilidade:** fragilidade associada a um ativo.
- **CVE:** identificador público de uma vulnerabilidade conhecida.
- **CWE:** categoria de fraqueza.
- **CVSS:** nota de 0 a 10 para ajudar na avaliação de impacto.

O programa funciona no terminal, salva os dados em `dados/inventario.json` e não armazena senhas, chaves ou tokens. Interface gráfica, login, varredura automática e consulta automática a APIs estão fora do escopo.

## Requisitos e critérios de aceite

| Requisito | Regra verificável | Como conferir |
| --- | --- | --- |
| Cadastrar ativo | ID inteiro, positivo e único; nome, responsável e localização obrigatórios; tipo e criticidade padronizados | Cadastre um ativo e tente repetir o mesmo ID |
| Consultar ativo | Busca por ID ou filtros de nome, tipo e criticidade sem alterar a base | Faça uma consulta e depois liste os ativos |
| Atualizar ativo | O ID não muda; só campos permitidos podem mudar; a mudança entra no histórico | Atualize o responsável e consulte o mesmo ID |
| Excluir ativo | O alvo é mostrado; só é removido após `SIM`; vulnerabilidades ligadas a ele saem junto | Cancele uma remoção e depois confirme outra |
| Cadastrar vulnerabilidade | O ativo precisa existir; CVE, CWE e CVSS precisam ter formato válido; prioridade e status são escolhas padronizadas | Informe CVE ou CVSS inválido e veja a mensagem sem o programa encerrar |
| Consultar vulnerabilidade | Filtros locais por CVE, prioridade e status não alteram os dados | Consulte e confirme o mesmo registro depois |
| Atualizar/remover vulnerabilidade | O CVE identifica a vulnerabilidade dentro do ativo; remoção exige confirmação; alterações entram no histórico | Atualize o status e remova com e sem confirmação |

## Cenários de aceite

1. Com uma base vazia, ao cadastrar o ativo `10`, ele aparece na busca por ID. Ao tentar cadastrar outro ativo `10`, o programa mostra uma mensagem de ID duplicado.
2. Com um ativo cadastrado, ao incluir `CVE-2021-44228` com CVSS `10.0`, a vulnerabilidade aparece na consulta. Ao informar CVSS `11` ou `nan`, o cadastro é recusado sem encerrar o menu.
3. Com uma vulnerabilidade registrada, ao mudar seu status para `Em tratamento`, a consulta mostra o novo status e o histórico registra a ação.
4. Ao pedir remoção de uma vulnerabilidade e responder algo diferente de `SIM`, nada é apagado. Com `SIM`, o registro deixa de aparecer na consulta.
5. Se o JSON estiver inválido, o programa avisa e encerra sem salvar uma base vazia por cima do arquivo existente.

Esses cenários são observáveis no terminal e os principais casos também estão em `test_sprint2.py`.

## Consulta externa usada como referência

O programa não busca vulnerabilidades automaticamente na internet: o cadastro é manual para manter o trabalho simples e funcionar sem conexão. Como exemplo de consulta externa, foi verificado em 24/09/2026 o registro [CVE-2021-44228 no NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-44228): vulnerabilidade do Apache Log4j, CVSS 10.0 e gravidade crítica. Esse exemplo mostra de onde podem vir CVE, CWE, CVSS, fonte e data; antes de cadastrar, é preciso confirmar se o ativo realmente usa o software afetado.

## Roteiro curto de demonstração

1. Execute `python app.py`.
2. Cadastre um servidor usando a opção 1.
3. Cadastre uma vulnerabilidade usando a opção 6.
4. Consulte-a na opção 7 e altere-a na opção 10.
5. Teste o cancelamento e a confirmação da remoção na opção 11.
6. Saia pela opção 0, abra de novo o programa e consulte o ativo para demonstrar o JSON.
