# Critérios de aceitação do CRUD — versão 1.0

Cada resultado é observável no inventário em memória e, após salvar/recarregar, no JSON. A revisão técnica do texto foi feita contra as regras do programa; a revisão por outro integrante solicitada em S2_06 permanece pendente.

| ID | Requisito | Dado | Quando | Então |
|---|---|---|---|---|
| CA-01 | RF-01 | ID 20 livre e campos válidos | cadastro ativo | objeto de classe do tipo escolhido é inserido sob chave 20 |
| CA-02 | RF-01 | ID ou nome já cadastrado | novo cadastro | erro de domínio é mostrado e coleção não muda |
| CA-03 | RF-02 | código de tipo válido | cadastro | classe derivada correta é criada; código fora do Enum é rejeitado |
| CA-04 | RF-03 | ativo ID 20 existe | consulta por ID | o mesmo objeto é retornado |
| CA-05 | RF-03 | ID 99 não existe | consulta por ID | resultado é `None`, sem criar registro |
| CA-06 | RF-04 | ativo 20 existe | atualizar apenas nome | novo nome aparece e ID/vulnerabilidades são mantidos |
| CA-07 | RF-04 | ativo 20 existe e nome de outro ativo é informado | atualizar nome | erro é retornado; todos os campos originais permanecem |
| CA-08 | RF-05 | ativo 20 existe | solicitar exclusão e cancelar | função retorna `False`; registro e vulnerabilidades continuam |
| CA-09 | RF-05 | ativo 20 existe e outro depende dele | confirmar exclusão | registro e suas vulnerabilidades desaparecem; dependência de terceiros é removida |
| CA-10 | RF-06, RF-07 | ativo 20 existe | cadastrar CVE válido | vulnerabilidade fica vinculada ao ativo e pode ser consultada |
| CA-11 | RF-06, RF-07 | ativo inexiste ou CVE já está no mesmo ativo | cadastrar vulnerabilidade | erro de domínio, sem novo registro |
| CA-12 | RF-08 | inventário válido | salvar e carregar | JSON é lista de objetos e subclasses são reconstituídas |
| CA-13 | RF-08 | arquivo JSON inválido | carregar | resultado `None`, arquivo original preservado |
| CA-14 | RF-09 | matriz de dependências válida | calcular riscos | `Mv` e solução de `(I-A)r=Mv` retornam na ordem dos IDs |
| CA-15 | RF-09 | `I-A` singular | calcular riscos | erro explícito impede resultado enganoso |
| CA-16 | RF-10 | container iniciado com `-dit` e volume persistente no servidor docente | usar menu, consultar/cadastrar ativo e verificar o mesmo container após 24 h | CRUD e riscos funcionam, JSON persiste, container segue ativo sem reinício; evidência ainda pendente |

Os cenários CA-01 a CA-09 cobrem ao menos dois casos de cada operação do CRUD: cadastro, consulta, atualização e exclusão. CA-10 a CA-16 cobrem vínculos, persistência, matemática e Docker.
