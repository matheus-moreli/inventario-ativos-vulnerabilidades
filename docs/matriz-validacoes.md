# Matriz campo × regra × erro — S2_05

| Campo | Regra | Mensagem de erro / resultado | Validador |
|---|---|---|---|
| ID ativo | inteiro estrito maior que zero e único | `ID deve ser um número inteiro maior que zero.` / `Já existe um ativo com esse ID.` | `cadastrar_ativo` |
| Nome/hostname | texto não vazio e único ignorando caixa e espaços laterais | `Nome ou hostname é obrigatório.` / `Já existe um ativo com esse nome ou hostname.` | `validar_texto`, `validar_nome_unico` |
| Responsável/localização | texto não vazio | `<campo> é obrigatório.` | `validar_texto` |
| Tipo | código existente em `TipoAtivo`; booleano não é código | `Tipo de ativo inválido.` | `validar_tipo_ativo` |
| Criticidade | valor de `CRITICIDADES` | `Criticidade inválida. Escolha uma opção permitida.` | `validar_opcao` |
| CVE | `CVE-AAAA-NÚMERO`, único por ativo | `CVE inválido...` / `Esta vulnerabilidade já foi cadastrada para o ativo.` | `validar_cve`, `buscar_vulnerabilidade` |
| CWE | `CWE-NÚMERO` | `CWE inválido. Use o formato CWE-NÚMERO.` | `validar_cwe` |
| CVSS | número de 0 a 10 inclusive, aceita vírgula decimal; rejeita NaN | `CVSS deve estar entre 0.0 e 10.0.` | `validar_cvss` |
| Data da fonte | data existente em `dd/mm/aaaa` | `Data inválida. Use o formato dd/mm/aaaa.` | `validar_data_fonte` |
| Fonte, impacto, tratamento, verificação | texto não vazio | `<campo> é obrigatório.` | `validar_texto` |
| Prioridade/status | item das listas permitidas | `<campo> inválida. Escolha uma opção permitida.` | `validar_opcao` |
| Status Corrigida | verificação diferente de Pendente | `Informe como a correção foi verificada antes de concluir.` | `cadastrar_vulnerabilidade`, `atualizar_vulnerabilidade` |
| Dependência | destino existente, diferente da origem, sem duplicata; peso 0 ≤ p < 1 e soma < 1 | erro de domínio correspondente | `adicionar_dependencia`, `validar_dependencias` |

Valores de fronteira relevantes: ID 0/1, CVSS 0/10/10,1, peso 0/1, soma de pesos imediatamente abaixo e exatamente igual a 1. Os testes automatizados verificam os caminhos críticos. A interface captura `DadosInvalidosError` e mostra mensagens de domínio, sem traceback para o usuário.
