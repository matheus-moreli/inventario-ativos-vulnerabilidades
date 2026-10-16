# Dois CVEs reais para os exercícios S2_12 e S2_13

Consulta das fontes oficiais em 13/10/2026. Os ativos do arquivo demonstrativo são fictícios; a associação abaixo **não afirma que algum equipamento real foi afetado**. Para confirmar um achado seria preciso identificar produto, versão e configuração.

## CVE-2019-0708 — Remote Desktop Services

O registro [NVD CVE-2019-0708](https://nvd.nist.gov/vuln/detail/CVE-2019-0708) descreve execução remota de código no Remote Desktop Services de versões antigas do Windows. A NVD classifica a fraqueza como CWE-416 (use after free) e lista sistemas afetados, incluindo Windows 7 SP1 e Windows Server 2008. A gravidade alta exige checar a versão instalada e se RDP está exposto. No inventário didático, o notebook `NB-LAB-01` só pode ser considerado vulnerável se usar versão afetada; o JSON é uma simulação. Tratamento: aplicar correção do fornecedor e restringir acesso remoto; verificação: conferir versão/patch e testar exposição. Fonte complementar primária: [aviso da Microsoft](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708).

## CVE-2021-44228 — Apache Log4j2

O registro [NVD CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) descreve falha de execução remota ligada a JNDI no `log4j-core` quando dados controlados por atacante chegam a mensagens/parâmetros de log em configurações afetadas. A NVD reúne classificações CWE de fontes distintas, entre elas CWE-917 e CWE-502; o JSON de exemplo usa CWE-502. O servidor `SRV-WEB-01` é somente um exemplo: é necessário confirmar a biblioteca e a versão empacotadas na aplicação. Tratamento: atualizar para versão corrigida compatível com a linha usada e revisar dependências transitivas. Verificação: inventário de componentes, versão instalada e teste controlado conforme orientação do fornecedor. Fonte primária: [orientação do Apache Log4j](https://logging.apache.org/log4j/2.x/security.html).

## Aplicação ao cadastro

Nos dois casos, o programa guarda CVE, CWE, CVSS, descrição, fonte, data, impacto, prioridade, tratamento, status e método de verificação. O CVSS é um dado da fonte e pode mudar com nova análise; a prioridade local considera também criticidade e exposição do ativo. O sistema valida formato e faixa da nota, mas não consulta a NVD automaticamente nem prova que o ativo está vulnerável.
