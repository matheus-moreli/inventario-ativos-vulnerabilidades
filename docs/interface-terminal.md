# Interface de terminal unificada

A interface fica em `apresentacao/interface_rica.py`, com as telas de vulnerabilidades,
dependências e risco em `telas_vulnerabilidades.py`, `telas_dependencias.py` e `telas_risco.py`.
Os menus e formulários
usam `apresentacao/navegacao.py` para tratar teclas, entradas e cancelamento.

## Atalhos

- ↑/↓: mover pelos menus; Enter: escolher; Esc ou 0: voltar.
- Em qualquer campo: Esc ou Ctrl+C cancela a **operação inteira**, sem
  persistir mudanças. Também é possível digitar `/cancelar` ou `/voltar`.
- Na edição, escolha **Salvar alterações** e confirme; Esc descarta o rascunho.
- Exclusões exigem uma confirmação própria, com padrão "Cancelar".
- Campos de texto em Windows PowerShell e terminal Linux usam prompt_toolkit;
  em execução sem TTY, o programa aceita a escolha numérica.
- Para usar o modo numérico em um terminal com problemas de renderização,
  defina `INVENTARIO_MENU=simples`. No PowerShell, execute
  `$env:INVENTARIO_MENU = 'simples'` antes de abrir o programa.
- Quando um formulário acaba, a alteração é validada em uma cópia da base e
  gravada atomicamente no JSON. Só depois o inventário em memória é atualizado.
  Cancelamentos não alteram nem a memória nem o JSON.

## Risco

Em **Vulnerabilidades**, a busca filtra por CVE, equipamento, situação ou
prioridade. Nas listas, use as opções de página para percorrer a base. Em
terminais estreitos, a listagem usa um conjunto menor de colunas e a ficha
continua disponível para consultar detalhes.

Em **Dependências**, é possível alterar o peso de um vínculo existente. A
mudança só é gravada se o novo peso e a soma dos pesos passarem na validação.

Toda vez que ocorre uma alteração, o sistema reconstrói as matrizes M e A,
o vetor v e os riscos próprio e efetivo a partir do rascunho **antes de salvar**.
Se o cálculo falhar, o arquivo anterior permanece. O painel também refaz o
cálculo a cada exibição para evitar dados obsoletos.

O índice de risco **não é nota CVSS**, e pode superar 10. Campos adicionais
são descritivos e não afetam a fórmula do Trabalho 2.
O resumo ordena os equipamentos por risco efetivo. Matrizes largas podem
ser percorridas em blocos de colunas.

## Executar

```powershell
.\iniciar.bat
.\iniciar.bat --testes
```

Em Docker, use `docker compose exec inventario python app.py`.

## Testes

`tests/test_interface_rica.py` verifica cadastro completo, tipo personalizado,
rollback ao cancelar em meio ao cadastro/edição, falha de persistência,
recalcular risco ao adicionar/remover vulnerabilidades e leitura não
interativa de menus. O GitHub Actions deve passar testes Python e smoke Docker
antes do merge.

Os testes de teclado acionam os atalhos registrados. A duração em Docker é
verificada separadamente pelos registros do servidor.
