# Interface de terminal unificada

A interface principal é `apresentacao/interface_rica.py`. Ela **não chama**
`apresentacao/interface.py`, que é conservada apenas para compatibilidade com
testes e exercícios anteriores. Todos os menus e formulários novos usam
`apresentacao/navegacao.py` e a mesma apresentação visual.

## Atalhos

- ↑/↓: mover pelos menus; Enter: escolher; Esc ou 0: voltar.
- Em qualquer campo: Esc ou Ctrl+C cancela a **operação inteira**, sem
  persistir mudanças. Também é possível digitar `/cancelar` ou `/voltar`.
- Na edição, escolha **Salvar alterações** e confirme; Esc descarta o rascunho.
- Exclusões exigem uma confirmação própria, com padrão "Cancelar".
- Campos de texto em Windows PowerShell e terminal Linux usam prompt_toolkit;
  em execução sem TTY, o programa aceita a escolha numérica.
- Quando um formulário acaba, a alteração é validada em uma cópia da base e
  gravada atomicamente no JSON. Só depois o inventário em memória é atualizado.
  Cancelamentos não alteram nem a memória nem o JSON.

## Risco

Toda vez que ocorre uma alteração, o sistema reconstrói as matrizes M e A,
o vetor v e os riscos próprio e efetivo a partir do rascunho **antes de salvar**.
Se o cálculo falhar, o arquivo anterior permanece. O painel também refaz o
cálculo a cada exibição para evitar dados obsoletos.

O índice de risco **não é nota CVSS**, e pode superar 10. Campos adicionais
são descritivos e não afetam a fórmula do Trabalho 2.

## Executar

```powershell
py -m pip install -r requirements.txt
py -m unittest -v
py app.py
```

O atalho `py` é próprio do Windows; no Linux use `python3`.
Também funciona em Docker com `sudo docker exec -it inventario-2217 python app.py`.

## Testes

`test_interface_nova.py` verifica cadastro completo, tipo personalizado,
rollback ao cancelar em meio ao cadastro/edição, falha de persistência,
recalcular risco ao adicionar/remover vulnerabilidades e leitura não
interativa de menus. O GitHub Actions deve passar testes Python e smoke Docker
antes do merge.

O teste de teclado com setas em um PowerShell real e o funcionamento
ininterrupto por 24 horas são verificações manuais, não substituídas pelo CI.
