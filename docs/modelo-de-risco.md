# Cálculo de risco

| Símbolo | Dimensão | Significado |
|---|---|---|
| `M` | ativos × CVEs | `M[i,j] = 1` se o ativo i tem a CVE j. Uma CVE compartilhada ocupa uma só coluna. |
| `v` | CVEs | Notas CVSS na mesma ordem das colunas de `M`. |
| `F` | ativos × ativos | Diagonal com o fator de exposição de cada tipo de equipamento. |
| `b = F·Mv` | ativos | Risco próprio de cada ativo, já ponderado pela exposição. |
| `A` | ativos × ativos | `A[i,j]` é a fração do risco de j herdada por i. A diagonal é zero. |
| `x` | ativos | Risco efetivo, dado por `x = b + Ax`, ou `(I − A)x = b`. |

O índice de risco pode passar de 10 porque soma contribuições. Cada CVSS
continua entre 0 e 10. Os pesos de dependência são registrados separadamente.

## Fator de exposição por tipo (polimorfismo)

Cada classe de equipamento sobrescreve `fator_exposicao()`. O valor pondera o risco
próprio: `b = F·Mv`. A classe base devolve 1,0, que não altera o risco.

| Tipo | Fator | Motivo |
|---|---|---|
| Servidor, Roteador, Aplicação Web | 1,0 | Expostos a muitos acessos ou à borda da rede. |
| Banco de Dados | 0,8 | Normalmente atrás de firewall. |
| Software Licenciado | 0,7 | Roda em máquinas já protegidas. |
| Notebook | 0,6 | Rede interna e uso individual. |
| Tipo personalizado | 1,0 | Sem hipótese sobre a exposição. |

O fator não é gravado no JSON: o tipo do objeto o define. O restante do modelo não muda,
pois `(I − A)x = b` usa o `b` já ponderado. Os valores são hipóteses de ensino.

## Exemplo conferido com três equipamentos

Os exemplos abaixo e os testes de `TesteRisco` usam fator 1,0 em todos os tipos, como na aula.
Os testes de `TesteFatorExposicao` conferem à mão o caso com fatores diferentes.

Assuma três equipamentos e duas vulnerabilidades, de severidades 4 e 6:

```text
   [1 0]      [4]          [4]
M =[0 1]  v = [6]  b = Mv =[6]
   [0 0]                  [0]
```

O ativo 1 herda 50% do ativo 2. O ativo 2 herda 25% do ativo 1.
O ativo 3 herda 20% do ativo 1 e 30% do ativo 2.

```text
    [ 0     0,50  0 ]           [ 1    -0,50  0 ]
A = [ 0,25  0     0 ]   I − A = [-0,25  1     0 ]
    [ 0,20  0,30  0 ]           [-0,20 -0,30  1 ]
```

1. `x₁ = 4 + 0,5 x₂`.
2. `x₂ = 6 + 0,25 x₁`.
3. Substituindo a segunda equação na primeira, `x₁ = 7 + 0,125 x₁`.
   Logo, `0,875 x₁ = 7` e `x₁ = 8`.
4. `x₂ = 6 + 0,25 × 8 = 8`.
5. `x₃ = 0,20 × 8 + 0,30 × 8 = 4`. O ativo 3 tem risco próprio zero e herda quatro pontos.

| Vetor | Resultado |
|---|---|
| `b = Mv` | (4, 6, 0) |
| `Ax` | (4, 2, 4) |
| `x = b + Ax` | (8, 8, 4) |
| `(I − A)x − b` | (0, 0, 0) |

## Por que a solução existe e como é conferida

- **Soma dos pesos.** O cadastro exige soma menor que 1 em cada linha de
  `A`. A diagonal de `I − A` é 1, superior à soma dos módulos fora da
  diagonal. Essa dominância diagonal garante a invertibilidade.
- **Pivoteamento.** A eliminação troca linhas para usar o maior pivô em
  módulo na coluna. A fatoração `P(I − A) = LU` guarda essas operações
  para resolver o sistema por duas substituições.
- **Determinante e condicionamento.** O produto dos pivôs, corrigido
  pelo sinal das trocas, dá o determinante. No exemplo ele é 0,875.
  O número de condição informa a sensibilidade a perturbações. O programa
  reaproveita a mesma fatoração para obtê-lo.
- **Resíduo.** `‖(I − A)x − b‖∞` mede a maior diferença ao
  substituir a solução nas equações. Em ponto flutuante, um valor pequeno
  é esperado.
- **Simulação.** Com os mesmos pesos, acrescentar uma vulnerabilidade
  muda `b`. A variação efetiva obedece a `(I − A)Δx = Δb`.
  No exemplo, adicionar 2 ao próprio do ativo 1 resulta em
  `Δx = (16/7, 4/7, 22/35)`. A simulação preserva o JSON.

No menu de análise, **Matrizes, vetores e verificação** mostra os dados do
sistema. **Explicar a conta de um equipamento** mostra a soma CVSS, a
contribuição de cada dependência e o risco efetivo.
