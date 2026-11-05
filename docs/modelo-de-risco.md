# Modelo de risco e simulação

## O que é calculado

Cada ativo recebe dois valores. O **risco próprio** é a soma das notas CVSS das
vulnerabilidades cadastradas nele. O **risco efetivo** inclui também a parcela
de risco recebida dos ativos dos quais ele depende.

Não existe nota inventada pela interface. A aplicação usa as vulnerabilidades,
os pesos de dependência e operações básicas de álgebra linear para chegar ao
resultado.

## Matrizes e vetores

Os ativos ocupam as linhas da matriz de incidência `M`. Cada CVE ocupa uma
coluna. O elemento `M[i][j]` vale 1 quando o ativo `i` é afetado pelo CVE `j` e
0 quando não é. O vetor `v` guarda a nota CVSS de cada CVE.

O risco próprio é:

```text
b = Mv
```

Exemplo: se um notebook tem CVSS 4 e um servidor tem CVSS 6, então `b = [4, 6]`.
Se os dois ativos compartilhassem o mesmo CVE de nota 5, a mesma coluna teria
dois valores 1, pois a falha atinge os dois.

## Dependências

A matriz `A` guarda os pesos cadastrados no painel. `A[i][j] = 0,25` significa
que o ativo da linha `i` recebe 25% do risco efetivo do ativo da coluna `j`.

O sistema resolvido é:

```text
x = b + Ax
(I - A)x = b
```

`I` é a matriz identidade e `x` é o vetor de risco efetivo. O programa resolve
esse sistema por eliminação de Gauss. Ele não calcula uma inversa para obter o
resultado. Antes disso, verifica se `I - A` é invertível e mede o número de
condição na norma infinita. Um valor muito alto avisa que pequenas mudanças nos
pesos podem gerar grande variação no resultado.

### Exemplo conferível

Se o ativo 3 recebe 25% do risco do ativo 1 e o ativo 1 tem risco próprio 8:

```text
b = [8, 0, 0]
x1 = 8
x2 = 0
x3 = 0 + 0,25 * 8 = 2
```

Logo, `x = [8, 0, 2]`. Este mesmo cenário é coberto pelo teste automático
`test_simulacao_nao_altera_a_base_e_propagacao_e_conferivel`.

## Simulação no painel

Em **Gerenciar dependências e consultar riscos**, escolha **Simular
vulnerabilidade sem salvar**. Informe o ID do ativo e uma nota CVSS. A aplicação
acrescenta uma coluna temporária à matriz `M`, calcula os novos vetores e mostra
a diferença no ativo e nos demais que recebem risco por dependência.

A vulnerabilidade hipotética não é criada no inventário e o arquivo JSON não é
alterado. A seta para a esquerda cancela a operação; a seta para a direita só
avança após uma nota válida, inclusive aceitando `9,8` ou `9.8`.
