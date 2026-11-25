"""Cálculo do risco próprio e efetivo pedido no Trabalho 2."""

import math
import sys

EPSILON = 0.000000000001


def ativos_ordenados(ativos):
    """Mantém linhas e colunas das matrizes na mesma ordem dos IDs."""
    return [ativos[identificador] for identificador in sorted(ativos)]


def montar_matriz_incidencia(ativos):
    """Uma coluna por CVE; ela pode afetar mais de um equipamento."""
    lista_ativos = ativos_ordenados(ativos)
    vulnerabilidades = []
    por_cve = {}
    for ativo in lista_ativos:
        for vulnerabilidade in ativo.vulnerabilidades:
            anterior = por_cve.get(vulnerabilidade.cve)
            if anterior is None:
                por_cve[vulnerabilidade.cve] = vulnerabilidade
                vulnerabilidades.append(vulnerabilidade)
            elif not math.isclose(anterior.cvss, vulnerabilidade.cvss, rel_tol=0, abs_tol=1e-9):
                raise ValueError(
                    f"CVE {vulnerabilidade.cve} tem notas CVSS diferentes entre ativos."
                )

    matriz = []
    for ativo in lista_ativos:
        cves_do_ativo = {item.cve for item in ativo.vulnerabilidades}
        matriz.append([1 if item.cve in cves_do_ativo else 0 for item in vulnerabilidades])
    return lista_ativos, vulnerabilidades, matriz


def produto_matriz_vetor(matriz, vetor):
    """Multiplica uma matriz por um vetor usando apenas operações básicas."""
    resultado = []
    for linha in matriz:
        soma = 0
        for indice, valor in enumerate(linha):
            soma += valor * vetor[indice]
        resultado.append(soma)
    return resultado


def aplicar_exposicao(lista_ativos, proprio):
    """Pondera cada risco próprio pelo fator do tipo; o tipo decide o valor."""
    return [ativo.fator_exposicao() * risco for ativo, risco in zip(lista_ativos, proprio)]


def montar_matriz_dependencias(lista_ativos):
    """A[i][j] é a fração do risco do ativo j transmitida ao ativo i."""
    indices = {ativo.id: indice for indice, ativo in enumerate(lista_ativos)}
    matriz = [[0.0 for _ in lista_ativos] for _ in lista_ativos]
    for indice, ativo in enumerate(lista_ativos):
        for dependencia in ativo.dependencias:
            matriz[indice][indices[dependencia["ativo_id"]]] = dependencia["peso"]
    return matriz


def identidade_menos(matriz):
    """Monta I - A, sistema usado para calcular o risco efetivo."""
    tamanho = len(matriz)
    return [
        [(1.0 if linha == coluna else 0.0) - matriz[linha][coluna] for coluna in range(tamanho)]
        for linha in range(tamanho)
    ]


class SistemaLinear:
    """Fatora P S = L U uma vez por Gauss com pivoteamento parcial."""

    def __init__(self, matriz):
        tamanho = len(matriz)
        self.lu = [list(linha) for linha in matriz]
        self.ordem = list(range(tamanho))
        sinal = 1
        for coluna in range(tamanho):
            pivo = max(range(coluna, tamanho), key=lambda i: abs(self.lu[i][coluna]))
            if abs(self.lu[pivo][coluna]) < EPSILON:
                raise ValueError("Não é possível calcular o risco: I - A não é invertível.")
            if pivo != coluna:
                self.lu[coluna], self.lu[pivo] = self.lu[pivo], self.lu[coluna]
                self.ordem[coluna], self.ordem[pivo] = self.ordem[pivo], self.ordem[coluna]
                sinal = -sinal
            for linha in range(coluna + 1, tamanho):
                fator = self.lu[linha][coluna] / self.lu[coluna][coluna]
                self.lu[linha][coluna] = fator
                for item in range(coluna + 1, tamanho):
                    self.lu[linha][item] -= fator * self.lu[coluna][item]
        self.determinante = sinal * math.prod(self.lu[i][i] for i in range(tamanho))
        self.norma = max((sum(map(abs, linha)) for linha in matriz), default=0.0)

    def resolver(self, vetor):
        """Resolve L y = P b e U x = y por substituição."""
        tamanho = len(self.ordem)
        solucao = [vetor[i] for i in self.ordem]
        for i in range(tamanho):
            solucao[i] -= sum(self.lu[i][j] * solucao[j] for j in range(i))
        for i in range(tamanho - 1, -1, -1):
            soma = sum(self.lu[i][j] * solucao[j] for j in range(i + 1, tamanho))
            solucao[i] = (solucao[i] - soma) / self.lu[i][i]
        return solucao

    def condicionamento(self):
        """Obtém ||S⁻¹||∞ resolvendo S z = eⱼ para cada vetor da base."""
        tamanho = len(self.ordem)
        if not tamanho:
            return 1.0
        somas = [0.0] * tamanho
        for j in range(tamanho):
            coluna = self.resolver([float(i == j) for i in range(tamanho)])
            for i, valor in enumerate(coluna):
                somas[i] += abs(valor)
        return self.norma * max(somas)


class AnalisadorRisco:
    """Calcula o risco dos objetos Ativo recebidos do inventário."""

    def __init__(self, ativos):
        self.ativos = ativos

    def calcular(self):
        """Devolve M, v, A e riscos próprios e efetivos na ordem dos IDs.

        O risco próprio é b = F M v, em que F é a diagonal dos fatores de
        exposição de cada tipo de equipamento.
        """
        lista, self.vulnerabilidades, matriz = montar_matriz_incidencia(self.ativos)
        vetor = [vulnerabilidade.cvss for vulnerabilidade in self.vulnerabilidades]
        self.fatores = [ativo.fator_exposicao() for ativo in lista]
        self.soma_cvss = produto_matriz_vetor(matriz, vetor)
        proprio = aplicar_exposicao(lista, self.soma_cvss)
        dependencias = montar_matriz_dependencias(lista)
        self.matriz_sistema = identidade_menos(dependencias)
        sistema = SistemaLinear(self.matriz_sistema)
        self.determinante = sistema.determinante
        self.numero_condicao = sistema.condicionamento()
        if self.numero_condicao > 1 / sys.float_info.epsilon:
            raise ValueError("I - A é singular ou quase singular; revise as dependências.")
        efetivo = sistema.resolver(proprio)
        self.herdado = produto_matriz_vetor(dependencias, efetivo)
        calculado = produto_matriz_vetor(self.matriz_sistema, efetivo)
        self.residuo = max(
            (abs(real - esperado) for real, esperado in zip(calculado, proprio)), default=0.0
        )
        self.maior_soma_pesos = max(map(sum, dependencias), default=0.0)
        return lista, matriz, vetor, proprio, dependencias, efetivo


def simular_vulnerabilidade(ativos, identificador, cvss):
    """Calcula o risco após uma vulnerabilidade hipotética, sem alterar os ativos.

    A simulação acrescenta uma coluna temporária à matriz de incidência. Ela tem
    valor 1 apenas na linha do ativo escolhido, pois a vulnerabilidade simulada
    afeta somente esse ativo. Nenhum objeto é gravado ou modificado.
    """
    lista, matriz, vetor, _, dependencias, _ = AnalisadorRisco(ativos).calcular()
    indice_ativo = next(
        (indice for indice, ativo in enumerate(lista) if ativo.id == identificador),
        None,
    )
    if indice_ativo is None:
        raise ValueError("Ativo não encontrado para a simulação.")

    matriz_simulada = [
        linha[:] + [1 if indice == indice_ativo else 0] for indice, linha in enumerate(matriz)
    ]
    vetor_simulado = vetor + [cvss]
    proprio = aplicar_exposicao(lista, produto_matriz_vetor(matriz_simulada, vetor_simulado))
    sistema = identidade_menos(dependencias)
    efetivo = SistemaLinear(sistema).resolver(proprio)
    return lista, matriz_simulada, vetor_simulado, proprio, dependencias, efetivo
