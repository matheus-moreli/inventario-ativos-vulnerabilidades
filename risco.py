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
            elif not math.isclose(
                anterior.cvss, vulnerabilidade.cvss, rel_tol=0, abs_tol=1e-9
            ):
                raise ValueError(
                    f"CVE {vulnerabilidade.cve} tem notas CVSS diferentes entre ativos."
                )

    matriz = []
    for ativo in lista_ativos:
        cves_do_ativo = {item.cve for item in ativo.vulnerabilidades}
        matriz.append(
            [1 if item.cve in cves_do_ativo else 0 for item in vulnerabilidades]
        )
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
        [
            (1.0 if linha == coluna else 0.0) - matriz[linha][coluna]
            for coluna in range(tamanho)
        ]
        for linha in range(tamanho)
    ]


def sistema_e_invertivel(matriz):
    """Usa eliminação de Gauss para verificar se a matriz possui pivô em cada coluna."""
    copia = [linha[:] for linha in matriz]
    tamanho = len(copia)
    for coluna in range(tamanho):
        pivo = max(range(coluna, tamanho), key=lambda linha: abs(copia[linha][coluna]))
        if abs(copia[pivo][coluna]) < EPSILON:
            return False
        copia[coluna], copia[pivo] = copia[pivo], copia[coluna]
        for linha in range(coluna + 1, tamanho):
            fator = copia[linha][coluna] / copia[coluna][coluna]
            for item in range(coluna, tamanho):
                copia[linha][item] -= fator * copia[coluna][item]
    return True


def resolver_sistema(matriz, vetor):
    """Resolve Ax=b por eliminação de Gauss, sem calcular a inversa da matriz."""
    if not sistema_e_invertivel(matriz):
        raise ValueError("Não é possível calcular o risco: I - A não é invertível.")
    tamanho = len(matriz)
    aumentado = [matriz[linha][:] + [vetor[linha]] for linha in range(tamanho)]
    for coluna in range(tamanho):
        pivo = max(
            range(coluna, tamanho), key=lambda linha: abs(aumentado[linha][coluna])
        )
        aumentado[coluna], aumentado[pivo] = aumentado[pivo], aumentado[coluna]
        for linha in range(coluna + 1, tamanho):
            fator = aumentado[linha][coluna] / aumentado[coluna][coluna]
            for item in range(coluna, tamanho + 1):
                aumentado[linha][item] -= fator * aumentado[coluna][item]

    resultado = [0.0] * tamanho
    for linha in range(tamanho - 1, -1, -1):
        soma = sum(
            aumentado[linha][coluna] * resultado[coluna]
            for coluna in range(linha + 1, tamanho)
        )
        resultado[linha] = (aumentado[linha][-1] - soma) / aumentado[linha][linha]
    return resultado


def numero_condicao_infinito(matriz):
    """Calcula κ∞ = ||S||∞ ||S⁻¹||∞ sem usar a inversa para resolver o risco."""
    tamanho = len(matriz)
    if tamanho == 0:
        return 1.0
    norma = max(sum(abs(valor) for valor in linha) for linha in matriz)
    somas_inversa = [0.0] * tamanho
    for coluna in range(tamanho):
        base = [1.0 if indice == coluna else 0.0 for indice in range(tamanho)]
        solucao = resolver_sistema(matriz, base)
        for linha, valor in enumerate(solucao):
            somas_inversa[linha] += abs(valor)
    return norma * max(somas_inversa)


class AnalisadorRisco:
    """Calcula o risco dos objetos Ativo recebidos do inventário."""

    def __init__(self, ativos):
        self.ativos = ativos

    def calcular(self):
        """Devolve M, v, A e riscos próprios e efetivos na ordem dos IDs."""
        lista, vulnerabilidades, matriz = montar_matriz_incidencia(self.ativos)
        vetor = [vulnerabilidade.cvss for vulnerabilidade in vulnerabilidades]
        proprio = produto_matriz_vetor(matriz, vetor)
        dependencias = montar_matriz_dependencias(lista)
        sistema = identidade_menos(dependencias)
        self.numero_condicao = numero_condicao_infinito(sistema)
        if self.numero_condicao > 1 / sys.float_info.epsilon:
            raise ValueError(
                "I - A é singular ou quase singular; revise as dependências."
            )
        efetivo = resolver_sistema(sistema, proprio)
        return lista, matriz, vetor, proprio, dependencias, efetivo


def calcular_riscos(ativos):
    """Compatibilidade com as chamadas das Sprints anteriores."""
    return AnalisadorRisco(ativos).calcular()
