"""Cálculo do risco próprio e efetivo pedido no Trabalho 2."""

EPSILON = 0.000000000001


def ativos_ordenados(ativos):
    """Mantém linhas e colunas das matrizes na mesma ordem dos IDs."""
    return [ativos[identificador] for identificador in sorted(ativos)]


def montar_matriz_incidencia(ativos):
    """M[i][j] vale 1 quando a vulnerabilidade j pertence ao ativo i."""
    lista_ativos = ativos_ordenados(ativos)
    vulnerabilidades = []
    for ativo in lista_ativos:
        for vulnerabilidade in ativo.vulnerabilidades:
            vulnerabilidades.append((ativo.id, vulnerabilidade))

    matriz = []
    for ativo in lista_ativos:
        linha = []
        for ativo_id, vulnerabilidade in vulnerabilidades:
            linha.append(1 if ativo.id == ativo_id else 0)
        matriz.append(linha)
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


class AnalisadorRisco:
    """Calcula o risco dos objetos Ativo recebidos do inventário."""

    def __init__(self, ativos):
        self.ativos = ativos

    def calcular(self):
        """Devolve M, v, A e riscos próprios e efetivos na ordem dos IDs."""
        lista, vulnerabilidades, matriz = montar_matriz_incidencia(self.ativos)
        vetor = [vulnerabilidade.cvss for _, vulnerabilidade in vulnerabilidades]
        proprio = produto_matriz_vetor(matriz, vetor)
        dependencias = montar_matriz_dependencias(lista)
        sistema = identidade_menos(dependencias)
        efetivo = resolver_sistema(sistema, proprio)
        return lista, matriz, vetor, proprio, dependencias, efetivo


def calcular_riscos(ativos):
    """Compatibilidade com as chamadas das Sprints anteriores."""
    return AnalisadorRisco(ativos).calcular()
