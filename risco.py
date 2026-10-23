"""Cálculo didático do risco próprio e efetivo dos equipamentos.

O módulo usa somente listas e laços do Python para deixar visível a relação:
    b = Mv
    (I - A)x = b
"""

EPSILON = 1e-12


def ativos_ordenados(ativos):
    """Ordena por ID e evita usar o ID como posição de matriz."""
    return [ativos[identificador] for identificador in sorted(ativos)]


def montar_matriz_incidencia(ativos):
    """Monta M: linhas são equipamentos e colunas são vulnerabilidades."""
    equipamentos = ativos_ordenados(ativos)
    vulnerabilidades = []
    for ativo in equipamentos:
        for vulnerabilidade in ativo.vulnerabilidades:
            vulnerabilidades.append((ativo.id, vulnerabilidade))

    matriz = []
    for ativo in equipamentos:
        linha = []
        for id_afetado, _ in vulnerabilidades:
            linha.append(1 if ativo.id == id_afetado else 0)
        matriz.append(linha)
    return equipamentos, vulnerabilidades, matriz


def montar_vetor_severidade(vulnerabilidades):
    """Monta v com CVSS; uma falha corrigida deixa de contribuir para o risco."""
    vetor = []
    for _, vulnerabilidade in vulnerabilidades:
        if vulnerabilidade.status == "Corrigida":
            vetor.append(0.0)
        else:
            vetor.append(float(vulnerabilidade.cvss))
    return vetor


def montar_matriz_dependencias(equipamentos):
    """Monta A: A[i][j] é o risco de j transmitido para i."""
    posicao_por_id = {ativo.id: posicao for posicao, ativo in enumerate(equipamentos)}
    matriz = [[0.0 for _ in equipamentos] for _ in equipamentos]
    for linha, ativo in enumerate(equipamentos):
        for dependencia in ativo.dependencias:
            coluna = posicao_por_id.get(dependencia["id"])
            if coluna is None:
                raise ValueError("Há uma dependência para um ativo inexistente.")
            matriz[linha][coluna] = float(dependencia["peso"])
    return matriz


def produto_matriz_vetor(matriz, vetor):
    """Calcula Mv com laços explícitos, sem esconder a operação matemática."""
    resultado = []
    for linha in matriz:
        soma = 0.0
        for coluna, valor in enumerate(linha):
            soma += valor * vetor[coluna]
        resultado.append(soma)
    return resultado


def identidade_menos(matriz):
    """Devolve I-A, a matriz que será usada para calcular o risco efetivo."""
    tamanho = len(matriz)
    return [
        [(1.0 if linha == coluna else 0.0) - matriz[linha][coluna]
         for coluna in range(tamanho)]
        for linha in range(tamanho)
    ]


def resolver_sistema(matriz, vetor):
    """Resolve Ax=b por eliminação de Gauss com pivoteamento parcial."""
    tamanho = len(matriz)
    if tamanho != len(vetor) or any(len(linha) != tamanho for linha in matriz):
        raise ValueError("Sistema linear com dimensões inválidas.")

    aumentada = [list(matriz[indice]) + [float(vetor[indice])]
                 for indice in range(tamanho)]
    for coluna in range(tamanho):
        pivo = max(range(coluna, tamanho),
                   key=lambda linha: abs(aumentada[linha][coluna]))
        if abs(aumentada[pivo][coluna]) < EPSILON:
            raise ValueError("I - A não é invertível; o risco efetivo não pode ser calculado.")
        aumentada[coluna], aumentada[pivo] = aumentada[pivo], aumentada[coluna]
        divisor = aumentada[coluna][coluna]
        for indice in range(coluna, tamanho + 1):
            aumentada[coluna][indice] /= divisor
        for linha in range(coluna + 1, tamanho):
            fator = aumentada[linha][coluna]
            for indice in range(coluna, tamanho + 1):
                aumentada[linha][indice] -= fator * aumentada[coluna][indice]

    resultado = [0.0] * tamanho
    for linha in range(tamanho - 1, -1, -1):
        resultado[linha] = aumentada[linha][tamanho]
        for coluna in range(linha + 1, tamanho):
            resultado[linha] -= aumentada[linha][coluna] * resultado[coluna]
    return resultado


def calcular_riscos(ativos):
    """Monta M, v, b, A e resolve (I-A)x para todos os equipamentos."""
    equipamentos, vulnerabilidades, matriz_m = montar_matriz_incidencia(ativos)
    vetor_v = montar_vetor_severidade(vulnerabilidades)
    risco_proprio = produto_matriz_vetor(matriz_m, vetor_v)
    matriz_a = montar_matriz_dependencias(equipamentos)
    sistema = identidade_menos(matriz_a)
    risco_efetivo = resolver_sistema(sistema, risco_proprio)
    return {
        "equipamentos": equipamentos,
        "vulnerabilidades": vulnerabilidades,
        "M": matriz_m,
        "v": vetor_v,
        "b": risco_proprio,
        "A": matriz_a,
        "I_menos_A": sistema,
        "x": risco_efetivo,
    }
