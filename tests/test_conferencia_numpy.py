"""Conferência independente do modelo de risco com NumPy.

O programa resolve (I - A)x = F M v em Python puro, por fatoração LU. Aqui a mesma
conta é refeita com `numpy.linalg`, que não compartilha código com a implementação.
"""

import random

import pytest

from dominio.inventario import Inventario
from dominio.risco import AnalisadorRisco

np = pytest.importorskip("numpy")

TIPOS = [1, 2, 3, 4, 5, 6]  # um de cada tipo nativo, para exercitar fatores diferentes


def inventario_aleatorio(semente, quantidade=8):
    sorteio = random.Random(semente)
    inv = Inventario()
    for i in range(1, quantidade + 1):
        inv.cadastrar_ativo(i, f"ATIVO-{i}", "TI", "Sala", sorteio.choice(TIPOS), "Alta")
    cve = 0
    for i in range(1, quantidade + 1):
        for _ in range(sorteio.randint(0, 3)):
            cve += 1
            inv.cadastrar_vulnerabilidade(
                i,
                f"CVE-2026-{cve:05d}",
                "CWE-79",
                round(sorteio.uniform(0, 10), 1),
                "Teste",
                "Fonte",
                "01/01/2026",
                "Impacto",
                "Alta",
                "Tratar",
            )
    for i in range(1, quantidade + 1):
        origens = sorteio.sample([j for j in range(1, quantidade + 1) if j != i], 3)
        pesos = [0.15, 0.1, 0.05]  # soma 0,30 < 1: I - A é invertível
        for origem, peso in zip(origens, pesos):
            inv.adicionar_dependencia(i, origem, peso)
    return inv


@pytest.mark.parametrize("semente", range(5))
def test_risco_proprio_e_efetivo_batem_com_numpy(semente):
    inv = inventario_aleatorio(semente)
    analise = AnalisadorRisco(inv.ativos)
    lista, m, v, proprio, a, efetivo = analise.calcular()

    f = np.diag([ativo.fator_exposicao() for ativo in lista])
    m, v, a = np.array(m, dtype=float), np.array(v, dtype=float), np.array(a)
    b = f @ m @ v if v.size else np.zeros(len(lista))
    x = np.linalg.solve(np.eye(len(lista)) - a, b)

    assert proprio == pytest.approx(b)
    assert efetivo == pytest.approx(x)
    assert np.allclose((np.eye(len(lista)) - a) @ x, b)


@pytest.mark.parametrize("semente", range(5))
def test_determinante_e_condicionamento_batem_com_numpy(semente):
    inv = inventario_aleatorio(semente)
    analise = AnalisadorRisco(inv.ativos)
    analise.calcular()
    sistema = np.array(analise.matriz_sistema)

    assert analise.determinante == pytest.approx(np.linalg.det(sistema))
    assert analise.numero_condicao == pytest.approx(np.linalg.cond(sistema, np.inf))
