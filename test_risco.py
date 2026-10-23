"""Testes do modelo linear de risco do Trabalho 2.

Execute com: python -m unittest -v test_risco.py
O cenário foi resolvido à mão antes de virar teste:
  b = [4, 6, 0]
  x1 = 4 + 0,25*x2 = 5,5
  x2 = 6
  x3 = 0 + 0,50*x1 = 2,75
"""

import unittest

from inventario import (DadosInvalidosError, adicionar_dependencia,
                        cadastrar_ativo, cadastrar_vulnerabilidade)
from modelos import Notebook, Servidor
from risco import calcular_riscos, resolver_sistema


class TesteRiscoLinear(unittest.TestCase):
    def setUp(self):
        self.ativos = {}
        cadastrar_ativo(self.ativos, 1, "NB-01", "Ana", "Sala 1", 1, "Média")
        cadastrar_ativo(self.ativos, 2, "SRV-01", "TI", "Datacenter", 2, "Crítica")
        cadastrar_ativo(self.ativos, 3, "RTR-01", "TI", "Rede", 3, "Alta")
        cadastrar_vulnerabilidade(
            self.ativos, 1, "CVE-2026-0001", "CWE-79", 4.0, "Falha A",
            "Fonte", "01/01/2026", "Impacto", "Média", "Tratar"
        )
        cadastrar_vulnerabilidade(
            self.ativos, 2, "CVE-2026-0002", "CWE-89", 6.0, "Falha B",
            "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar"
        )
        adicionar_dependencia(self.ativos, 1, 2, 0.25)
        adicionar_dependencia(self.ativos, 3, 1, 0.50)

    def test_subclasses_sao_criadas_pelo_tipo(self):
        self.assertIsInstance(self.ativos[1], Notebook)
        self.assertIsInstance(self.ativos[2], Servidor)
        self.assertEqual(self.ativos[2].descricao_tipo(), "Servidor")

    def test_cenario_de_tres_equipamentos_resolvido_a_mao(self):
        resultado = calcular_riscos(self.ativos)
        self.assertEqual(resultado["M"], [[1, 0], [0, 1], [0, 0]])
        self.assertEqual(resultado["v"], [4.0, 6.0])
        self.assertEqual(resultado["b"], [4.0, 6.0, 0.0])
        self.assertEqual(resultado["A"], [[0.0, 0.25, 0.0],
                                           [0.0, 0.0, 0.0],
                                           [0.5, 0.0, 0.0]])
        self.assertAlmostEqual(resultado["x"][0], 5.5)
        self.assertAlmostEqual(resultado["x"][1], 6.0)
        self.assertAlmostEqual(resultado["x"][2], 2.75)

    def test_dependencia_nao_pode_deixar_a_linha_igual_ou_maior_que_um(self):
        with self.assertRaises(DadosInvalidosError):
            adicionar_dependencia(self.ativos, 1, 3, 0.75)

    def test_sistema_singular_e_recusado(self):
        with self.assertRaises(ValueError):
            resolver_sistema([[1.0, 1.0], [2.0, 2.0]], [1.0, 2.0])


if __name__ == "__main__":
    unittest.main()
