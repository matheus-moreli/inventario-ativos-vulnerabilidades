"""Testes pequenos do requisito de POO e álgebra linear do Trabalho 2."""

import json
import os
import tempfile
import unittest

from inventario import (DadosInvalidosError, adicionar_dependencia,
                        atualizar_ativo, cadastrar_ativo,
                        cadastrar_vulnerabilidade)
from modelos import Notebook, Servidor
from persistencia import salvar_ativos
from risco import calcular_riscos


class TesteRisco(unittest.TestCase):
    def setUp(self):
        self.ativos = {}
        cadastrar_ativo(self.ativos, 1, "NOTE-01", "Ana", "Sala 1", 1, "Baixa")
        cadastrar_ativo(self.ativos, 2, "SRV-01", "TI", "Datacenter", 2, "Alta")
        cadastrar_ativo(self.ativos, 3, "APP-01", "TI", "Nuvem", 4, "Alta")

    def vulnerabilidade(self, identificador, cve, cvss):
        cadastrar_vulnerabilidade(
            self.ativos, identificador, cve, "CWE-79", cvss, "Teste", "Fonte",
            "01/01/2026", "Impacto", "Alta", "Tratar"
        )

    def test_cada_tipo_gera_o_objeto_correspondente(self):
        self.assertIsInstance(self.ativos[1], Notebook)
        self.assertIsInstance(self.ativos[2], Servidor)
        self.assertEqual(self.ativos[2].nome_do_tipo(), "Servidor")

    def test_troca_de_tipo_recria_o_objeto_correto(self):
        atualizar_ativo(self.ativos, 1, tipo=2)
        self.assertIsInstance(self.ativos[1], Servidor)

    def test_json_salvo_e_uma_lista_de_objetos(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos(self.ativos, caminho))
            with open(caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        self.assertIsInstance(dados, list)
        self.assertEqual(dados[0]["id"], 1)

    def test_risco_com_dependencias_tem_resultado_conferivel(self):
        # b = [4, 6, 0]. APP-01 recebe 25% do notebook e 50% do servidor:
        # x = [4, 6, 4].
        self.vulnerabilidade(1, "CVE-2026-0001", 4)
        self.vulnerabilidade(2, "CVE-2026-0002", 6)
        adicionar_dependencia(self.ativos, 3, 1, "0,25")
        adicionar_dependencia(self.ativos, 3, 2, "0.50")

        ativos, matriz, vetor, proprio, dependencias, efetivo = calcular_riscos(self.ativos)

        self.assertEqual([ativo.id for ativo in ativos], [1, 2, 3])
        self.assertEqual(matriz, [[1, 0], [0, 1], [0, 0]])
        self.assertEqual(vetor, [4.0, 6.0])
        self.assertEqual(proprio, [4.0, 6.0, 0])
        self.assertEqual(dependencias[2], [0.25, 0.5, 0.0])
        self.assertEqual([round(valor, 2) for valor in efetivo], [4.0, 6.0, 4.0])

    def test_soma_das_dependencias_nao_pode_chegar_a_um(self):
        adicionar_dependencia(self.ativos, 3, 1, 0.60)
        with self.assertRaises(DadosInvalidosError):
            adicionar_dependencia(self.ativos, 3, 2, 0.40)


if __name__ == "__main__":
    unittest.main()
