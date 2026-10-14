"""Testes pequenos do requisito de POO e álgebra linear do Trabalho 2."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from interface import InterfaceTerminal
from inventario import (
    DadosInvalidosError,
    Inventario,
    adicionar_dependencia,
    atualizar_ativo,
    cadastrar_ativo,
    cadastrar_vulnerabilidade,
)
from modelos import Ativo, Equipamento, Notebook, Servidor
from persistencia import carregar_ativos, salvar_ativos
from risco import calcular_riscos, resolver_sistema


class TesteRisco(unittest.TestCase):
    def setUp(self):
        self.ativos = {}
        cadastrar_ativo(self.ativos, 1, "NOTE-01", "Ana", "Sala 1", 1, "Baixa")
        cadastrar_ativo(self.ativos, 2, "SRV-01", "TI", "Datacenter", 2, "Alta")
        cadastrar_ativo(self.ativos, 3, "APP-01", "TI", "Nuvem", 4, "Alta")

    def vulnerabilidade(self, identificador, cve, cvss):
        cadastrar_vulnerabilidade(
            self.ativos,
            identificador,
            cve,
            "CWE-79",
            cvss,
            "Teste",
            "Fonte",
            "01/01/2026",
            "Impacto",
            "Alta",
            "Tratar",
        )

    def test_cada_tipo_gera_o_objeto_correspondente(self):
        self.assertIs(Ativo, Equipamento)
        self.assertTrue(issubclass(Servidor, Equipamento))
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

        ativos, matriz, vetor, proprio, dependencias, efetivo = calcular_riscos(
            self.ativos
        )

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

    def test_dependencias_persistem_e_mantem_o_risco(self):
        self.vulnerabilidade(1, "CVE-2026-0001", 4)
        adicionar_dependencia(self.ativos, 3, 1, 0.25)
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos(self.ativos, caminho))
            carregados = carregar_ativos(caminho)
        self.assertEqual(carregados[3].dependencias, [{"ativo_id": 1, "peso": 0.25}])
        self.assertEqual(calcular_riscos(carregados)[-1], [4.0, 0.0, 1.0])

    def test_matriz_singular_e_rejeitada_antes_da_solucao(self):
        with self.assertRaisesRegex(ValueError, "não é invertível"):
            resolver_sistema([[1.0, 1.0], [2.0, 2.0]], [1.0, 2.0])

    def test_ciclo_de_tres_ativos_resolvido_a_mao(self):
        # x1=4+0,5x2; x2=6+0,25x1; x3=0,2x1+0,3x2.
        # Substituindo: x1=8, x2=8 e x3=4.
        self.vulnerabilidade(1, "CVE-2026-0001", 4)
        self.vulnerabilidade(2, "CVE-2026-0002", 6)
        adicionar_dependencia(self.ativos, 1, 2, 0.5)
        adicionar_dependencia(self.ativos, 2, 1, 0.25)
        adicionar_dependencia(self.ativos, 3, 1, 0.2)
        adicionar_dependencia(self.ativos, 3, 2, 0.3)
        _, _, _, proprio, matriz_a, efetivo = calcular_riscos(self.ativos)
        self.assertEqual(proprio, [4.0, 6.0, 0])
        self.assertEqual(matriz_a, [[0.0, 0.5, 0.0], [0.25, 0.0, 0.0], [0.2, 0.3, 0.0]])
        for obtido, esperado in zip(efetivo, [8.0, 8.0, 4.0]):
            self.assertAlmostEqual(obtido, esperado)

    def test_interface_usa_a_mesma_instancia_do_inventario(self):
        inventario = Inventario(self.ativos)
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            tela = InterfaceTerminal(inventario, caminho)
            self.assertIs(tela.inventario, inventario)
            with patch("interface.mostrar_menu", side_effect=["2", "0"]):
                tela.executar()
            self.assertIsInstance(carregar_ativos(caminho)[1], Notebook)


if __name__ == "__main__":
    unittest.main()
