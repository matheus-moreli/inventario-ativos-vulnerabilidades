"""Regressões de tipos dinâmicos, metadados, matrizes e porta oficial."""
import json
import os
import tempfile
import unittest

from dominio.inventario import Inventario, DadosInvalidosError
from dominio.modelos import EquipamentoPersonalizado
from dominio.risco import AnalisadorRisco
from infraestrutura.persistencia import RepositorioJSON
from apresentacao.servico import ServicoInventario


class TesteExtensibilidade(unittest.TestCase):
    def test_tipo_personalizado_e_metadados_persistem(self):
        inv = Inventario()
        inv.cadastrar_ativo(1, "FW-01", "Equipe", "Rack", 100, "Alta",
                           nome_tipo_personalizado="Firewall")
        inv.definir_campo_extra(1, "IP", "192.0.2.1")
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(RepositorioJSON(caminho).salvar(inv.ativos))
            with open(caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
            carregados = RepositorioJSON(caminho).carregar()
        self.assertIsInstance(dados, list)
        self.assertIsInstance(carregados[1], EquipamentoPersonalizado)
        self.assertEqual(carregados[1].nome_do_tipo(), "Firewall")
        self.assertEqual(carregados[1].campos_extras["IP"], "192.0.2.1")

    def test_categoria_invalida_e_rejeitada(self):
        inv = Inventario()
        with self.assertRaises(DadosInvalidosError):
            inv.cadastrar_ativo(1, "FW", "TI", "Rack", 100, "Alta")
        with self.assertRaises(DadosInvalidosError):
            inv.cadastrar_ativo(2, "FW", "TI", "Rack", 99, "Alta")

    def test_matrizes_aumentam_automaticamente(self):
        inv = Inventario()
        for i in range(1, 8):
            inv.cadastrar_ativo(i, f"A-{i}", "TI", "Sala", 1, "Alta")
        argumentos = (1, "CVE-2026-99999", "CWE-79", 9.8, "Teste", "Fonte",
                      "01/01/2026", "Impacto", "Alta", "Tratar")
        inv.cadastrar_vulnerabilidade(*argumentos)
        resultado = AnalisadorRisco(inv.ativos).calcular()
        self.assertEqual(len(resultado[0]), 7)
        self.assertEqual(len(resultado[1]), 7)
        self.assertEqual(len(resultado[1][0]), 1)
        self.assertEqual(len(resultado[4]), 7)
        self.assertEqual(resultado[3][0], 9.8)

    def test_campos_extras_nao_mudam_calculo(self):
        inv = Inventario()
        inv.cadastrar_ativo(1, "SRV", "TI", "Sala", 2, "Alta")
        anterior = AnalisadorRisco(inv.ativos).calcular()[-1]
        inv.definir_campo_extra(1, "Ambiente", "Produção")
        depois = AnalisadorRisco(inv.ativos).calcular()[-1]
        self.assertEqual(anterior, depois)

    def test_porta_padrao_e_2217(self):
        anterior = os.environ.pop("INVENTARIO_PORTA", None)
        try:
            self.assertEqual(ServicoInventario({}).porta, 2217)
        finally:
            if anterior is not None:
                os.environ["INVENTARIO_PORTA"] = anterior


if __name__ == "__main__":
    unittest.main()
