"""Comportamento observável do modo de serviço usado no container."""

import os
import tempfile
import unittest

from modelos import TipoAtivo
from inventario import Inventario, cadastrar_ativo
from persistencia import salvar_ativos
from servico import ServicoInventario


class TesteServico(unittest.TestCase):
    def test_saude_e_riscos_com_base_vazia(self):
        servico = ServicoInventario({}, host="127.0.0.1", porta=8080)
        codigo, saude = servico.resposta("/saude")
        self.assertEqual(codigo, 200)
        self.assertEqual(saude["ativos"], 0)
        self.assertGreaterEqual(saude["tempo_ativo_segundos"], 0)
        codigo, riscos = servico.resposta("/riscos")
        self.assertEqual(codigo, 200)
        self.assertEqual(riscos["risco_efetivo"], [])
        self.assertEqual(riscos["numero_condicao_infinito"], 1.0)

    def test_riscos_de_objeto_cadastrado(self):
        ativos = {}
        cadastrar_ativo(
            ativos,
            1,
            "srv-01",
            "Matheus",
            "Laboratório",
            TipoAtivo.SERVIDOR.value,
            "Alta",
        )
        codigo, riscos = ServicoInventario(ativos).resposta("/riscos")
        self.assertEqual(codigo, 200)
        self.assertEqual(riscos["ids"], [1])
        self.assertEqual(riscos["risco_proprio"], [0])

    def test_inventario_orientado_a_objetos(self):
        inventario = Inventario()
        ativo = inventario.cadastrar_ativo(
            1, "srv-01", "Matheus", "Laboratório", TipoAtivo.SERVIDOR.value, "Alta"
        )
        self.assertIs(inventario.consultar_por_id(1), ativo)
        self.assertEqual(ativo.nome_do_tipo(), "Servidor")

    def test_servico_recarrega_json_e_falha_se_base_corromper(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos({}, caminho))
            servico = ServicoInventario({}, caminho_dados=caminho)
            self.assertEqual(servico.resposta("/saude")[1]["ativos"], 0)
            ativos = {}
            cadastrar_ativo(ativos, 1, "srv-01", "Matheus", "Laboratório", 2, "Alta")
            self.assertTrue(salvar_ativos(ativos, caminho))
            self.assertEqual(servico.resposta("/saude")[1]["ativos"], 1)
            self.assertEqual(servico.resposta("/riscos")[1]["ids"], [1])
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write("{")
            self.assertEqual(servico.resposta("/riscos")[0], 503)


if __name__ == "__main__":
    unittest.main()
