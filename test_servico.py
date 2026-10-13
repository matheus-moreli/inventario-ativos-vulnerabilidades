"""Comportamento observável do modo de serviço usado no container."""

import unittest

from modelos import TipoAtivo
from inventario import Inventario, cadastrar_ativo
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


if __name__ == "__main__":
    unittest.main()
