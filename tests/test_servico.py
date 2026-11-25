"""Comportamento observável do modo de serviço usado no container."""

import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from apresentacao.servico import ServicoInventario
from dominio.inventario import Inventario
from dominio.modelos import TipoAtivo
from tests.ajudantes import cadastrar_ativo, salvar_ativos


class TesteServico(unittest.TestCase):
    def test_handler_http_usa_cabecalhos_de_problem_details(self):
        with tempfile.TemporaryDirectory() as pasta:
            senha = Path(pasta) / "segredo"
            senha.write_text("segredo-local-de-teste", encoding="utf-8")
            servico = ServicoInventario({}, caminho_senha=senha)
            with patch("apresentacao.servico.ThreadingHTTPServer") as servidor:
                servico.executar()
            handler = servidor.call_args.args[1]
            requisicao = Mock()
            requisicao.makefile.return_value = io.BytesIO(
                b"GET /v1/ativos HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
            handler(requisicao, ("127.0.0.1", 12345), Mock())
            resposta = b"".join(chamada.args[0] for chamada in requisicao.sendall.call_args_list)
            self.assertIn(b" 401 ", resposta.split(b"\r\n", 1)[0])
            self.assertIn(b"Content-Type: application/problem+json", resposta)
            self.assertIn(b'WWW-Authenticate: Bearer realm="Inventario"', resposta)

    def test_api_v1_filtra_pagina_ordena_e_mantem_retorno_legado(self):
        inv = Inventario()
        inv.cadastrar_ativo(1, "SRV-01", "Equipe", "Sala", 2, "Alta")
        inv.cadastrar_ativo(2, "SRV-02", "Equipe", "Sala", 2, "Alta")
        inv.cadastrar_ativo(3, "NB-01", "Equipe", "Sala", 1, "Alta")
        inv.cadastrar_vulnerabilidade(
            2,
            "CVE-2026-1234",
            "CWE-79",
            8,
            "Caso didático",
            "NVD",
            "01/01/2026",
            "Impacto",
            "Alta",
            "Corrigir",
        )
        with tempfile.TemporaryDirectory() as pasta:
            senha = Path(pasta) / "segredo"
            senha.write_text("segredo-local-de-teste", encoding="utf-8")
            servico = ServicoInventario(inv.ativos, caminho_senha=senha)
            bearer = "Bearer segredo-local-de-teste"
            rota = "/v1/ativos?busca=srv&ordenar=risco&limite=1"
            estado, pagina = servico.atender("GET", rota, bearer)
            self.assertEqual(estado, 200)
            self.assertEqual((pagina["pagina"], pagina["limite"], pagina["total"]), (1, 1, 2))
            self.assertEqual([ativo["id"] for ativo in pagina["itens"]], [2])
            _, pagina = servico.atender("GET", rota + "&pagina=2", bearer)
            self.assertEqual([ativo["id"] for ativo in pagina["itens"]], [1])
            _, pagina = servico.atender("GET", rota + "&pagina=3", bearer)
            self.assertEqual(pagina["itens"], [])
            self.assertEqual(
                servico.atender("GET", "/v1/riscos", bearer),
                servico.atender("GET", "/riscos", bearer),
            )

    def test_api_v1_nega_acesso_e_documenta_validacao(self):
        with tempfile.TemporaryDirectory() as pasta:
            senha = Path(pasta) / "segredo"
            senha.write_text("segredo-local-de-teste", encoding="utf-8")
            servico = ServicoInventario({}, caminho_senha=senha)
            bearer = "Bearer segredo-local-de-teste"
            codigo, resposta = servico.atender("GET", "/v1/ativos")
            self.assertEqual(
                (codigo, resposta["status"], resposta["type"]), (401, 401, "about:blank")
            )
            for consulta in (
                "limite=101",
                "pagina=0",
                "pagina=1&pagina=2",
                "ordenar=nome",
                "inexistente=1",
                "limite=",
            ):
                with self.subTest(consulta=consulta):
                    codigo, resposta = servico.atender("GET", "/v1/ativos?" + consulta, bearer)
                    self.assertEqual((codigo, resposta["status"]), (422, 422))
            self.assertEqual(servico.atender("POST", "/v1/ativos", bearer)[0], 405)
            self.assertEqual(servico.atender("GET", "/v1/inexistente", bearer)[0], 404)
            codigo, contrato = servico.atender("GET", "/openapi.json")
            self.assertEqual(codigo, 200)
            self.assertIn("/v1/ativos", contrato["paths"])
            self.assertIn("/v1/riscos", contrato["paths"])

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
