"""Barreira de senha do HTTP e auditoria sem captura de credenciais."""

import os
import tempfile
import unittest

from apresentacao.servico import ServicoInventario
from infraestrutura.auditoria import AuditoriaHTTP
from infraestrutura.autenticacao import AutenticacaoHTTP


class TesteBarreirasHTTP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.senha = os.path.join(self.tmp.name, "senha-acesso")
        with open(self.senha, "w", encoding="utf-8") as arquivo:
            arquivo.write("senha-dedicada-para-testes\n")
        self.servico = ServicoInventario({}, caminho_senha=self.senha)

    def test_arquivo_de_senha_obrigatorio(self):
        autenticacao = AutenticacaoHTTP(os.path.join(self.tmp.name, "inexistente"))
        self.assertFalse(autenticacao.configurada())
        self.assertFalse(autenticacao.autorizada("Bearer qualquer"))
        with open(self.senha, "w", encoding="utf-8") as arquivo:
            arquivo.write("")
        self.assertFalse(AutenticacaoHTTP(self.senha).configurada())

    def test_credencial_correta_e_incorreta(self):
        self.assertTrue(
            AutenticacaoHTTP(self.senha).autorizada("Bearer senha-dedicada-para-testes")
        )
        self.assertFalse(
            AutenticacaoHTTP(self.senha).autorizada("Bearer senha-dedicada-para-teste")
        )
        self.assertFalse(AutenticacaoHTTP(self.senha).autorizada("Basic abc"))

    def test_riscos_exige_senha(self):
        self.assertEqual(self.servico.atender("GET", "/riscos")[0], 401)
        self.assertEqual(self.servico.atender("GET", "/riscos", "Bearer senha-errada")[0], 401)
        self.assertEqual(
            self.servico.atender("GET", "/riscos", "Bearer senha-dedicada-para-testes")[0], 200
        )

    def test_saude_continua_publica_para_healthcheck(self):
        self.assertEqual(self.servico.atender("GET", "/saude")[0], 200)

    def test_rota_inexistente_registrada_sem_credenciais(self):
        self.assertEqual(self.servico.atender("GET", "/admin")[0], 404)
        log = os.path.join(self.tmp.name, "auditoria.jsonl")
        AuditoriaHTTP(log).registrar("192.0.2.15", "GET", "/admin?senha=nao-registrar", 404)
        with open(log, encoding="utf-8") as arquivo:
            linha = arquivo.read()
        self.assertIn("requisicao_recusada", linha)
        self.assertNotIn("nao-registrar", linha)

    def test_metodo_nao_permitido(self):
        self.assertEqual(
            self.servico.atender("POST", "/riscos", "Bearer senha-dedicada-para-testes")[0], 405
        )


if __name__ == "__main__":
    unittest.main()
