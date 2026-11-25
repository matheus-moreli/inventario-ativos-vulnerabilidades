"""Testes de auditoria defensiva de acesso HTTP."""

import json
import os
import tempfile
import unittest

from infraestrutura.auditoria import AuditoriaHTTP


class TesteAuditoriaHTTP(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.caminho = os.path.join(self.tmp.name, "auditoria.jsonl")

    def eventos(self):
        if not os.path.exists(self.caminho):
            return []
        with open(self.caminho, encoding="utf-8") as arquivo:
            return [json.loads(linha) for linha in arquivo]

    def test_registra_consulta_e_recusa_sem_parametros(self):
        auditoria = AuditoriaHTTP(self.caminho)
        auditoria.registrar("192.0.2.10", "GET", "/riscos?token=segredo", 200)
        auditoria.registrar("192.0.2.10", "GET", "/rota-invalida?senha=segredo", 404)
        eventos = self.eventos()
        self.assertEqual([evento["codigo_http"] for evento in eventos], [200, 404])
        self.assertEqual(eventos[0]["rota"], "/riscos")
        self.assertEqual(eventos[1]["rota"], "/rota-invalida")
        self.assertNotIn("segredo", open(self.caminho, encoding="utf-8").read())
        self.assertEqual(eventos[1]["classificacao"], "requisicao_recusada")

    def test_ignora_healthcheck_local(self):
        auditoria = AuditoriaHTTP(self.caminho)
        auditoria.registrar("127.0.0.1", "GET", "/saude", 200)
        self.assertFalse(os.path.exists(self.caminho))

    def test_alerta_por_cinco_erros_da_mesma_origem(self):
        auditoria = AuditoriaHTTP(self.caminho)
        for _ in range(6):
            auditoria.registrar("198.51.100.20", "GET", "/sem-rota", 404)
        classes = [evento["classificacao"] for evento in self.eventos()]
        self.assertEqual(classes.count("alerta_falhas_repetidas"), 1)
        self.assertEqual(classes[-1], "requisicao_recusada")

    def test_outros_metodos_sao_auditados(self):
        auditoria = AuditoriaHTTP(self.caminho)
        auditoria.registrar("192.0.2.11", "POST", "/riscos", 405)
        evento = self.eventos()[0]
        self.assertEqual(evento["metodo"], "POST")
        self.assertEqual(evento["codigo_http"], 405)

    def test_rotacao_limita_armazenamento_e_permissoes(self):
        auditoria = AuditoriaHTTP(self.caminho, tamanho_maximo=200, backups=2)
        for indice in range(12):
            auditoria.registrar("203.0.113.7", "GET", f"/rota-{indice}", 404)
        self.assertTrue(os.path.exists(self.caminho))
        self.assertTrue(os.path.exists(f"{self.caminho}.1"))
        self.assertTrue(os.path.exists(f"{self.caminho}.2"))
        self.assertFalse(os.path.exists(f"{self.caminho}.3"))
        if os.name != "nt":
            self.assertEqual(os.stat(self.caminho).st_mode & 0o777, 0o600)

    def test_falha_de_gravacao_nao_quebra_aplicacao(self):
        pasta = os.path.join(self.tmp.name, "log-nao-pode-ser-diretorio")
        os.makedirs(pasta)
        auditoria = AuditoriaHTTP(pasta)
        auditoria.registrar("192.0.2.11", "GET", "/rota", 404)


if __name__ == "__main__":
    unittest.main()
