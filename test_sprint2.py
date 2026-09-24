"""Testes automatizados das regras de negócio da Sprint 2.

Execute com: python -m unittest -v test_sprint2.py
Cada teste cria dados próprios e não usa dados/inventario.json.
"""

import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from inventario import (DadosInvalidosError, atualizar_ativo,
                        atualizar_vulnerabilidade, cadastrar_ativo,
                        cadastrar_vulnerabilidade, consultar_por_id,
                        consultar_vulnerabilidades, excluir_ativo,
                        excluir_vulnerabilidade, filtrar_ativos)
from persistencia import carregar_ativos, salvar_ativos


class TesteInventario(unittest.TestCase):
    """Cada teste cria a própria base, sem depender do JSON real do projeto."""

    def setUp(self):
        self.ativos = {}
        cadastrar_ativo(self.ativos, 10, "SRV-ARQUIVOS", "Equipe TI",
                        "Datacenter", 2, "Alta")

    def cadastrar_vulnerabilidade_de_exemplo(self):
        """Evita repetir os mesmos dados válidos em vários testes."""
        return cadastrar_vulnerabilidade(
            self.ativos, 10, "CVE-2024-1234", "CWE-79", "7.5",
            "Exemplo de validação", "https://nvd.nist.gov", "01/01/2026",
            "Execução de código", "Alta", "Aplicar correção", "Aberta",
            "Validar versão após atualização")

    def test_cadastro_e_busca_por_id(self):
        ativo = consultar_por_id(self.ativos, 10)
        self.assertIsNotNone(ativo)
        self.assertEqual(ativo.nome, "SRV-ARQUIVOS")
        self.assertIsNone(consultar_por_id(self.ativos, 999))

    def test_id_duplicado_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 10, "OUTRO", "TI", "Sala 1", 1, "Baixa")

    def test_tipo_invalido_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 20, "APP", "TI", "Nuvem", 99, "Média")

    def test_filtro_nao_altera_a_base(self):
        resultado = filtrar_ativos(self.ativos, termo="srv", criticidade="Alta")
        self.assertEqual(len(resultado), 1)
        self.assertEqual(len(self.ativos), 1)

    def test_atualizacao_preserva_identificador_e_registra_historico(self):
        atualizar_ativo(self.ativos, 10, responsavel="Segurança", criticidade="Crítica")
        ativo = self.ativos[10]
        self.assertEqual(ativo.id, 10)
        self.assertEqual(ativo.responsavel, "Segurança")
        self.assertEqual(ativo.criticidade, "Crítica")
        self.assertGreaterEqual(len(ativo.historico), 2)

    def test_exclusao_exige_confirmacao(self):
        self.assertFalse(excluir_ativo(self.ativos, 10, False))
        self.assertIn(10, self.ativos)
        self.assertTrue(excluir_ativo(self.ativos, 10, True))
        self.assertNotIn(10, self.ativos)

    def test_vulnerabilidade_com_dados_verificaveis(self):
        vulnerabilidade = self.cadastrar_vulnerabilidade_de_exemplo()
        self.assertEqual(vulnerabilidade.cvss, 7.5)
        resultado = consultar_vulnerabilidades(self.ativos, cve="CVE-2024-1234")
        self.assertEqual(len(resultado), 1)

    def test_cve_e_cvss_invalidos_sao_rejeitados(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "123", "CWE-79", 5,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 11,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", "nan",
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")

    def test_cve_duplicado_no_mesmo_ativo_e_rejeitado(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        with self.assertRaises(DadosInvalidosError):
            self.cadastrar_vulnerabilidade_de_exemplo()

    def test_atualizacao_de_vulnerabilidade_registra_historico(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        atualizar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234",
                                  status="Em tratamento", verificacao="Revisar versão")
        vulnerabilidade = self.ativos[10].vulnerabilidades[0]
        self.assertEqual(vulnerabilidade.status, "Em tratamento")
        self.assertEqual(vulnerabilidade.verificacao, "Revisar versão")
        self.assertIn("atualizada", self.ativos[10].historico[-1])

    def test_remocao_de_vulnerabilidade_exige_confirmacao(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        self.assertFalse(excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", False))
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 1)
        self.assertTrue(excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", True))
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 0)

    def test_correcao_exige_verificacao(self):
        # Não informamos verificação: a função usa o padrão "Pendente".
        cadastrar_vulnerabilidade(
            self.ativos, 10, "CVE-2024-5678", "CWE-79", 5,
            "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            atualizar_vulnerabilidade(self.ativos, 10, "CVE-2024-5678", status="Corrigida")

    def test_json_invalido_nao_e_substituido(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            conteudo_invalido = "{arquivo quebrado"
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write(conteudo_invalido)
            with redirect_stdout(io.StringIO()):
                self.assertIsNone(carregar_ativos(caminho))
            with open(caminho, "r", encoding="utf-8") as arquivo:
                self.assertEqual(arquivo.read(), conteudo_invalido)

    def test_json_preserva_dados(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos(self.ativos, caminho))
            recarregados = carregar_ativos(caminho)
        self.assertEqual(recarregados[10].nome, "SRV-ARQUIVOS")
        self.assertEqual(recarregados[10].criticidade, "Alta")


if __name__ == "__main__":
    unittest.main()
