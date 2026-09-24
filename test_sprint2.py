"""Testes automatizados das regras de negócio da Sprint 2."""

import os
import tempfile
import unittest

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

    def testar_cadastro_e_busca_por_id(self):
        ativo = consultar_por_id(self.ativos, 10)
        self.assertIsNotNone(ativo)
        self.assertEqual(ativo.nome, "SRV-ARQUIVOS")
        self.assertIsNone(consultar_por_id(self.ativos, 999))

    def testar_id_duplicado_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 10, "OUTRO", "TI", "Sala 1", 1, "Baixa")

    def testar_tipo_invalido_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 20, "APP", "TI", "Nuvem", 99, "Média")

    def testar_filtro_nao_altera_a_base(self):
        resultado = filtrar_ativos(self.ativos, termo="srv", criticidade="Alta")
        self.assertEqual(len(resultado), 1)
        self.assertEqual(len(self.ativos), 1)

    def testar_atualizacao_preserva_identificador_e_registra_historico(self):
        atualizar_ativo(self.ativos, 10, responsavel="Segurança", criticidade="Crítica")
        ativo = self.ativos[10]
        self.assertEqual(ativo.id, 10)
        self.assertEqual(ativo.responsavel, "Segurança")
        self.assertEqual(ativo.criticidade, "Crítica")
        self.assertGreaterEqual(len(ativo.historico), 2)

    def testar_exclusao_exige_confirmacao(self):
        self.assertFalse(excluir_ativo(self.ativos, 10, False))
        self.assertIn(10, self.ativos)
        self.assertTrue(excluir_ativo(self.ativos, 10, True))
        self.assertNotIn(10, self.ativos)

    def testar_vulnerabilidade_com_dados_verificaveis(self):
        vulnerabilidade = cadastrar_vulnerabilidade(
            self.ativos, 10, "CVE-2024-1234", "CWE-79", "7.5",
            "Exemplo de validação", "https://nvd.nist.gov", "01/01/2026",
            "Execução de código", "Alta", "Aplicar correção", "Aberta",
            "Validar versão após atualização")
        self.assertEqual(vulnerabilidade.cvss, 7.5)
        resultado = consultar_vulnerabilidades(self.ativos, cve="CVE-2024-1234")
        self.assertEqual(len(resultado), 1)

    def testar_cve_e_cvss_invalidos_sao_rejeitados(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "123", "CWE-79", 5,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 11,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", "nan",
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")

    def testar_cve_duplicado_no_mesmo_ativo_e_rejeitado(self):
        cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
            "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")

    def testar_atualizacao_de_vulnerabilidade_registra_historico(self):
        cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
            "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        atualizar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234",
                                  status="Em tratamento", verificacao="Revisar versão")
        vulnerabilidade = self.ativos[10].vulnerabilidades[0]
        self.assertEqual(vulnerabilidade.status, "Em tratamento")
        self.assertEqual(vulnerabilidade.verificacao, "Revisar versão")
        self.assertIn("atualizada", self.ativos[10].historico[-1])

    def testar_remocao_de_vulnerabilidade_exige_confirmacao(self):
        cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
            "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        self.assertFalse(excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", False))
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 1)
        self.assertTrue(excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", True))
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 0)

    def testar_correcao_exige_verificacao(self):
        cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
            "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        with self.assertRaises(DadosInvalidosError):
            atualizar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", status="Corrigida")

    def testar_json_invalido_nao_e_substituido(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            conteudo_invalido = "{arquivo quebrado"
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write(conteudo_invalido)
            self.assertIsNone(carregar_ativos(caminho))
            with open(caminho, "r", encoding="utf-8") as arquivo:
                self.assertEqual(arquivo.read(), conteudo_invalido)

    def testar_json_preserva_dados(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos(self.ativos, caminho))
            recarregados = carregar_ativos(caminho)
        self.assertEqual(recarregados[10].nome, "SRV-ARQUIVOS")
        self.assertEqual(recarregados[10].criticidade, "Alta")


if __name__ == "__main__":
    unittest.main()
