"""Testes automatizados das regras de negócio da Sprint 2.

Execute com: python -m pytest -q test_inventario.py
Cada teste cria dados próprios e não usa dados/inventario.json.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from dominio.inventario import (
    DadosInvalidosError,
    atualizar_ativo,
    atualizar_vulnerabilidade,
    cadastrar_ativo,
    cadastrar_vulnerabilidade,
    consultar_por_id,
    consultar_vulnerabilidades,
    excluir_ativo,
    excluir_vulnerabilidade,
    filtrar_ativos,
)
from infraestrutura.persistencia import RepositorioJSON, carregar_ativos, salvar_ativos


class TesteInventario(unittest.TestCase):
    """Cada teste cria a própria base, sem depender do JSON real do projeto."""

    def setUp(self):
        self.ativos = {}
        cadastrar_ativo(
            self.ativos, 10, "SRV-ARQUIVOS", "Equipe TI", "Datacenter", 2, "Alta"
        )

    def cadastrar_vulnerabilidade_de_exemplo(self):
        """Evita repetir os mesmos dados válidos em vários testes."""
        return cadastrar_vulnerabilidade(
            self.ativos,
            10,
            "CVE-2024-1234",
            "CWE-79",
            "7.5",
            "Exemplo de validação",
            "https://nvd.nist.gov",
            "01/01/2026",
            "Execução de código",
            "Alta",
            "Aplicar correção",
            "Aberta",
            "Validar versão após atualização",
        )

    def test_cadastro_e_busca_por_id(self):
        ativo = consultar_por_id(self.ativos, 10)
        self.assertIsNotNone(ativo)
        self.assertEqual(ativo.nome, "SRV-ARQUIVOS")
        self.assertIsNone(consultar_por_id(self.ativos, 999))

    def test_id_duplicado_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 10, "OUTRO", "TI", "Sala 1", 1, "Baixa")

    def test_nome_duplicado_e_rejeitado(self):
        """Hostname repetido não pode identificar dois ativos diferentes."""
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(
                self.ativos, 20, " srv-arquivos ", "TI", "Sala 1", 1, "Baixa"
            )
        self.assertNotIn(20, self.ativos)

    def test_atualizacao_nao_permite_nome_de_outro_ativo(self):
        cadastrar_ativo(self.ativos, 20, "NOTEBOOK-ANA", "Ana", "Sala 2", 1, "Média")
        with self.assertRaises(DadosInvalidosError):
            atualizar_ativo(self.ativos, 20, nome="SRV-ARQUIVOS")
        self.assertEqual(self.ativos[20].nome, "NOTEBOOK-ANA")

    def test_tipo_invalido_e_rejeitado(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 20, "APP", "TI", "Nuvem", 99, "Média")
        with self.assertRaises(DadosInvalidosError):
            cadastrar_ativo(self.ativos, 20, "APP", "TI", "Nuvem", True, "Média")

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

    def test_atualizacao_invalida_nao_altera_o_ativo(self):
        ativo = self.ativos[10]
        with self.assertRaises(DadosInvalidosError):
            atualizar_ativo(self.ativos, 10, nome="NOVO-NOME", responsavel="   ")
        self.assertEqual(ativo.nome, "SRV-ARQUIVOS")
        self.assertEqual(ativo.responsavel, "Equipe TI")

    def test_exclusao_exige_confirmacao(self):
        self.assertFalse(excluir_ativo(self.ativos, 10, False))
        self.assertIn(10, self.ativos)
        self.assertTrue(excluir_ativo(self.ativos, 10, True))
        self.assertNotIn(10, self.ativos)

    def test_exclusao_remove_vulnerabilidades_e_dependencias(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        cadastrar_ativo(self.ativos, 20, "APP-PORTAL", "TI", "Nuvem", 4, "Alta")
        self.ativos[20].dependencias.append({"ativo_id": 10, "peso": 0.3})
        self.assertTrue(excluir_ativo(self.ativos, 10, True))
        self.assertEqual(consultar_vulnerabilidades(self.ativos), [])
        self.assertEqual(self.ativos[20].dependencias, [])

    def test_vulnerabilidade_com_dados_verificaveis(self):
        vulnerabilidade = self.cadastrar_vulnerabilidade_de_exemplo()
        self.assertEqual(vulnerabilidade.cvss, 7.5)
        resultado = consultar_vulnerabilidades(self.ativos, cve="CVE-2024-1234")
        self.assertEqual(len(resultado), 1)

    def test_cvss_com_virgula_e_aceito(self):
        vulnerabilidade = cadastrar_vulnerabilidade(
            self.ativos,
            10,
            "CVE-2024-9999",
            "CWE-79",
            "9,8",
            "Exemplo",
            "Fonte",
            "01/01/2026",
            "Impacto",
            "Alta",
            "Tratar",
        )
        self.assertEqual(vulnerabilidade.cvss, 9.8)

    def test_cve_e_cvss_invalidos_sao_rejeitados(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos,
                10,
                "123",
                "CWE-79",
                5,
                "Teste",
                "Fonte",
                "01/01/2026",
                "Impacto",
                "Alta",
                "Tratar",
            )
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos,
                10,
                "CVE-2024-1234",
                "CWE-79",
                11,
                "Teste",
                "Fonte",
                "01/01/2026",
                "Impacto",
                "Alta",
                "Tratar",
            )
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos,
                10,
                "CVE-2024-1234",
                "CWE-79",
                "nan",
                "Teste",
                "Fonte",
                "01/01/2026",
                "Impacto",
                "Alta",
                "Tratar",
            )

    def test_data_da_fonte_invalida_e_rejeitada(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos,
                10,
                "CVE-2024-1234",
                "CWE-79",
                5,
                "Teste",
                "Fonte",
                "2026-01-01",
                "Impacto",
                "Alta",
                "Tratar",
            )

    def test_cve_duplicado_no_mesmo_ativo_e_rejeitado(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        with self.assertRaises(DadosInvalidosError):
            self.cadastrar_vulnerabilidade_de_exemplo()

    def test_atualizacao_de_vulnerabilidade_registra_historico(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        atualizar_vulnerabilidade(
            self.ativos,
            10,
            "CVE-2024-1234",
            status="Em tratamento",
            verificacao="Revisar versão",
        )
        vulnerabilidade = self.ativos[10].vulnerabilidades[0]
        self.assertEqual(vulnerabilidade.status, "Em tratamento")
        self.assertEqual(vulnerabilidade.verificacao, "Revisar versão")
        self.assertIn("atualizada", self.ativos[10].historico[-1])

    def test_atualizacao_invalida_nao_altera_a_vulnerabilidade(self):
        cadastrar_vulnerabilidade(
            self.ativos,
            10,
            "CVE-2024-5678",
            "CWE-79",
            5,
            "Descrição original",
            "Fonte",
            "01/01/2026",
            "Impacto",
            "Alta",
            "Tratar",
        )
        vulnerabilidade = self.ativos[10].vulnerabilidades[0]
        with self.assertRaises(DadosInvalidosError):
            atualizar_vulnerabilidade(
                self.ativos,
                10,
                "CVE-2024-5678",
                descricao="Descrição nova",
                status="Corrigida",
            )
        self.assertEqual(vulnerabilidade.descricao, "Descrição original")
        self.assertEqual(vulnerabilidade.status, "Aberta")

    def test_remocao_de_vulnerabilidade_exige_confirmacao(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        self.assertFalse(
            excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", False)
        )
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 1)
        self.assertTrue(excluir_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", True))
        self.assertEqual(len(self.ativos[10].vulnerabilidades), 0)

    def test_correcao_exige_verificacao(self):
        # Não informamos verificação: a função usa o padrão "Pendente".
        cadastrar_vulnerabilidade(
            self.ativos,
            10,
            "CVE-2024-5678",
            "CWE-79",
            5,
            "Teste",
            "Fonte",
            "01/01/2026",
            "Impacto",
            "Alta",
            "Tratar",
        )
        with self.assertRaises(DadosInvalidosError):
            atualizar_vulnerabilidade(
                self.ativos, 10, "CVE-2024-5678", status="Corrigida"
            )

    def test_cadastro_corrigido_exige_verificacao(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos,
                10,
                "CVE-2024-9999",
                "CWE-79",
                5,
                "Teste",
                "Fonte",
                "01/01/2026",
                "Impacto",
                "Alta",
                "Tratar",
                "Corrigida",
                "Pendente",
            )

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
        vulnerabilidade = self.cadastrar_vulnerabilidade_de_exemplo()
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(salvar_ativos(self.ativos, caminho))
            recarregados = carregar_ativos(caminho)
        self.assertEqual(recarregados[10].nome, "SRV-ARQUIVOS")
        self.assertEqual(recarregados[10].criticidade, "Alta")
        self.assertEqual(recarregados[10].vulnerabilidades[0].cve, vulnerabilidade.cve)
        self.assertEqual(recarregados[10].vulnerabilidades[0].cvss, 7.5)

    def test_falha_na_substituicao_preserva_json_anterior(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            self.assertTrue(RepositorioJSON(caminho).salvar(self.ativos))
            with open(caminho, "r", encoding="utf-8") as arquivo:
                anterior = arquivo.read()
            with patch("infraestrutura.persistencia.os.replace", side_effect=OSError("disco")):
                with redirect_stdout(io.StringIO()):
                    self.assertFalse(RepositorioJSON(caminho).salvar({}))
            with open(caminho, "r", encoding="utf-8") as arquivo:
                self.assertEqual(arquivo.read(), anterior)
            self.assertEqual(os.listdir(pasta), ["inventario.json"])

    def test_json_do_trabalho_1_e_lido_e_gravado_como_lista(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            registro = self.ativos[10].para_dicionario()
            for campo in ("dependencias", "nome_tipo_personalizado", "campos_extras"):
                registro.pop(campo)
            with open(caminho, "w", encoding="utf-8") as arquivo:
                json.dump({"10": registro}, arquivo)

            ativos = carregar_ativos(caminho)
            self.assertEqual(ativos[10].nome, registro["nome"])
            self.assertEqual(ativos[10].dependencias, [])
            self.assertTrue(salvar_ativos(ativos, caminho))

            with open(caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
            self.assertIsInstance(dados, list)
            self.assertEqual(dados[0]["id"], 10)

    def test_json_com_id_inconsistente_e_rejeitado(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            dados = {
                "10": {
                    "id": 99,
                    "nome": "SRV-ARQUIVOS",
                    "responsavel": "Equipe TI",
                    "localizacao": "Datacenter",
                    "tipo": 2,
                    "criticidade": "Alta",
                    "vulnerabilidades": [],
                    "historico": [],
                }
            }
            with open(caminho, "w", encoding="utf-8") as arquivo:
                json.dump(dados, arquivo)
            with redirect_stdout(io.StringIO()):
                self.assertIsNone(carregar_ativos(caminho))

    def test_json_com_regra_invalida_e_rejeitado(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "inventario.json")
            dados = {
                "10": {
                    "id": 10,
                    "nome": "SRV-ARQUIVOS",
                    "responsavel": "Equipe TI",
                    "localizacao": "Datacenter",
                    "tipo": 99,
                    "criticidade": "Alta",
                    "vulnerabilidades": [],
                    "historico": [],
                }
            }
            with open(caminho, "w", encoding="utf-8") as arquivo:
                json.dump(dados, arquivo)
            with redirect_stdout(io.StringIO()):
                self.assertIsNone(carregar_ativos(caminho))


def test_persistencia_atomica_rejeita_valor_nao_finito(tmp_path):
    caminho = tmp_path / "inventario.json"
    repositorio = RepositorioJSON(caminho)
    ativos = {}
    ativo = cadastrar_ativo(ativos, 7, "SRV-07", "TI", "Sala", 2, "Alta")
    assert repositorio.salvar(ativos)
    original = caminho.read_bytes()
    registro = ativo.para_dicionario()
    registro["campos_extras"] = {"entrada inválida": float("nan")}
    with patch.object(ativo, "para_dicionario", return_value=registro):
        assert not repositorio.salvar(ativos)
    assert caminho.read_bytes() == original
    assert list(tmp_path.iterdir()) == [caminho]
    assert repositorio.carregar()[7].nome == "SRV-07"


if __name__ == "__main__":
    unittest.main()
