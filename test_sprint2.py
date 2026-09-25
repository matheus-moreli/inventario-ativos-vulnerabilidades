"""Testes automatizados das regras de negócio da Sprint 2.

Execute com: python -m unittest -v test_sprint2.py
Cada teste cria dados próprios e não usa dados/inventario.json.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from interface import (VOLTAR, atualizar_ativo_tela, confirmar_remocao,
                       consultar_vulnerabilidades_tela, executar_programa,
                       ler_id_para_operacao, ler_texto_formulario,
                       ler_verificacao_formulario, resumo_vulnerabilidade,
                       salvar_com_aviso)
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

    def test_vulnerabilidade_com_dados_verificaveis(self):
        vulnerabilidade = self.cadastrar_vulnerabilidade_de_exemplo()
        self.assertEqual(vulnerabilidade.cvss, 7.5)
        resultado = consultar_vulnerabilidades(self.ativos, cve="CVE-2024-1234")
        self.assertEqual(len(resultado), 1)

    def test_resumo_da_vulnerabilidade_identifica_registro_sem_decorar_cve(self):
        vulnerabilidade = self.cadastrar_vulnerabilidade_de_exemplo()
        resumo = resumo_vulnerabilidade(self.ativos[10], vulnerabilidade)
        self.assertIn("CVE-2024-1234", resumo)
        self.assertIn("CVSS 7.5", resumo)
        self.assertIn("Alta", resumo)
        self.assertIn("SRV-ARQUIVOS", resumo)

    def test_consulta_por_lista_abre_vulnerabilidade_sem_digitar_filtros(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        tela = io.StringIO()
        # Simula: ver todas, abrir a primeira e voltar para a lista.
        with patch("interface.escolher_com_setas", side_effect=[0, 0, None]), \
                patch("interface.aguardar_retorno_lista"):
            with redirect_stdout(tela):
                consultar_vulnerabilidades_tela(self.ativos)
        self.assertIn("CVE-2024-1234", tela.getvalue())
        self.assertIn("SRV-ARQUIVOS", tela.getvalue())

    def test_consulta_por_id_mostra_apenas_vulnerabilidades_do_ativo(self):
        self.cadastrar_vulnerabilidade_de_exemplo()
        cadastrar_ativo(self.ativos, 20, "NOTEBOOK-ANA", "Ana", "Sala 2", 1, "Média")
        cadastrar_vulnerabilidade(
            self.ativos, 20, "CVE-2025-4321", "CWE-89", "6.0", "Outro teste",
            "Fonte", "02/01/2026", "Impacto", "Média", "Tratar"
        )
        tela = io.StringIO()
        # Simula: consultar por ID 10, abrir a vulnerabilidade e voltar.
        with patch("interface.ler_id_para_operacao", return_value=10):
            with patch("interface.escolher_com_setas", side_effect=[1, 0, None]), \
                    patch("interface.aguardar_retorno_lista"):
                with redirect_stdout(tela):
                    consultar_vulnerabilidades_tela(self.ativos)
        self.assertIn("CVE-2024-1234", tela.getvalue())
        self.assertNotIn("CVE-2025-4321", tela.getvalue())

    def test_letra_a_com_crase_nao_e_tratada_como_seta(self):
        with patch("interface.msvcrt.getwch", side_effect=["à", "\r"]), \
                patch("interface.msvcrt.kbhit", return_value=False):
            with redirect_stdout(io.StringIO()):
                texto = ler_texto_formulario("Localização")
        self.assertEqual(texto, "à")

    def test_letra_a_com_crase_em_texto_colado_e_preservada(self):
        with patch("interface.msvcrt.getwch", side_effect=["à", " ", "r", "\r"]), \
                patch("interface.msvcrt.kbhit", return_value=True):
            with redirect_stdout(io.StringIO()):
                texto = ler_texto_formulario("Localização")
        self.assertEqual(texto, "à r")

    def test_seta_esquerda_cancela_id_em_tela_simples(self):
        with patch("interface.ler_inteiro_formulario", return_value=VOLTAR):
            with redirect_stdout(io.StringIO()):
                self.assertIsNone(ler_id_para_operacao("ID do ativo"))

    def test_correcao_exige_verificacao_antes_de_finalizar_formulario(self):
        valores = {"status": "Corrigida"}
        with patch("interface.ler_texto_formulario", side_effect=["Pendente", "Teste aplicado"]):
            with redirect_stdout(io.StringIO()):
                verificacao = ler_verificacao_formulario(
                    valores, "Verificação", obrigatorio=False
                )
        self.assertEqual(verificacao, "Teste aplicado")

    def test_correcao_mantem_verificacao_atual_que_ja_e_valida(self):
        valores = {"status": "Corrigida"}
        with patch("interface.ler_texto_formulario", return_value=""):
            with redirect_stdout(io.StringIO()):
                verificacao = ler_verificacao_formulario(
                    valores, "Verificação", obrigatorio=False,
                    verificacao_atual="Teste da atualização aplicado"
                )
        self.assertEqual(verificacao, "")

    def test_confirmacao_de_remocao_inicia_em_cancelar(self):
        with patch("interface.escolher_com_setas", return_value=1) as escolha:
            self.assertFalse(confirmar_remocao())
        self.assertEqual(escolha.call_args.args[3], 1)

    def test_falha_ao_salvar_e_informada_pela_interface(self):
        with patch("interface.salvar_ativos", return_value=False):
            with redirect_stdout(io.StringIO()) as tela:
                self.assertFalse(salvar_com_aviso(self.ativos, "dados/inventario.json"))
        self.assertIn("Não foi possível salvar", tela.getvalue())

    def test_saida_pode_ser_confirmada_sem_salvar(self):
        with patch("interface.mostrar_menu", return_value="0"), \
                patch("interface.salvar_ativos", return_value=False), \
                patch("interface.ler_sim_ou_nao", return_value=True):
            with redirect_stdout(io.StringIO()) as tela:
                executar_programa(self.ativos, "dados/inventario.json")
        self.assertIn("sem salvar", tela.getvalue())

    def test_troca_de_id_na_atualizacao_nao_reaproveita_outro_ativo(self):
        cadastrar_ativo(self.ativos, 20, "NOTEBOOK-ANA", "Ana", "Sala 2", 1, "Média")
        respostas_de_texto = ["Nome temporário", VOLTAR, VOLTAR, "", "", ""]
        chamadas_de_texto = []

        def texto_controlado(mensagem, obrigatorio, anterior, preenchido):
            chamadas_de_texto.append((mensagem, anterior, preenchido))
            return respostas_de_texto.pop(0)

        with patch("interface.ler_inteiro_formulario", side_effect=[10, 20]), \
                patch("interface.ler_texto_formulario", side_effect=texto_controlado), \
                patch("interface.escolher_tipo_atualizacao", return_value=None), \
                patch("interface.escolher_item_atualizacao", return_value=None):
            with redirect_stdout(io.StringIO()):
                atualizar_ativo_tela(self.ativos)

        self.assertEqual(self.ativos[20].nome, "NOTEBOOK-ANA")
        self.assertIn(("Nome ou hostname [NOTEBOOK-ANA]", None, False), chamadas_de_texto)

    def test_cvss_com_virgula_e_aceito(self):
        vulnerabilidade = cadastrar_vulnerabilidade(
            self.ativos, 10, "CVE-2024-9999", "CWE-79", "9,8",
            "Exemplo", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar"
        )
        self.assertEqual(vulnerabilidade.cvss, 9.8)

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

    def test_data_da_fonte_invalida_e_rejeitada(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(self.ativos, 10, "CVE-2024-1234", "CWE-79", 5,
                "Teste", "Fonte", "2026-01-01", "Impacto", "Alta", "Tratar")

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

    def test_atualizacao_invalida_nao_altera_a_vulnerabilidade(self):
        cadastrar_vulnerabilidade(
            self.ativos, 10, "CVE-2024-5678", "CWE-79", 5,
            "Descrição original", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar")
        vulnerabilidade = self.ativos[10].vulnerabilidades[0]
        with self.assertRaises(DadosInvalidosError):
            atualizar_vulnerabilidade(self.ativos, 10, "CVE-2024-5678",
                                      descricao="Descrição nova", status="Corrigida")
        self.assertEqual(vulnerabilidade.descricao, "Descrição original")
        self.assertEqual(vulnerabilidade.status, "Aberta")

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

    def test_cadastro_corrigido_exige_verificacao(self):
        with self.assertRaises(DadosInvalidosError):
            cadastrar_vulnerabilidade(
                self.ativos, 10, "CVE-2024-9999", "CWE-79", 5,
                "Teste", "Fonte", "01/01/2026", "Impacto", "Alta", "Tratar",
                "Corrigida", "Pendente")

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


if __name__ == "__main__":
    unittest.main()
