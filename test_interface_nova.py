"""Testes da interface nova: transações, cancelamentos e risco atualizado."""
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from rich.console import Console

from apresentacao.interface_rica import InterfaceRica
from apresentacao.navegacao import Navegacao, OperacaoCancelada
from dominio.inventario import Inventario
from dominio.risco import AnalisadorRisco
from infraestrutura.persistencia import RepositorioJSON


class NavegacaoFalsa:
    def __init__(self, escolhas=(), textos=(), inteiros=(), confirmacoes=()):
        self.escolhas = iter(escolhas)
        self.textos = iter(textos)
        self.inteiros = iter(inteiros)
        self.confirmacoes = iter(confirmacoes)

    def escolha(self, *_args, **_kwargs):
        valor = next(self.escolhas)
        if isinstance(valor, Exception):
            raise valor
        return valor

    def texto(self, *_args, **kwargs):
        valor = next(self.textos)
        if isinstance(valor, Exception):
            raise valor
        conversor = kwargs.get("conversor")
        return conversor(valor) if conversor else valor

    def inteiro(self, *_args, **_kwargs):
        valor = next(self.inteiros)
        if isinstance(valor, Exception):
            raise valor
        return valor

    def confirmar(self, *_args, **_kwargs):
        valor = next(self.confirmacoes)
        if isinstance(valor, Exception):
            raise valor
        return valor


class TesteInterfaceUnificada(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.caminho = os.path.join(self.temp.name, "inventario.json")
        self.inv = Inventario()
        self.tela = InterfaceRica(
            self.inv, self.caminho,
            navegacao=NavegacaoFalsa(),
            console=Console(file=io.StringIO(), force_terminal=False),
        )

    def test_cadastro_por_fluxo_unificado_persiste(self):
        self.tela.nav = NavegacaoFalsa(
            inteiros=[7],
            textos=["NB-07", "TI", "Sala 2"],
            escolhas=[0, 1],
            confirmacoes=[False, False, True],
        )
        self.tela.novo_ativo()
        self.assertEqual(self.inv[7].nome, "NB-07")
        self.assertEqual(RepositorioJSON(self.caminho).carregar()[7].nome, "NB-07")
        self.assertEqual(AnalisadorRisco(self.inv.ativos).calcular()[-1], [0.0])

    def test_cancelar_durante_cadastro_nao_salva_nada(self):
        self.tela.nav = NavegacaoFalsa(
            inteiros=[7],
            textos=[OperacaoCancelada()],
        )
        with self.assertRaises(OperacaoCancelada):
            self.tela.novo_ativo()
        self.assertEqual(len(self.inv), 0)
        self.assertFalse(os.path.exists(self.caminho))

    def test_cadastro_tipo_personalizado_sem_interface_antiga(self):
        self.tela.nav = NavegacaoFalsa(
            inteiros=[8, 100],
            textos=["FW-08", "Equipe", "Rack", "Firewall"],
            escolhas=[6, 2],
            confirmacoes=[False, False, True],
        )
        self.tela.novo_ativo()
        ativo = RepositorioJSON(self.caminho).carregar()[8]
        self.assertEqual(ativo.nome_do_tipo(), "Firewall")
        self.assertEqual(ativo.tipo, 100)

    def test_risco_recalculado_apos_incluir_e_excluir_vulnerabilidade(self):
        self.inv.cadastrar_ativo(1, "SRV-01", "TI", "Sala", 2, "Alta")
        self.assertEqual(AnalisadorRisco(self.inv.ativos).calcular()[-1], [0.0])
        self.tela.nav = NavegacaoFalsa(confirmacoes=[True])
        self.tela.transacao(lambda inv: inv.cadastrar_vulnerabilidade(
            1, "CVE-2026-1234", "CWE-79", 9.8, "Falha", "NVD",
            "01/01/2026", "Impacto", "Alta", "Corrigir",
        ))
        self.assertEqual(AnalisadorRisco(self.inv.ativos).calcular()[-1], [9.8])
        self.tela.transacao(
            lambda inv: inv.excluir_vulnerabilidade(1, "CVE-2026-1234", True),
            confirmar=False,
        )
        self.assertEqual(AnalisadorRisco(self.inv.ativos).calcular()[-1], [0.0])
        self.assertEqual(
            AnalisadorRisco(RepositorioJSON(self.caminho).carregar()).calcular()[-1],
            [0.0],
        )

    def test_cancelar_edicao_depois_de_mudar_rascunho_reverte(self):
        self.inv.cadastrar_ativo(1, "SRV-01", "TI", "Sala", 2, "Alta")
        self.assertTrue(RepositorioJSON(self.caminho).salvar(self.inv.ativos))
        self.tela.nav = NavegacaoFalsa(
            escolhas=[0, 0, OperacaoCancelada()],
            textos=["TEMPORARIO"],
        )
        with self.assertRaises(OperacaoCancelada):
            self.tela.atualizar_ativo()
        self.assertEqual(self.inv[1].nome, "SRV-01")
        self.assertEqual(
            RepositorioJSON(self.caminho).carregar()[1].nome, "SRV-01"
        )

    def test_cancelar_na_confirmacao_nao_persiste(self):
        self.tela.nav = NavegacaoFalsa(confirmacoes=[False])
        with self.assertRaises(OperacaoCancelada):
            self.tela.transacao(
                lambda inv: inv.cadastrar_ativo(
                    1, "SRV", "TI", "Sala", 2, "Alta"
                )
            )
        self.assertEqual(len(self.inv), 0)

    def test_falha_na_gravacao_nao_publica_rascunho(self):
        self.tela.nav = NavegacaoFalsa(confirmacoes=[True])
        with patch("apresentacao.interface_rica.RepositorioJSON.salvar",
                   return_value=False):
            with self.assertRaisesRegex(Exception, "Falha na gravação"):
                self.tela.transacao(
                    lambda inv: inv.cadastrar_ativo(
                        1, "SRV", "TI", "Sala", 2, "Alta"
                    )
                )
        self.assertEqual(len(self.inv), 0)

    def test_menu_fallback_com_zero_cancela(self):
        nav = Navegacao()
        with patch("apresentacao.navegacao.sys.stdin.isatty",
                   return_value=False), patch("builtins.input", return_value="0"):
            self.assertIsNone(nav.menu("Opções", ["Um", "Dois"]))

    def test_setas_para_baixo_e_enter_escolhem_segunda_opcao(self):
        from prompt_toolkit.application import Application
        from prompt_toolkit.input.defaults import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        with create_pipe_input() as entrada:
            entrada.send_text("\\x1b[B\\r".encode().decode("unicode_escape"))

            def criar_app(*args, **kwargs):
                return Application(
                    *args, **kwargs, input=entrada, output=DummyOutput()
                )

            with patch("apresentacao.navegacao.sys.stdin.isatty",
                       return_value=True), patch(
                "apresentacao.navegacao.Application", side_effect=criar_app
            ):
                self.assertEqual(
                    Navegacao().menu("Ações", ["Primeira", "Segunda"]), 1
                )

    def test_esc_volta_sem_selecionar(self):
        from prompt_toolkit.application import Application
        from prompt_toolkit.input.defaults import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        with create_pipe_input() as entrada:
            entrada.send_text("\\x1b".encode().decode("unicode_escape"))

            def criar_app(*args, **kwargs):
                return Application(
                    *args, **kwargs, input=entrada, output=DummyOutput()
                )

            with patch("apresentacao.navegacao.sys.stdin.isatty",
                       return_value=True), patch(
                "apresentacao.navegacao.Application", side_effect=criar_app
            ):
                self.assertIsNone(Navegacao().menu("Ações", ["Primeira"]))

    def test_texto_cancelar_por_comando(self):
        nav = Navegacao()
        with patch("apresentacao.navegacao.sys.stdin.isatty",
                   return_value=False), patch("builtins.input",
                   return_value="/cancelar"):
            with self.assertRaises(OperacaoCancelada):
                nav.texto("Hostname")


if __name__ == "__main__":
    unittest.main()
