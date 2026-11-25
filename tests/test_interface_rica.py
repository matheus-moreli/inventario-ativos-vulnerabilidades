"""Testes da interface nova: transações, cancelamentos e risco atualizado."""
import io
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from rich.console import Console

from apresentacao.interface_rica import InterfaceRica
from apresentacao.navegacao import Navegacao, OperacaoCancelada
from dominio.inventario import DadosInvalidosError, Inventario
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

    def menu(self, *_args, **_kwargs):
        return next(self.escolhas)

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

    def test_listagem_pagina_e_preserva_texto_literal_em_terminal_estreito(self):
        for identificador in range(1, 10):
            self.inv.cadastrar_ativo(
                identificador, f"SRV-{identificador:02d}[/]", "TI", "Sala", 2, "Alta",
            )
        saida = io.StringIO()
        self.tela.console = Console(file=saida, force_terminal=False, width=42, height=18)
        self.tela.nav = NavegacaoFalsa(escolhas=[0, 1])
        self.assertFalse(self.tela.listar_ativos())
        tela = saida.getvalue()
        self.assertIn("1/2", tela)
        self.assertIn("2/2", tela)
        self.assertIn("SRV-09[/]", tela)
        self.assertNotIn("Responsável", tela)

    def test_busca_cve_preserva_descricao_e_abre_a_ficha_correta(self):
        for identificador in (7, 8):
            self.inv.cadastrar_ativo(identificador, f"SRV-{identificador}", "TI", "Sala", 2, "Alta")
            self.inv.cadastrar_vulnerabilidade(
                identificador, f"CVE-2026-123{identificador}", "CWE-79", 8, "Falha [/] registrada",
                "NVD", "01/01/2026", "Impacto", "Alta", "Tratar",
            )
        self.tela.nav = NavegacaoFalsa(escolhas=[0], textos=["CVE-2026-1238"])
        self.tela.buscar_vulnerabilidade()
        tela = self.tela.console.file.getvalue()
        self.assertIn("Falha [/] registrada", tela)
        self.assertIn("SRV-8", tela)
        self.assertNotIn("CVE-2026-1237", tela)

    def test_menu_principal_reutiliza_resumo_e_submenus_nao_recalculam(self):
        with patch.object(AnalisadorRisco, "calcular", return_value=([], [], [], [], [], [])) as calcular:
            self.tela.cabecalho("Menu principal")
            self.tela.cabecalho("Equipamentos")
            self.tela.cabecalho("Menu principal")
        calcular.assert_called_once()

    def test_menu_recupera_falha_de_renderizacao_com_modo_numerico(self):
        nav = Navegacao()
        with patch.object(nav, "usar_setas", return_value=True), patch(
            "apresentacao.navegacao.Application", side_effect=OSError
        ), patch("builtins.input", side_effect=["²", "2"]):
            self.assertEqual(nav.menu("Opções", ["Primeiro", "Segundo"]), 1)

    def test_edicao_de_peso_preserva_dependencia_se_novo_valor_for_invalido(self):
        self.inv.cadastrar_ativo(1, "NOTE", "TI", "Sala", 1, "Alta")
        self.inv.cadastrar_ativo(2, "APP", "TI", "Sala", 4, "Alta")
        self.inv.adicionar_dependencia(2, 1, 0.25)
        RepositorioJSON(self.caminho).salvar(self.inv.ativos)
        self.tela.nav = NavegacaoFalsa(escolhas=[0], textos=["1,25"])
        with self.assertRaises(DadosInvalidosError):
            self.tela.editar_dependencia()
        self.assertEqual(RepositorioJSON(self.caminho).carregar()[2].dependencias[0]["peso"], 0.25)
        self.assertEqual(self.inv[2].dependencias[0]["peso"], 0.25)
        self.tela.nav = NavegacaoFalsa(escolhas=[0], textos=["0,50"], confirmacoes=[True])
        self.tela.editar_dependencia()
        self.assertEqual(RepositorioJSON(self.caminho).carregar()[2].dependencias[0]["peso"], 0.5)

    def test_busca_por_id_e_por_hostname_abre_a_ficha(self):
        self.inv.cadastrar_ativo(7, "SRV-07", "TI", "Sala", 2, "Alta")
        self.inv.cadastrar_ativo(8, "SRV-08", "TI", "Sala", 2, "Alta")
        for navegacao in (
            NavegacaoFalsa(escolhas=[0], inteiros=[7]),
            NavegacaoFalsa(escolhas=[1], textos=["srv-07"]),
            NavegacaoFalsa(escolhas=[1, 0], textos=["srv"]),
        ):
            self.tela.nav = navegacao
            with patch.object(self.tela, "mostrar_ficha") as mostrar:
                self.tela.buscar_ativo()
                mostrar.assert_called_once_with(self.inv[7])
        self.tela.nav = NavegacaoFalsa(escolhas=[1], textos=["inexistente"])
        with self.assertRaisesRegex(DadosInvalidosError, "Nenhum equipamento"):
            self.tela.buscar_ativo()
        self.assertFalse(os.path.exists(self.caminho))

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

    def test_setas_e_escape_nos_menus(self):
        from prompt_toolkit.keys import Keys

        with patch.object(Navegacao, "usar_setas", return_value=True), patch(
            "apresentacao.navegacao.Application"
        ) as aplicativo:
            app = aplicativo.return_value

            def executar_escolha(teclas):
                for tecla in teclas:
                    vinculo = aplicativo.call_args.kwargs["key_bindings"].get_bindings_for_keys((tecla,))[0]
                    vinculo.handler(Mock(app=app))
                return app.exit.call_args.kwargs["result"]

            app.run.side_effect = lambda: executar_escolha([Keys.Down, Keys.ControlM])
            self.assertEqual(Navegacao().menu("Ações", ["Primeira", "Segunda"]), 1)
            app.run.side_effect = lambda: executar_escolha([Keys.Escape])
            self.assertIsNone(Navegacao().menu("Ações", ["Primeira"]))

    def test_escape_cancela_campo_de_texto_em_tty(self):
        from prompt_toolkit.keys import Keys

        with patch.object(Navegacao, "usar_setas", return_value=True), patch(
            "apresentacao.navegacao.PromptSession"
        ) as sessao:
            def digitar_escape(*_args, **_kwargs):
                app = Mock()
                teclas = sessao.call_args.kwargs["key_bindings"]
                teclas.get_bindings_for_keys((Keys.Escape,))[0].handler(Mock(app=app))
                return app.exit.call_args.kwargs["result"]

            sessao.return_value.prompt.side_effect = digitar_escape
            with self.assertRaises(OperacaoCancelada):
                Navegacao().texto("Nome")

    def test_texto_preserva_caracteres_acentuados(self):
        with patch.object(Navegacao, "usar_setas", return_value=True), patch(
            "apresentacao.navegacao.PromptSession"
        ) as sessao:
            sessao.return_value.prompt.return_value = "Sala à direita"
            self.assertEqual(Navegacao().texto("Localização"), "Sala à direita")

    def test_remocao_cancelada_preserva_memoria_e_arquivo(self):
        self.inv.cadastrar_ativo(7, "NB-07", "TI", "Sala", 1, "Alta")
        RepositorioJSON(self.caminho).salvar(self.inv.ativos)
        self.tela.nav = NavegacaoFalsa(escolhas=[0], confirmacoes=[False])
        with self.assertRaises(OperacaoCancelada):
            self.tela.remover_ativo()
        self.assertIn(7, self.inv)
        self.assertIn(7, RepositorioJSON(self.caminho).carregar())

    def test_ficha_por_id_exibe_apenas_vulnerabilidades_do_ativo(self):
        for identificador, cve in [(7, "CVE-2026-1234"), (8, "CVE-2026-1235")]:
            self.inv.cadastrar_ativo(identificador, f"SRV-{identificador}", "TI", "Sala", 2, "Alta")
            self.inv.cadastrar_vulnerabilidade(
                identificador, cve, "CWE-79", 8, "Caso didático",
                "NVD", "01/01/2026", "Impacto", "Alta", "Tratar",
            )
        self.tela.nav = NavegacaoFalsa(escolhas=[0], inteiros=[7])
        self.tela.buscar_ativo()
        exibido = self.tela.console.file.getvalue()
        self.assertIn("SRV-7", exibido)
        self.assertIn("CVE-2026-1234", exibido)
        self.assertNotIn("CVE-2026-1235", exibido)

    def test_alteracao_de_dependencia_recalcula_risco(self):
        self.inv.cadastrar_ativo(1, "SRV-01", "TI", "Rack", 2, "Alta")
        self.inv.cadastrar_ativo(2, "APP-01", "TI", "Rack", 4, "Alta")
        self.inv.cadastrar_vulnerabilidade(
            1, "CVE-2026-2222", "CWE-79", 8.0, "Falha", "NVD",
            "01/01/2026", "Impacto", "Alta", "Corrigir",
        )
        self.tela.nav = NavegacaoFalsa(confirmacoes=[True])
        self.tela.transacao(
            lambda inv: inv.adicionar_dependencia(2, 1, "0,25")
        )
        self.assertEqual(
            AnalisadorRisco(self.inv.ativos).calcular()[-1],
            [8.0, 2.0],
        )
        self.tela.transacao(
            lambda inv: inv.remover_dependencia(2, 1), confirmar=False
        )
        self.assertEqual(
            AnalisadorRisco(self.inv.ativos).calcular()[-1],
            [8.0, 0.0],
        )

    def test_texto_cancelar_por_comando(self):
        nav = Navegacao()
        with patch("apresentacao.navegacao.sys.stdin.isatty",
                   return_value=False), patch("builtins.input",
                   return_value="/cancelar"):
            with self.assertRaises(OperacaoCancelada):
                nav.texto("Hostname")


if __name__ == "__main__":
    unittest.main()
