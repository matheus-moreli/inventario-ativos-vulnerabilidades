"""Navegação homogênea para o terminal Windows/Linux.

Menus têm setas e Esc; campos aceitam Esc/Ctrl+C e /cancelar.
Nenhum formulário grava dados antes de confirmação.
"""

import os
import sys

from prompt_toolkit.application import Application
from prompt_toolkit.data_structures import Point
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.styles import Style

from dominio.validacoes import DadosInvalidosError

ERROS_TERMINAL = (OSError,)
if sys.platform == "win32":
    from prompt_toolkit.output.win32 import NoConsoleScreenBufferError

    ERROS_TERMINAL += (NoConsoleScreenBufferError,)


class OperacaoCancelada(Exception):
    """Usuário interrompeu o fluxo: nenhum rascunho deve ser confirmado."""


ESTILO = Style.from_dict(
    {
        "titulo": "bold #7dd3fc",
        "opcao": "#d1d5db",
        "selecionada": "bold #0b1220 bg:#7dd3fc",
        "instrucao": "#9ca3af",
    }
)


class Navegacao:
    """Componente único para escolhas, formulários e cancelamento."""

    def usar_setas(self):
        return (
            os.environ.get("INVENTARIO_MENU") != "simples"
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        )

    def menu(self, titulo, opcoes, indice_inicial=0):
        """Retorna o índice escolhido ou None ao pressionar Esc/0/Ctrl+C."""
        if not opcoes:
            return None
        if not self.usar_setas():
            return self.menu_numerico(titulo, opcoes)

        indice = max(0, min(indice_inicial, len(opcoes) - 1))
        teclas = KeyBindings()

        def desenhar():
            linhas = [("class:titulo", " ".join(titulo.splitlines()) + "\n\n")]
            for i, opcao in enumerate(opcoes):
                selecionada = i == indice
                marcador = "❯" if selecionada else " "
                estilo = "class:selecionada" if selecionada else "class:opcao"
                rotulo = " ".join(opcao.splitlines())
                linhas.append((estilo, f" {marcador}  {rotulo} \n"))
            linhas.append(("class:instrucao", "\n  0  ← Voltar / Sair"))
            linhas.append(("class:instrucao", "\n↑↓ Navegar   Enter Confirmar   Esc Cancelar"))
            return linhas

        @teclas.add("up")
        def subir(event):
            nonlocal indice
            indice = (indice - 1) % len(opcoes)
            event.app.invalidate()

        @teclas.add("down")
        def descer(event):
            nonlocal indice
            indice = (indice + 1) % len(opcoes)
            event.app.invalidate()

        @teclas.add("enter")
        def confirmar(event):
            event.app.exit(result=indice)

        @teclas.add("escape")
        @teclas.add("c-c")
        @teclas.add("0")
        def cancelar(event):
            event.app.exit(result=None)

        controle = FormattedTextControl(
            text=desenhar,
            focusable=True,
            get_cursor_position=lambda: Point(x=0, y=indice + 2),
        )
        janela = Window(
            content=controle,
            height=len(opcoes) + 5,
            dont_extend_height=True,
            always_hide_cursor=True,
        )
        try:
            return Application(
                layout=Layout(janela),
                key_bindings=teclas,
                style=ESTILO,
            ).run()
        except (EOFError, KeyboardInterrupt):
            return None
        except ERROS_TERMINAL:
            return self.menu_numerico(titulo, opcoes)

    def menu_numerico(self, titulo, opcoes):
        print("\n" + titulo)
        for indice, opcao in enumerate(opcoes, 1):
            print(f" {indice}. {opcao}")
        print(" 0. Voltar / Sair")
        while True:
            try:
                resposta = input("Escolha: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return None
            if resposta in ("0", "/cancelar", "/voltar", "/sair", ""):
                return None
            if (
                resposta.isascii()
                and resposta.isdecimal()
                and len(resposta) <= len(str(len(opcoes)))
            ):
                indice = int(resposta)
                if 1 <= indice <= len(opcoes):
                    return indice - 1
            print("Escolha uma opção válida.")

    def texto(self, rotulo, padrao=None, obrigatorio=True, conversor=None):
        """Lê campo validado. Esc ou /cancelar interrompe a operação inteira."""
        teclas = KeyBindings()

        @teclas.add("escape")
        @teclas.add("c-c")
        def sair(event):
            event.app.exit(result=None)

        setas = self.usar_setas()
        sessao = None
        while True:
            try:
                if setas:
                    if sessao is None:
                        sessao = PromptSession(key_bindings=teclas)
                    resposta = sessao.prompt(
                        f"{rotulo} (Esc cancela): ",
                        default="" if padrao is None else str(padrao),
                    )
                else:
                    resposta = input(f"{rotulo} (/cancelar): ")
                    if resposta == "" and padrao is not None:
                        resposta = str(padrao)
            except (EOFError, KeyboardInterrupt):
                raise OperacaoCancelada() from None
            except ERROS_TERMINAL:
                if not setas:
                    raise
                setas = False
                continue

            if resposta is None or resposta.strip().lower() in ("/cancelar", "/voltar", "/sair"):
                raise OperacaoCancelada()
            resposta = resposta.strip()
            if obrigatorio and not resposta:
                print("Este campo é obrigatório.")
                continue
            if conversor is not None and resposta:
                try:
                    resposta = conversor(resposta)
                except (ValueError, TypeError, DadosInvalidosError) as erro:
                    print(f"Valor inválido: {erro}")
                    continue
            return resposta

    def inteiro(self, rotulo, padrao=None):
        def converter(texto):
            numero = int(texto)
            if numero <= 0:
                raise ValueError("Informe um inteiro positivo.")
            return numero

        return self.texto(rotulo, padrao, conversor=converter)

    def escolha(self, titulo, opcoes, indice_inicial=0):
        indice = self.menu(titulo, opcoes, indice_inicial)
        if indice is None:
            raise OperacaoCancelada()
        return indice

    def confirmar(self, mensagem, risco=False):
        indice = self.menu(mensagem, ["Confirmar", "Cancelar"], 1 if risco else 0)
        if indice is None:
            raise OperacaoCancelada()
        return indice == 0
