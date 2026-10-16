"""Ponto de entrada do Inventário de Ativos e Vulnerabilidades."""

import os
import sys

from interface import InterfaceTerminal
from inventario import Inventario
from persistencia import RepositorioJSON
from servico import ServicoInventario

# O caminho parte desta pasta, mesmo se o comando for executado de outro local.
PASTA_DO_PROJETO = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_DADOS = os.environ.get(
    "INVENTARIO_DADOS", os.path.join(PASTA_DO_PROJETO, "dados", "inventario.json")
)


class Aplicacao:
    """Coordena a leitura da base e a forma de execução escolhida."""

    def __init__(self, caminho_dados=ARQUIVO_DADOS):
        self.caminho_dados = caminho_dados

    def iniciar(self, modo_servico=False):
        ativos = RepositorioJSON(self.caminho_dados).carregar()
        # None indica arquivo inválido. Encerrar evita apagar dados por acidente.
        if ativos is None:
            print("Corrija ou recupere o arquivo JSON antes de iniciar o programa.")
            return False
        inventario = Inventario(ativos)
        if modo_servico:
            ServicoInventario(inventario, caminho_dados=self.caminho_dados).executar()
        else:
            try:
                InterfaceTerminal(inventario, self.caminho_dados).executar()
            except EOFError:
                print("Entrada encerrada. Use um terminal interativo para o menu.")
        return True


def iniciar(modo_servico=False):
    """Entrada compatível com o menu usado desde a primeira entrega."""
    return Aplicacao().iniciar(modo_servico)


# Assim os testes podem importar funções sem abrir o menu interativo.
if __name__ == "__main__":
    raise SystemExit(0 if iniciar("--servico" in sys.argv[1:]) else 1)
