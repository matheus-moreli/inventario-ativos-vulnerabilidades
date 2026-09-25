"""Ponto de entrada do Inventário de Ativos e Vulnerabilidades."""

import os

from interface import executar_programa
from persistencia import carregar_ativos


# O caminho parte desta pasta, mesmo se o comando for executado de outro local.
PASTA_DO_PROJETO = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_DADOS = os.path.join(PASTA_DO_PROJETO, "dados", "inventario.json")


def iniciar():
    """Carrega a base uma vez e inicia a interface do terminal."""
    ativos = carregar_ativos(ARQUIVO_DADOS)
    # None indica que havia um arquivo inválido. Encerrar evita apagar dados por acidente.
    if ativos is None:
        print("Corrija ou recupere o arquivo JSON antes de iniciar o programa.")
        return
    executar_programa(ativos, ARQUIVO_DADOS)


# Assim os testes podem importar funções sem abrir o menu interativo.
if __name__ == "__main__":
    iniciar()
