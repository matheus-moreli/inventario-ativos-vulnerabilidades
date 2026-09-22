"""Ponto de entrada do Inventário de Ativos e Vulnerabilidades."""

from interface import executar_programa
from persistencia import carregar_ativos


# O caminho é configuração de execução, não uma regra de negócio do inventário.
ARQUIVO_DADOS = "dados/inventario.json"


def iniciar():
    """Carrega a base uma vez e inicia a interface do terminal."""
    ativos = carregar_ativos(ARQUIVO_DADOS)
    executar_programa(ativos, ARQUIVO_DADOS)


# Assim os testes podem importar funções sem abrir o menu interativo.
if __name__ == "__main__":
    iniciar()
