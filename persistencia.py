"""Leitura e gravação do inventário em JSON."""

import json
import os

from inventario import DadosInvalidosError, validar_ativo_carregado
from modelos import Ativo


def carregar_ativos(caminho):
    """Lê o JSON e devolve um dicionário {id: objeto Ativo}."""
    if not os.path.exists(caminho):
        return {}
    try:
        with open(caminho, "r", encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        if not isinstance(dados, dict):
            raise DadosInvalidosError("A base deve conter ativos por ID.")
        ativos = {}
        for identificador, dados_ativo in dados.items():
            if not isinstance(dados_ativo, dict):
                raise ValueError("Ativo inválido no arquivo de dados.")
            chave = int(identificador)
            ativo = Ativo.de_dicionario(dados_ativo)
            if ativo.id != chave:
                raise ValueError("ID do ativo não corresponde à chave do arquivo.")
            ativos[chave] = validar_ativo_carregado(ativo)
        return ativos
    except (OSError, json.JSONDecodeError, ValueError, KeyError, TypeError,
            AttributeError, DadosInvalidosError):
        print("Não foi possível ler o arquivo de dados. Ele não será sobrescrito.")
        return None


def salvar_ativos(ativos, caminho):
    """Converte os objetos em dicionários e grava um JSON legível."""
    dados = {}
    for identificador, ativo in ativos.items():
        dados[str(identificador)] = ativo.para_dicionario()
    try:
        pasta = os.path.dirname(caminho)
        if pasta:
            os.makedirs(pasta, exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, ensure_ascii=False, indent=2)
        return True
    except OSError:
        print("Erro ao salvar os dados no arquivo.")
        return False
