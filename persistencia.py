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
        if not isinstance(dados, list):
            raise DadosInvalidosError("A base deve conter uma lista de ativos.")
        ativos = {}
        for dados_ativo in dados:
            if not isinstance(dados_ativo, dict):
                raise ValueError("Ativo inválido no arquivo de dados.")
            ativo = Ativo.de_dicionario(dados_ativo)
            if ativo.id in ativos:
                raise ValueError("ID repetido no arquivo de dados.")
            ativos[ativo.id] = validar_ativo_carregado(ativo)
        nomes = set()
        for ativo in ativos.values():
            nome = ativo.nome.lower()
            if nome in nomes:
                raise DadosInvalidosError("Nome ou hostname repetido no arquivo de dados.")
            nomes.add(nome)
            for dependencia in ativo.dependencias:
                if dependencia["ativo_id"] not in ativos:
                    raise DadosInvalidosError("Dependência aponta para ativo inexistente.")
        return ativos
    except (OSError, json.JSONDecodeError, ValueError, KeyError, TypeError,
            AttributeError, DadosInvalidosError):
        print("Não foi possível ler o arquivo de dados. Ele não será sobrescrito.")
        return None


def salvar_ativos(ativos, caminho):
    """Converte os objetos em dicionários e grava um JSON legível."""
    dados = []
    for identificador in sorted(ativos):
        dados.append(ativos[identificador].para_dicionario())
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
