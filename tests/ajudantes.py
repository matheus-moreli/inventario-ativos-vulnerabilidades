"""Atalhos funcionais usados pelos testes sobre o dicionário de ativos."""

from dominio.inventario import Inventario
from dominio.risco import AnalisadorRisco, SistemaLinear
from infraestrutura.persistencia import RepositorioJSON


def _como_inventario(ativos):
    return ativos if isinstance(ativos, Inventario) else Inventario(ativos)


def _atalho(metodo):
    def chamar(ativos, *args, **kwargs):
        return getattr(_como_inventario(ativos), metodo)(*args, **kwargs)

    chamar.__name__ = metodo
    return chamar


validar_nome_unico = _atalho("validar_nome_unico")
cadastrar_ativo = _atalho("cadastrar_ativo")
consultar_por_id = _atalho("consultar_por_id")
filtrar_ativos = _atalho("filtrar_ativos")
atualizar_ativo = _atalho("atualizar_ativo")
excluir_ativo = _atalho("excluir_ativo")
adicionar_dependencia = _atalho("adicionar_dependencia")
remover_dependencia = _atalho("remover_dependencia")
cadastrar_vulnerabilidade = _atalho("cadastrar_vulnerabilidade")
atualizar_vulnerabilidade = _atalho("atualizar_vulnerabilidade")
excluir_vulnerabilidade = _atalho("excluir_vulnerabilidade")
consultar_vulnerabilidades = _atalho("consultar_vulnerabilidades")


def calcular_riscos(ativos):
    return AnalisadorRisco(ativos).calcular()


def resolver_sistema(matriz, vetor):
    return SistemaLinear(matriz).resolver(vetor)


def numero_condicao_infinito(matriz):
    return SistemaLinear(matriz).condicionamento()


def carregar_ativos(caminho):
    return RepositorioJSON(caminho).carregar()


def salvar_ativos(ativos, caminho):
    return RepositorioJSON(caminho).salvar(ativos)
