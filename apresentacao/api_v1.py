"""Listagem versionada e erros estruturados da API do inventário."""

import json
from pathlib import Path
from urllib.parse import parse_qs

from dominio.inventario import Inventario
from dominio.risco import AnalisadorRisco

ROTA_ATIVOS = "/v1/ativos"
ROTA_RISCOS = "/v1/riscos"


def problema(codigo, titulo, detalhe):
    return codigo, {"type": "about:blank", "title": titulo, "status": codigo, "detail": detalhe}


def especificacao():
    caminho = Path(__file__).with_name("openapi.json")
    return json.loads(caminho.read_text(encoding="utf-8"))


def inteiro_limitado(valor, maximo):
    if len(valor) > len(str(maximo)) or not valor.isascii() or not valor.isdecimal():
        raise ValueError(f"Informe um inteiro entre 1 e {maximo}.")
    numero = int(valor)
    if not 1 <= numero <= maximo:
        raise ValueError(f"Informe um inteiro entre 1 e {maximo}.")
    return numero


def listar_ativos(ativos, consulta):
    """Lista paginada com busca por hostname e ordenação por risco."""
    try:
        campos = parse_qs(consulta, keep_blank_values=True, max_num_fields=4)
        if campos.keys() - {"busca", "pagina", "limite", "ordenar"}:
            raise ValueError("Há parâmetro desconhecido na consulta.")
        if any(len(valores) != 1 for valores in campos.values()):
            raise ValueError("Cada parâmetro pode aparecer apenas uma vez.")
        valores = {chave: itens[0] for chave, itens in campos.items()}
        pagina = inteiro_limitado(valores.get("pagina", "1"), 1_000_000)
        limite = inteiro_limitado(valores.get("limite", "20"), 100)
        busca = valores.get("busca", "").strip()
        if len(busca) > 120:
            raise ValueError("A busca aceita até 120 caracteres.")
        ordenar = valores.get("ordenar", "id")
        if ordenar not in {"id", "risco"}:
            raise ValueError("Use id ou risco no parâmetro ordenar.")
    except ValueError as erro:
        return problema(422, "Consulta inválida", str(erro))

    encontrados = Inventario(ativos).filtrar_ativos(termo=busca)
    riscos = {}
    if ordenar == "risco" and encontrados:
        try:
            equipamentos, _, _, _, _, efetivos = AnalisadorRisco(ativos).calcular()
        except (ValueError, KeyError) as erro:
            return problema(422, "Risco indisponível", str(erro))
        riscos = {ativo.id: risco for ativo, risco in zip(equipamentos, efetivos)}
    encontrados.sort(key=lambda ativo: (-riscos.get(ativo.id, 0), ativo.id))
    inicio = (pagina - 1) * limite
    return 200, {
        "pagina": pagina,
        "limite": limite,
        "total": len(encontrados),
        "itens": [
            {
                "id": ativo.id,
                "nome": ativo.nome,
                "tipo": ativo.nome_do_tipo(),
                "criticidade": ativo.criticidade,
                "vulnerabilidades": len(ativo.vulnerabilidades),
            }
            for ativo in encontrados[inicio : inicio + limite]
        ],
    }
