"""Regras de negócio do CRUD. Este arquivo não usa input nem print."""

from modelos import (Ativo, CRITICIDADES, SEVERIDADES, STATUS, TipoAtivo,
                     Vulnerabilidade)


class DadosInvalidosError(Exception):
    """Indica que uma regra do inventário não foi respeitada."""


def validar_texto(valor, campo):
    """Impede que campos obrigatórios recebam texto vazio."""
    if not isinstance(valor, str) or not valor.strip():
        raise DadosInvalidosError(f"{campo} é obrigatório.")
    return valor.strip()


def validar_opcao(valor, opcoes, campo):
    """Aceita somente uma das opções padronizadas e devolve sua forma oficial."""
    for opcao in opcoes:
        if isinstance(valor, str) and valor.lower() == opcao.lower():
            return opcao
    raise DadosInvalidosError(f"{campo} inválida. Escolha uma opção permitida.")


def validar_cve(cve):
    """Valida o formato básico CVE-AAAA-NÚMERO sem exigir bibliotecas extras."""
    partes = cve.strip().upper().split("-") if isinstance(cve, str) else []
    if len(partes) != 3 or partes[0] != "CVE":
        raise DadosInvalidosError("CVE inválido. Use o formato CVE-AAAA-NÚMERO.")
    if not partes[1].isdigit() or len(partes[1]) != 4 or not partes[2].isdigit():
        raise DadosInvalidosError("CVE inválido. Use o formato CVE-AAAA-NÚMERO.")
    return "-".join(partes)


def validar_cvss(cvss):
    """Converte a nota CVSS e garante o intervalo oficial de 0.0 a 10.0."""
    try:
        nota = float(cvss)
    except (TypeError, ValueError):
        raise DadosInvalidosError("CVSS deve ser um número entre 0.0 e 10.0.")
    # Esta forma também rejeita "nan", que não é uma nota válida.
    if not 0.0 <= nota <= 10.0:
        raise DadosInvalidosError("CVSS deve estar entre 0.0 e 10.0.")
    return nota


def validar_cwe(cwe):
    """Aceita a identificação simples de uma categoria de fraqueza."""
    texto = validar_texto(cwe, "CWE").upper()
    partes = texto.split("-")
    if len(partes) != 2 or partes[0] != "CWE" or not partes[1].isdigit():
        raise DadosInvalidosError("CWE inválido. Use o formato CWE-NÚMERO.")
    return texto


def validar_tipo_ativo(tipo):
    """Confirma que o código pertence ao Enum antes de salvar o ativo."""
    try:
        return TipoAtivo(tipo).value
    except (ValueError, TypeError):
        raise DadosInvalidosError("Tipo de ativo inválido.")


def cadastrar_ativo(ativos, identificador, nome, responsavel, localizacao,
                    tipo, criticidade):
    """Cria um ativo completo, sem alterar a base quando os dados forem inválidos."""
    if identificador in ativos:
        raise DadosInvalidosError("Já existe um ativo com esse ID.")
    if not isinstance(identificador, int) or identificador <= 0:
        raise DadosInvalidosError("ID deve ser um número inteiro maior que zero.")
    ativo = Ativo(
        identificador,
        validar_texto(nome, "Nome ou hostname"),
        validar_texto(responsavel, "Responsável"),
        validar_texto(localizacao, "Setor ou localização"),
        validar_tipo_ativo(tipo),
        validar_opcao(criticidade, CRITICIDADES, "Criticidade"),
    )
    ativo.registrar_historico("Ativo cadastrado.")
    ativos[identificador] = ativo
    return ativo


def consultar_por_id(ativos, identificador):
    """Busca direta pela chave do dicionário; retorna None se não existir."""
    return ativos.get(identificador)


def filtrar_ativos(ativos, termo="", tipo=None, criticidade=None):
    """Consulta sem mudar a base. Todos os filtros informados devem coincidir."""
    resultado = []
    for ativo in ativos.values():
        if termo and termo.lower() not in ativo.nome.lower():
            continue
        if tipo is not None and ativo.tipo != tipo:
            continue
        if criticidade is not None and ativo.criticidade != criticidade:
            continue
        resultado.append(ativo)
    return resultado


def atualizar_ativo(ativos, identificador, nome=None, responsavel=None,
                    localizacao=None, tipo=None, criticidade=None):
    """Altera apenas campos permitidos e preserva para sempre o ID do ativo."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")

    alteracoes = []
    if nome is not None and nome != "":
        ativo.nome = validar_texto(nome, "Nome ou hostname")
        alteracoes.append("nome")
    if responsavel is not None and responsavel != "":
        ativo.responsavel = validar_texto(responsavel, "Responsável")
        alteracoes.append("responsável")
    if localizacao is not None and localizacao != "":
        ativo.localizacao = validar_texto(localizacao, "Setor ou localização")
        alteracoes.append("localização")
    if tipo is not None:
        ativo.tipo = validar_tipo_ativo(tipo)
        alteracoes.append("tipo")
    if criticidade is not None:
        ativo.criticidade = validar_opcao(criticidade, CRITICIDADES, "Criticidade")
        alteracoes.append("criticidade")
    if alteracoes:
        ativo.registrar_historico("Campos alterados: " + ", ".join(alteracoes) + ".")
    return ativo


def excluir_ativo(ativos, identificador, confirmou):
    """Remove um ativo somente quando a confirmação explícita for verdadeira."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    if not confirmou:
        return False
    del ativos[identificador]
    return True


def cadastrar_vulnerabilidade(ativos, identificador, cve, cwe, cvss,
                              descricao, fonte, data_fonte, impacto,
                              prioridade, tratamento, status="Aberta",
                              verificacao="Pendente"):
    """Inclui vulnerabilidade apenas em ativo existente e com dados verificáveis."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    cve = validar_cve(cve)
    if buscar_vulnerabilidade(ativo, cve) is not None:
        raise DadosInvalidosError("Esta vulnerabilidade já foi cadastrada para o ativo.")
    vulnerabilidade = Vulnerabilidade(
        cve,
        validar_cwe(cwe),
        validar_cvss(cvss),
        validar_texto(descricao, "Descrição"),
        validar_texto(fonte, "Fonte"),
        validar_texto(data_fonte, "Data da fonte"),
        validar_texto(impacto, "Impacto"),
        validar_opcao(prioridade, SEVERIDADES, "Prioridade"),
        validar_texto(tratamento, "Tratamento"),
        validar_opcao(status, STATUS, "Status"),
        validar_texto(verificacao, "Verificação"),
    )
    ativo.vulnerabilidades.append(vulnerabilidade)
    ativo.registrar_historico(f"Vulnerabilidade {vulnerabilidade.cve} cadastrada.")
    return vulnerabilidade


def buscar_vulnerabilidade(ativo, cve):
    """Procura uma vulnerabilidade pelo CVE dentro de um ativo."""
    for vulnerabilidade in ativo.vulnerabilidades:
        if vulnerabilidade.cve == cve:
            return vulnerabilidade
    return None


def atualizar_vulnerabilidade(ativos, identificador, cve, descricao=None,
                              prioridade=None, tratamento=None, status=None,
                              verificacao=None):
    """Altera os dados de uma vulnerabilidade sem trocar seu CVE."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    cve = validar_cve(cve)
    vulnerabilidade = buscar_vulnerabilidade(ativo, cve)
    if vulnerabilidade is None:
        raise DadosInvalidosError("Vulnerabilidade não encontrada para este ativo.")

    alteracoes = []
    if descricao:
        vulnerabilidade.descricao = validar_texto(descricao, "Descrição")
        alteracoes.append("descrição")
    if prioridade:
        vulnerabilidade.prioridade = validar_opcao(prioridade, SEVERIDADES, "Prioridade")
        alteracoes.append("prioridade")
    if tratamento:
        vulnerabilidade.tratamento = validar_texto(tratamento, "Tratamento")
        alteracoes.append("tratamento")
    if verificacao:
        vulnerabilidade.verificacao = validar_texto(verificacao, "Verificação")
        alteracoes.append("verificação")
    if status:
        novo_status = validar_opcao(status, STATUS, "Status")
        if novo_status == "Corrigida" and vulnerabilidade.verificacao == "Pendente":
            raise DadosInvalidosError("Informe como a correção foi verificada antes de concluir.")
        vulnerabilidade.status = novo_status
        alteracoes.append("status")
    if alteracoes:
        ativo.registrar_historico(
            f"Vulnerabilidade {cve} atualizada: " + ", ".join(alteracoes) + ".")
    return vulnerabilidade


def excluir_vulnerabilidade(ativos, identificador, cve, confirmou):
    """Remove uma vulnerabilidade somente após confirmação explícita."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    cve = validar_cve(cve)
    vulnerabilidade = buscar_vulnerabilidade(ativo, cve)
    if vulnerabilidade is None:
        raise DadosInvalidosError("Vulnerabilidade não encontrada para este ativo.")
    if not confirmou:
        return False
    ativo.vulnerabilidades.remove(vulnerabilidade)
    ativo.registrar_historico(f"Vulnerabilidade {cve} removida.")
    return True


def consultar_vulnerabilidades(ativos, cve="", prioridade=None, status=None):
    """Filtra vulnerabilidades localmente sem modificar nenhum registro."""
    resultado = []
    for ativo in ativos.values():
        for vulnerabilidade in ativo.vulnerabilidades:
            if cve and vulnerabilidade.cve.lower() != cve.lower():
                continue
            if prioridade is not None and vulnerabilidade.prioridade != prioridade:
                continue
            if status is not None and vulnerabilidade.status != status:
                continue
            resultado.append((ativo, vulnerabilidade))
    return resultado
