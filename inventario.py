"""Regras de negócio do CRUD. Este arquivo não usa input nem print."""

from datetime import datetime

from modelos import (Ativo, CRITICIDADES, SEVERIDADES, STATUS, TipoAtivo,
                     Vulnerabilidade, criar_ativo)


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
        # No Brasil, é comum escrever 9,8. O float do Python usa ponto,
        # então aceitamos as duas formas antes de converter para número.
        if isinstance(cvss, str):
            cvss = cvss.strip().replace(",", ".")
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


def validar_data_fonte(data_fonte):
    """Exige a data no formato dd/mm/aaaa informado pela própria tela."""
    texto = validar_texto(data_fonte, "Data da fonte")
    try:
        datetime.strptime(texto, "%d/%m/%Y")
    except ValueError:
        raise DadosInvalidosError("Data inválida. Use o formato dd/mm/aaaa.")
    return texto


def validar_tipo_ativo(tipo):
    """Confirma que o código pertence ao Enum antes de salvar o ativo."""
    if isinstance(tipo, bool):
        raise DadosInvalidosError("Tipo de ativo inválido.")
    try:
        return TipoAtivo(tipo).value
    except (ValueError, TypeError):
        raise DadosInvalidosError("Tipo de ativo inválido.")


def validar_dependencias(ativo):
    """Valida a parte da dependência que pertence a um único equipamento."""
    if not isinstance(ativo.dependencias, list):
        raise DadosInvalidosError("Dependências inválidas no arquivo de dados.")
    ids_encontrados = set()
    soma_pesos = 0.0
    for dependencia in ativo.dependencias:
        if not isinstance(dependencia, dict):
            raise DadosInvalidosError("Dependência inválida no arquivo de dados.")
        identificador = dependencia.get("id")
        peso = dependencia.get("peso")
        if type(identificador) is not int or identificador <= 0:
            raise DadosInvalidosError("ID de dependência inválido.")
        if identificador == ativo.id:
            raise DadosInvalidosError("Um ativo não pode depender de si mesmo.")
        if identificador in ids_encontrados:
            raise DadosInvalidosError("Dependência repetida no arquivo de dados.")
        if isinstance(peso, bool) or not isinstance(peso, (int, float)):
            raise DadosInvalidosError("Peso de dependência inválido.")
        if not 0 < float(peso) < 1:
            raise DadosInvalidosError("Peso de dependência deve estar entre 0 e 1.")
        ids_encontrados.add(identificador)
        soma_pesos += float(peso)
    # Essa regra simples garante que cada linha de A soma menos de 1, um
    # critério suficiente para I-A ser invertível.
    if soma_pesos >= 1:
        raise DadosInvalidosError("A soma dos pesos das dependências deve ser menor que 1.")
def validar_ativo_carregado(ativo):
    """Confere o JSON carregado antes de permitir que ele seja usado no menu."""
    if type(ativo.id) is not int or ativo.id <= 0:
        raise DadosInvalidosError("ID inválido no arquivo de dados.")
    ativo.nome = validar_texto(ativo.nome, "Nome ou hostname")
    ativo.responsavel = validar_texto(ativo.responsavel, "Responsável")
    ativo.localizacao = validar_texto(ativo.localizacao, "Setor ou localização")
    ativo.tipo = validar_tipo_ativo(ativo.tipo)
    ativo.criticidade = validar_opcao(ativo.criticidade, CRITICIDADES, "Criticidade")
    if not isinstance(ativo.historico, list):
        raise DadosInvalidosError("Histórico inválido no arquivo de dados.")

    if not isinstance(ativo.vulnerabilidades, list):
        raise DadosInvalidosError("Vulnerabilidades inválidas no arquivo de dados.")

    validar_dependencias(ativo)

    cves_encontrados = set()
    for vulnerabilidade in ativo.vulnerabilidades:
        vulnerabilidade.cve = validar_cve(vulnerabilidade.cve)
        if vulnerabilidade.cve in cves_encontrados:
            raise DadosInvalidosError("CVE repetido no arquivo de dados.")
        cves_encontrados.add(vulnerabilidade.cve)
        vulnerabilidade.cwe = validar_cwe(vulnerabilidade.cwe)
        vulnerabilidade.cvss = validar_cvss(vulnerabilidade.cvss)
        vulnerabilidade.descricao = validar_texto(vulnerabilidade.descricao, "Descrição")
        vulnerabilidade.fonte = validar_texto(vulnerabilidade.fonte, "Fonte")
        vulnerabilidade.data_fonte = validar_data_fonte(vulnerabilidade.data_fonte)
        vulnerabilidade.impacto = validar_texto(vulnerabilidade.impacto, "Impacto")
        vulnerabilidade.prioridade = validar_opcao(
            vulnerabilidade.prioridade, SEVERIDADES, "Prioridade")
        vulnerabilidade.tratamento = validar_texto(vulnerabilidade.tratamento, "Tratamento")
        vulnerabilidade.status = validar_opcao(vulnerabilidade.status, STATUS, "Status")
        vulnerabilidade.verificacao = validar_texto(
            vulnerabilidade.verificacao, "Verificação")
        if (vulnerabilidade.status == "Corrigida" and
                vulnerabilidade.verificacao.lower() == "pendente"):
            raise DadosInvalidosError("Correção sem verificação no arquivo de dados.")
    return ativo


def cadastrar_ativo(ativos, identificador, nome, responsavel, localizacao,
                    tipo, criticidade):
    """Cria um ativo completo, sem alterar a base quando os dados forem inválidos."""
    if identificador in ativos:
        raise DadosInvalidosError("Já existe um ativo com esse ID.")
    if type(identificador) is not int or identificador <= 0:
        raise DadosInvalidosError("ID deve ser um número inteiro maior que zero.")
    ativo = criar_ativo({
        "id": identificador,
        "nome": validar_texto(nome, "Nome ou hostname"),
        "responsavel": validar_texto(responsavel, "Responsável"),
        "localizacao": validar_texto(localizacao, "Setor ou localização"),
        "tipo": validar_tipo_ativo(tipo),
        "criticidade": validar_opcao(criticidade, CRITICIDADES, "Criticidade"),
    })
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
    """Altera campos permitidos somente depois de validar todos os novos valores."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")

    alteracoes = []
    if nome is not None and nome != "":
        novo_nome = validar_texto(nome, "Nome ou hostname")
        alteracoes.append("nome")
    else:
        novo_nome = ativo.nome
    if responsavel is not None and responsavel != "":
        novo_responsavel = validar_texto(responsavel, "Responsável")
        alteracoes.append("responsável")
    else:
        novo_responsavel = ativo.responsavel
    if localizacao is not None and localizacao != "":
        nova_localizacao = validar_texto(localizacao, "Setor ou localização")
        alteracoes.append("localização")
    else:
        nova_localizacao = ativo.localizacao
    if tipo is not None:
        novo_tipo = validar_tipo_ativo(tipo)
        alteracoes.append("tipo")
    else:
        novo_tipo = ativo.tipo
    if criticidade is not None:
        nova_criticidade = validar_opcao(criticidade, CRITICIDADES, "Criticidade")
        alteracoes.append("criticidade")
    else:
        nova_criticidade = ativo.criticidade
    if alteracoes:
        if novo_tipo != ativo.tipo:
            # Trocar o tipo também troca a subclasse. Assim um Notebook não
            # fica, por engano, com tipo Servidor dentro do mesmo objeto.
            dados = ativo.para_dicionario()
            dados.update({"nome": novo_nome, "responsavel": novo_responsavel,
                          "localizacao": nova_localizacao, "tipo": novo_tipo,
                          "criticidade": nova_criticidade})
            ativo = criar_ativo(dados)
            ativos[identificador] = ativo
        else:
            ativo.nome = novo_nome
            ativo.responsavel = novo_responsavel
            ativo.localizacao = nova_localizacao
            ativo.criticidade = nova_criticidade
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
    # Remover o vínculo evita salvar uma referência para um ativo inexistente.
    for outro_ativo in ativos.values():
        antes = len(outro_ativo.dependencias)
        outro_ativo.dependencias = [
            dependencia for dependencia in outro_ativo.dependencias
            if dependencia["id"] != identificador
        ]
        if len(outro_ativo.dependencias) != antes:
            outro_ativo.registrar_historico(
                f"Dependência do ativo {identificador} removida junto com o ativo.")
    return True


def adicionar_dependencia(ativos, identificador, id_dependencia, peso):
    """Registra uma dependência sem deixar a matriz de risco inválida."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None or consultar_por_id(ativos, id_dependencia) is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    if identificador == id_dependencia:
        raise DadosInvalidosError("Um ativo não pode depender de si mesmo.")
    if isinstance(peso, str):
        peso = peso.strip().replace(",", ".")
    try:
        peso = float(peso)
    except (TypeError, ValueError):
        raise DadosInvalidosError("Peso deve ser um número entre 0 e 1.")
    if not 0 < peso < 1:
        raise DadosInvalidosError("Peso deve estar entre 0 e 1.")
    for dependencia in ativo.dependencias:
        if dependencia["id"] == id_dependencia:
            raise DadosInvalidosError("Esta dependência já está cadastrada.")
    if sum(item["peso"] for item in ativo.dependencias) + peso >= 1:
        raise DadosInvalidosError("A soma dos pesos deve permanecer menor que 1.")
    ativo.dependencias.append({"id": id_dependencia, "peso": peso})
    ativo.registrar_historico(
        f"Dependência do ativo {id_dependencia} adicionada com peso {peso:.2f}.")
    return True


def remover_dependencia(ativos, identificador, id_dependencia):
    """Remove uma dependência existente do equipamento informado."""
    ativo = consultar_por_id(ativos, identificador)
    if ativo is None:
        raise DadosInvalidosError("Ativo não encontrado.")
    for dependencia in ativo.dependencias:
        if dependencia["id"] == id_dependencia:
            ativo.dependencias.remove(dependencia)
            ativo.registrar_historico(f"Dependência do ativo {id_dependencia} removida.")
            return True
    raise DadosInvalidosError("Dependência não encontrada.")


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
    cwe = validar_cwe(cwe)
    cvss = validar_cvss(cvss)
    descricao = validar_texto(descricao, "Descrição")
    fonte = validar_texto(fonte, "Fonte")
    data_fonte = validar_data_fonte(data_fonte)
    impacto = validar_texto(impacto, "Impacto")
    prioridade = validar_opcao(prioridade, SEVERIDADES, "Prioridade")
    tratamento = validar_texto(tratamento, "Tratamento")
    status = validar_opcao(status, STATUS, "Status")
    verificacao = validar_texto(verificacao, "Verificação")
    if status == "Corrigida" and verificacao.lower() == "pendente":
        raise DadosInvalidosError("Informe como a correção foi verificada antes de concluir.")
    vulnerabilidade = Vulnerabilidade(cve, cwe, cvss, descricao, fonte, data_fonte,
                                      impacto, prioridade, tratamento, status, verificacao)
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
    nova_descricao = vulnerabilidade.descricao
    nova_prioridade = vulnerabilidade.prioridade
    novo_tratamento = vulnerabilidade.tratamento
    novo_status = vulnerabilidade.status
    nova_verificacao = vulnerabilidade.verificacao

    if descricao is not None and descricao != "":
        nova_descricao = validar_texto(descricao, "Descrição")
        alteracoes.append("descrição")
    if prioridade is not None and prioridade != "":
        nova_prioridade = validar_opcao(prioridade, SEVERIDADES, "Prioridade")
        alteracoes.append("prioridade")
    if tratamento is not None and tratamento != "":
        novo_tratamento = validar_texto(tratamento, "Tratamento")
        alteracoes.append("tratamento")
    if verificacao is not None and verificacao != "":
        nova_verificacao = validar_texto(verificacao, "Verificação")
        alteracoes.append("verificação")
    if status is not None and status != "":
        novo_status = validar_opcao(status, STATUS, "Status")
        alteracoes.append("status")
    if novo_status == "Corrigida" and nova_verificacao.lower() == "pendente":
        raise DadosInvalidosError("Informe como a correção foi verificada antes de concluir.")
    if alteracoes:
        vulnerabilidade.descricao = nova_descricao
        vulnerabilidade.prioridade = nova_prioridade
        vulnerabilidade.tratamento = novo_tratamento
        vulnerabilidade.status = novo_status
        vulnerabilidade.verificacao = nova_verificacao
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
