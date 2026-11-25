"""Regras de validação de campos e do arquivo de dados do inventário."""

import math
from datetime import datetime

from dominio.modelos import CRITICIDADES, SEVERIDADES, STATUS, TipoAtivo


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


def validar_campos_extras(campos):
    """Aceita apenas pares descritivos simples; não altera o cálculo de risco."""
    if not isinstance(campos, dict) or len(campos) > 30:
        raise DadosInvalidosError("Campos adicionais devem ser um objeto com até 30 itens.")
    normalizados = {}
    for chave, valor in campos.items():
        if not isinstance(chave, str) or not 1 <= len(chave.strip()) <= 60:
            raise DadosInvalidosError("Nome do campo adicional deve ter 1 a 60 caracteres.")
        if not isinstance(valor, str) or len(valor) > 500:
            raise DadosInvalidosError("Valor adicional deve ser texto com até 500 caracteres.")
        chave = chave.strip()
        if chave.lower() in (c.lower() for c in normalizados):
            raise DadosInvalidosError("Campo adicional duplicado.")
        normalizados[chave] = valor
    return normalizados


def validar_nome_tipo_personalizado(tipo, nome):
    if tipo >= 100:
        nome = validar_texto(nome, "Nome do tipo personalizado")
        if len(nome) > 60:
            raise DadosInvalidosError("Tipo personalizado deve ter até 60 caracteres.")
        return nome
    if nome is not None:
        raise DadosInvalidosError("Tipos nativos não aceitam outro nome de categoria.")
    return None


def validar_tipo_ativo(tipo):
    """Confirma que o código pertence ao Enum antes de salvar o ativo."""
    if isinstance(tipo, bool):
        raise DadosInvalidosError("Tipo de ativo inválido.")
    try:
        return TipoAtivo(tipo).value
    except (ValueError, TypeError):
        if type(tipo) is int and tipo >= 100:
            return tipo
        raise DadosInvalidosError("Tipo de ativo inválido.")


def validar_dependencias(dependencias):
    """Confere a estrutura simples usada para guardar risco herdado."""
    if not isinstance(dependencias, list):
        raise DadosInvalidosError("Dependências inválidas no arquivo de dados.")
    ids_encontrados = set()
    soma_pesos = 0
    for dependencia in dependencias:
        if not isinstance(dependencia, dict):
            raise DadosInvalidosError("Dependência inválida no arquivo de dados.")
        ativo_id = dependencia.get("ativo_id")
        peso = dependencia.get("peso")
        if type(ativo_id) is not int or ativo_id <= 0 or ativo_id in ids_encontrados:
            raise DadosInvalidosError("Dependência inválida no arquivo de dados.")
        if type(peso) not in (int, float) or not 0 <= peso < 1:
            raise DadosInvalidosError("Peso de dependência deve estar entre 0 e 1.")
        ids_encontrados.add(ativo_id)
        soma_pesos += peso
    if soma_pesos >= 1:
        raise DadosInvalidosError("A soma dos pesos de dependência deve ser menor que 1.")


def validar_ativo_carregado(ativo):
    """Confere o JSON carregado antes de permitir que ele seja usado no menu."""
    if type(ativo.id) is not int or ativo.id <= 0:
        raise DadosInvalidosError("ID inválido no arquivo de dados.")
    ativo.nome = validar_texto(ativo.nome, "Nome ou hostname")
    ativo.responsavel = validar_texto(ativo.responsavel, "Responsável")
    ativo.localizacao = validar_texto(ativo.localizacao, "Setor ou localização")
    ativo.tipo = validar_tipo_ativo(ativo.tipo)
    ativo.nome_tipo_personalizado = validar_nome_tipo_personalizado(
        ativo.tipo, ativo.nome_tipo_personalizado
    )
    ativo.campos_extras = validar_campos_extras(ativo.campos_extras)
    ativo.criticidade = validar_opcao(ativo.criticidade, CRITICIDADES, "Criticidade")
    validar_dependencias(ativo.dependencias)
    if ativo.id in [dependencia["ativo_id"] for dependencia in ativo.dependencias]:
        raise DadosInvalidosError("Um ativo não pode depender de si mesmo.")
    if not isinstance(ativo.historico, list):
        raise DadosInvalidosError("Histórico inválido no arquivo de dados.")

    if not isinstance(ativo.vulnerabilidades, list):
        raise DadosInvalidosError("Vulnerabilidades inválidas no arquivo de dados.")

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
            vulnerabilidade.prioridade, SEVERIDADES, "Prioridade"
        )
        vulnerabilidade.tratamento = validar_texto(vulnerabilidade.tratamento, "Tratamento")
        vulnerabilidade.status = validar_opcao(vulnerabilidade.status, STATUS, "Status")
        vulnerabilidade.verificacao = validar_texto(vulnerabilidade.verificacao, "Verificação")
        if (
            vulnerabilidade.status == "Corrigida"
            and vulnerabilidade.verificacao.lower() == "pendente"
        ):
            raise DadosInvalidosError("Correção sem verificação no arquivo de dados.")
    return ativo


def validar_cvss_compartilhado(ativos):
    """Garante um único valor de severidade para cada coluna CVE de M."""
    notas = {}
    for ativo in ativos.values():
        for vulnerabilidade in ativo.vulnerabilidades:
            anterior = notas.get(vulnerabilidade.cve)
            if anterior is not None and not math.isclose(
                anterior, vulnerabilidade.cvss, rel_tol=0, abs_tol=1e-9
            ):
                raise DadosInvalidosError(
                    f"CVE {vulnerabilidade.cve} tem notas CVSS diferentes no JSON."
                )
            notas[vulnerabilidade.cve] = vulnerabilidade.cvss
