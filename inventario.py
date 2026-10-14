"""Regras de negócio do CRUD. Este arquivo não usa input nem print."""

import math
from datetime import datetime

from modelos import (
    CRITICIDADES,
    SEVERIDADES,
    STATUS,
    TipoAtivo,
    Vulnerabilidade,
    criar_ativo,
)


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


class Inventario:
    """Regras e consultas de uma coleção de ativos em memória."""

    def __init__(self, ativos=None):
        self._ativos = {} if ativos is None else ativos

    @property
    def ativos(self):
        return self._ativos

    def __len__(self):
        return len(self._ativos)

    def __iter__(self):
        return iter(self._ativos)

    def __getitem__(self, identificador):
        return self._ativos[identificador]

    def __contains__(self, identificador):
        return identificador in self._ativos

    def values(self):
        return self._ativos.values()

    def items(self):
        return self._ativos.items()

    def get(self, identificador, padrao=None):
        return self._ativos.get(identificador, padrao)

    def calcular_riscos(self):
        """Consulta o risco da coleção mantida por este objeto."""
        from risco import AnalisadorRisco

        analisador = AnalisadorRisco(self._ativos)
        resultado = analisador.calcular()
        self.numero_condicao_risco = analisador.numero_condicao
        return resultado

    def validar_nome_unico(self, nome, identificador_ignorado=None):
        """Impede que dois ativos usem o mesmo nome ou hostname.

        Espaços nas pontas e letras maiúsculas/minúsculas não diferenciam nomes:
        "SRV-WEB-01", "srv-web-01" e " SRV-WEB-01 " representam o mesmo ativo.
        """
        ativos = self._ativos
        nome_normalizado = nome.strip().lower()
        for ativo in ativos.values():
            if (
                ativo.id != identificador_ignorado
                and ativo.nome.strip().lower() == nome_normalizado
            ):
                raise DadosInvalidosError(
                    "Já existe um ativo com esse nome ou hostname."
                )

    def cadastrar_ativo(
        self, identificador, nome, responsavel, localizacao, tipo, criticidade
    ):
        """Cria um ativo completo, sem alterar a base quando os dados forem inválidos."""
        ativos = self._ativos
        if identificador in ativos:
            raise DadosInvalidosError("Já existe um ativo com esse ID.")
        if type(identificador) is not int or identificador <= 0:
            raise DadosInvalidosError("ID deve ser um número inteiro maior que zero.")
        nome = validar_texto(nome, "Nome ou hostname")
        self.validar_nome_unico(nome)
        ativo = criar_ativo(
            identificador,
            nome,
            validar_texto(responsavel, "Responsável"),
            validar_texto(localizacao, "Setor ou localização"),
            validar_tipo_ativo(tipo),
            validar_opcao(criticidade, CRITICIDADES, "Criticidade"),
        )
        ativo.registrar_historico("Ativo cadastrado.")
        ativos[identificador] = ativo
        return ativo

    def consultar_por_id(self, identificador):
        """Busca direta pela chave do dicionário; retorna None se não existir."""
        ativos = self._ativos
        return ativos.get(identificador)

    def filtrar_ativos(self, termo="", tipo=None, criticidade=None):
        """Consulta sem mudar a base. Todos os filtros informados devem coincidir."""
        ativos = self._ativos
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

    def atualizar_ativo(
        self,
        identificador,
        nome=None,
        responsavel=None,
        localizacao=None,
        tipo=None,
        criticidade=None,
    ):
        """Altera campos permitidos somente depois de validar todos os novos valores."""
        ativos = self._ativos
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")

        alteracoes = []
        if nome is not None and nome != "":
            novo_nome = validar_texto(nome, "Nome ou hostname")
            self.validar_nome_unico(novo_nome, identificador)
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
            if novo_tipo != ativo.tipo:
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
                ativo_atualizado = criar_ativo(
                    ativo.id,
                    novo_nome,
                    novo_responsavel,
                    nova_localizacao,
                    novo_tipo,
                    nova_criticidade,
                    ativo.vulnerabilidades,
                    ativo.historico,
                    ativo.dependencias,
                )
                ativos[identificador] = ativo_atualizado
            else:
                ativo_atualizado = ativo
                ativo.nome = novo_nome
                ativo.responsavel = novo_responsavel
                ativo.localizacao = nova_localizacao
                ativo.criticidade = nova_criticidade
            ativo_atualizado.registrar_historico(
                "Campos alterados: " + ", ".join(alteracoes) + "."
            )
            return ativo_atualizado
        return ativo

    def excluir_ativo(self, identificador, confirmou):
        """Remove um ativo somente quando a confirmação explícita for verdadeira."""
        ativos = self._ativos
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        if not confirmou:
            return False
        del ativos[identificador]
        for outro_ativo in ativos.values():
            quantidade_anterior = len(outro_ativo.dependencias)
            outro_ativo.dependencias = [
                dependencia
                for dependencia in outro_ativo.dependencias
                if dependencia["ativo_id"] != identificador
            ]
            if len(outro_ativo.dependencias) != quantidade_anterior:
                outro_ativo.registrar_historico(
                    f"Dependência do ativo {identificador} removida com a exclusão do ativo."
                )
        return True

    def adicionar_dependencia(self, identificador, ativo_dependente, peso):
        """Registra a fração do risco de outro ativo herdada pelo ativo informado."""
        ativo = self.consultar_por_id(identificador)
        if ativo is None or self.consultar_por_id(ativo_dependente) is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        if identificador == ativo_dependente:
            raise DadosInvalidosError("Um ativo não pode depender de si mesmo.")
        if any(item["ativo_id"] == ativo_dependente for item in ativo.dependencias):
            raise DadosInvalidosError("Esta dependência já foi cadastrada.")
        try:
            peso = float(str(peso).replace(",", "."))
        except ValueError:
            raise DadosInvalidosError("Peso deve ser um número entre 0 e 1.")
        novas_dependencias = ativo.dependencias + [
            {"ativo_id": ativo_dependente, "peso": peso}
        ]
        validar_dependencias(novas_dependencias)
        ativo.dependencias = novas_dependencias
        ativo.registrar_historico(
            f"Dependência do ativo {ativo_dependente} cadastrada."
        )

    def remover_dependencia(self, identificador, ativo_dependente):
        """Remove uma dependência existente sem alterar os demais dados do ativo."""
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        novas_dependencias = [
            item for item in ativo.dependencias if item["ativo_id"] != ativo_dependente
        ]
        if len(novas_dependencias) == len(ativo.dependencias):
            raise DadosInvalidosError("Dependência não encontrada.")
        ativo.dependencias = novas_dependencias
        ativo.registrar_historico(f"Dependência do ativo {ativo_dependente} removida.")

    def cadastrar_vulnerabilidade(
        self,
        identificador,
        cve,
        cwe,
        cvss,
        descricao,
        fonte,
        data_fonte,
        impacto,
        prioridade,
        tratamento,
        status="Aberta",
        verificacao="Pendente",
    ):
        """Inclui vulnerabilidade apenas em ativo existente e com dados verificáveis."""
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        cve = validar_cve(cve)
        if ativo.buscar_vulnerabilidade(cve) is not None:
            raise DadosInvalidosError(
                "Esta vulnerabilidade já foi cadastrada para o ativo."
            )
        cwe = validar_cwe(cwe)
        cvss = validar_cvss(cvss)
        for outro_ativo in self._ativos.values():
            anterior = outro_ativo.buscar_vulnerabilidade(cve)
            if anterior is not None and not math.isclose(
                anterior.cvss, cvss, rel_tol=0, abs_tol=1e-9
            ):
                raise DadosInvalidosError(
                    f"CVE {cve} já existe com outra nota CVSS. Use a mesma severidade."
                )
        descricao = validar_texto(descricao, "Descrição")
        fonte = validar_texto(fonte, "Fonte")
        data_fonte = validar_data_fonte(data_fonte)
        impacto = validar_texto(impacto, "Impacto")
        prioridade = validar_opcao(prioridade, SEVERIDADES, "Prioridade")
        tratamento = validar_texto(tratamento, "Tratamento")
        status = validar_opcao(status, STATUS, "Status")
        verificacao = validar_texto(verificacao, "Verificação")
        if status == "Corrigida" and verificacao.lower() == "pendente":
            raise DadosInvalidosError(
                "Informe como a correção foi verificada antes de concluir."
            )
        vulnerabilidade = Vulnerabilidade(
            cve,
            cwe,
            cvss,
            descricao,
            fonte,
            data_fonte,
            impacto,
            prioridade,
            tratamento,
            status,
            verificacao,
        )
        ativo.vulnerabilidades.append(vulnerabilidade)
        ativo.registrar_historico(f"Vulnerabilidade {vulnerabilidade.cve} cadastrada.")
        return vulnerabilidade

    def atualizar_vulnerabilidade(
        self,
        identificador,
        cve,
        descricao=None,
        prioridade=None,
        tratamento=None,
        status=None,
        verificacao=None,
    ):
        """Altera os dados de uma vulnerabilidade sem trocar seu CVE."""
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        cve = validar_cve(cve)
        vulnerabilidade = ativo.buscar_vulnerabilidade(cve)
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
            raise DadosInvalidosError(
                "Informe como a correção foi verificada antes de concluir."
            )
        if alteracoes:
            vulnerabilidade.descricao = nova_descricao
            vulnerabilidade.prioridade = nova_prioridade
            vulnerabilidade.tratamento = novo_tratamento
            vulnerabilidade.status = novo_status
            vulnerabilidade.verificacao = nova_verificacao
            ativo.registrar_historico(
                f"Vulnerabilidade {cve} atualizada: " + ", ".join(alteracoes) + "."
            )
        return vulnerabilidade

    def excluir_vulnerabilidade(self, identificador, cve, confirmou):
        """Remove uma vulnerabilidade somente após confirmação explícita."""
        ativo = self.consultar_por_id(identificador)
        if ativo is None:
            raise DadosInvalidosError("Ativo não encontrado.")
        cve = validar_cve(cve)
        vulnerabilidade = ativo.buscar_vulnerabilidade(cve)
        if vulnerabilidade is None:
            raise DadosInvalidosError("Vulnerabilidade não encontrada para este ativo.")
        if not confirmou:
            return False
        ativo.vulnerabilidades.remove(vulnerabilidade)
        ativo.registrar_historico(f"Vulnerabilidade {cve} removida.")
        return True

    def consultar_vulnerabilidades(self, cve="", prioridade=None, status=None):
        """Filtra vulnerabilidades localmente sem modificar nenhum registro."""
        ativos = self._ativos
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
        raise DadosInvalidosError(
            "A soma dos pesos de dependência deve ser menor que 1."
        )


def validar_ativo_carregado(ativo):
    """Confere o JSON carregado antes de permitir que ele seja usado no menu."""
    if type(ativo.id) is not int or ativo.id <= 0:
        raise DadosInvalidosError("ID inválido no arquivo de dados.")
    ativo.nome = validar_texto(ativo.nome, "Nome ou hostname")
    ativo.responsavel = validar_texto(ativo.responsavel, "Responsável")
    ativo.localizacao = validar_texto(ativo.localizacao, "Setor ou localização")
    ativo.tipo = validar_tipo_ativo(ativo.tipo)
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
        vulnerabilidade.descricao = validar_texto(
            vulnerabilidade.descricao, "Descrição"
        )
        vulnerabilidade.fonte = validar_texto(vulnerabilidade.fonte, "Fonte")
        vulnerabilidade.data_fonte = validar_data_fonte(vulnerabilidade.data_fonte)
        vulnerabilidade.impacto = validar_texto(vulnerabilidade.impacto, "Impacto")
        vulnerabilidade.prioridade = validar_opcao(
            vulnerabilidade.prioridade, SEVERIDADES, "Prioridade"
        )
        vulnerabilidade.tratamento = validar_texto(
            vulnerabilidade.tratamento, "Tratamento"
        )
        vulnerabilidade.status = validar_opcao(vulnerabilidade.status, STATUS, "Status")
        vulnerabilidade.verificacao = validar_texto(
            vulnerabilidade.verificacao, "Verificação"
        )
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


def buscar_vulnerabilidade(ativo, cve):
    """Procura uma vulnerabilidade pelo CVE dentro de um ativo."""
    return ativo.buscar_vulnerabilidade(cve)


def _como_inventario(ativos):
    return ativos if isinstance(ativos, Inventario) else Inventario(ativos)


def validar_nome_unico(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).validar_nome_unico(*args, **kwargs)


def cadastrar_ativo(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).cadastrar_ativo(*args, **kwargs)


def consultar_por_id(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).consultar_por_id(*args, **kwargs)


def filtrar_ativos(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).filtrar_ativos(*args, **kwargs)


def atualizar_ativo(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).atualizar_ativo(*args, **kwargs)


def excluir_ativo(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).excluir_ativo(*args, **kwargs)


def adicionar_dependencia(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).adicionar_dependencia(*args, **kwargs)


def remover_dependencia(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).remover_dependencia(*args, **kwargs)


def cadastrar_vulnerabilidade(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).cadastrar_vulnerabilidade(*args, **kwargs)


def atualizar_vulnerabilidade(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).atualizar_vulnerabilidade(*args, **kwargs)


def excluir_vulnerabilidade(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).excluir_vulnerabilidade(*args, **kwargs)


def consultar_vulnerabilidades(ativos, *args, **kwargs):
    """Compatibilidade com as chamadas das Sprints 1 e 2."""
    return _como_inventario(ativos).consultar_vulnerabilidades(*args, **kwargs)
