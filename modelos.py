"""Entidades e listas padronizadas do inventário."""

from datetime import datetime
from enum import IntEnum


class TipoAtivo(IntEnum):
    """Tipos de ativo aceitos pelo sistema."""

    NOTEBOOK = 1
    SERVIDOR = 2
    ROTEADOR = 3
    APLICACAO_WEB = 4
    BANCO_DE_DADOS = 5
    SOFTWARE_LICENCIADO = 6


CRITICIDADES = ["Baixa", "Média", "Alta", "Crítica"]
SEVERIDADES = ["Baixa", "Média", "Alta", "Crítica"]
STATUS = ["Aberta", "Em tratamento", "Corrigida", "Aceita como risco"]


def data_hora_atual():
    """Devolve uma data legível para comprovar uma alteração no histórico."""
    return datetime.now().strftime("%d/%m/%Y %H:%M")


class Vulnerabilidade:
    """Representa uma vulnerabilidade ligada a exatamente um ativo."""

    def __init__(self, cve, cwe, cvss, descricao, fonte, data_fonte,
                 impacto, prioridade, tratamento, status="Aberta",
                 verificacao="Pendente"):
        self.cve = cve
        self.cwe = cwe
        self.cvss = cvss
        self.descricao = descricao
        self.fonte = fonte
        self.data_fonte = data_fonte
        self.impacto = impacto
        self.prioridade = prioridade
        self.tratamento = tratamento
        self.status = status
        self.verificacao = verificacao

    def para_dicionario(self):
        """Converte o objeto em dados simples que o JSON consegue salvar."""
        return {
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "descricao": self.descricao,
            "fonte": self.fonte,
            "data_fonte": self.data_fonte,
            "impacto": self.impacto,
            "prioridade": self.prioridade,
            "tratamento": self.tratamento,
            "status": self.status,
            "verificacao": self.verificacao,
        }

    @classmethod
    def de_dicionario(cls, dados):
        """Reconstrói uma vulnerabilidade a partir dos dados completos do JSON."""
        return cls(
            dados["cve"],
            dados["cwe"],
            dados["cvss"],
            dados["descricao"],
            dados["fonte"],
            dados["data_fonte"],
            dados["impacto"],
            dados["prioridade"],
            dados["tratamento"],
            dados["status"],
            dados["verificacao"],
        )


class Ativo:
    """Classe base com os dados comuns a qualquer equipamento."""

    nome_do_tipo = "Equipamento"

    def __init__(self, identificador, nome, responsavel, localizacao, tipo,
                 criticidade, vulnerabilidades=None, historico=None,
                 dependencias=None):
        self.id = identificador
        self.nome = nome
        self.responsavel = responsavel
        self.localizacao = localizacao
        self.tipo = tipo
        self.criticidade = criticidade
        self.vulnerabilidades = vulnerabilidades if vulnerabilidades is not None else []
        self.historico = historico if historico is not None else []
        # Um item informa de qual ativo este equipamento depende e qual fração
        # do risco é recebida: {"id": 2, "peso": 0.30}.
        self.dependencias = dependencias if dependencias is not None else []

    def descricao_tipo(self):
        """Método polimórfico usado pela interface para identificar o equipamento."""
        return self.nome_do_tipo

    def registrar_historico(self, mensagem):
        """Guarda uma evidência simples de criação, alteração ou cadastro."""
        self.historico.append(f"{data_hora_atual()} - {mensagem}")

    def para_dicionario(self):
        """Transforma o ativo em dicionário para persistência no arquivo JSON."""
        vulnerabilidades = []
        for vulnerabilidade in self.vulnerabilidades:
            vulnerabilidades.append(vulnerabilidade.para_dicionario())
        return {
            "id": self.id,
            "nome": self.nome,
            "responsavel": self.responsavel,
            "localizacao": self.localizacao,
            "tipo": self.tipo,
            "criticidade": self.criticidade,
            "vulnerabilidades": vulnerabilidades,
            "historico": self.historico,
            "dependencias": self.dependencias,
        }

    @classmethod
    def de_dicionario(cls, dados):
        """Reconstrói um ativo salvo a partir dos dados completos do JSON."""
        return criar_ativo(dados)


# As subclasses não criam campos artificiais. Elas existem para que o tipo de
# equipamento seja um objeto de verdade, permitindo herança e polimorfismo.
class Notebook(Ativo):
    nome_do_tipo = "Notebook"

    def descricao_tipo(self):
        return "Notebook"


class Servidor(Ativo):
    nome_do_tipo = "Servidor"

    def descricao_tipo(self):
        return "Servidor"


class Roteador(Ativo):
    nome_do_tipo = "Roteador"

    def descricao_tipo(self):
        return "Roteador"


class AplicacaoWeb(Ativo):
    nome_do_tipo = "Aplicação Web"

    def descricao_tipo(self):
        return "Aplicação Web"


class BancoDeDados(Ativo):
    nome_do_tipo = "Banco de Dados"

    def descricao_tipo(self):
        return "Banco de Dados"


class SoftwareLicenciado(Ativo):
    nome_do_tipo = "Software Licenciado"

    def descricao_tipo(self):
        return "Software Licenciado"


CLASSES_DE_ATIVO = {
    TipoAtivo.NOTEBOOK.value: Notebook,
    TipoAtivo.SERVIDOR.value: Servidor,
    TipoAtivo.ROTEADOR.value: Roteador,
    TipoAtivo.APLICACAO_WEB.value: AplicacaoWeb,
    TipoAtivo.BANCO_DE_DADOS.value: BancoDeDados,
    TipoAtivo.SOFTWARE_LICENCIADO.value: SoftwareLicenciado,
}


def criar_ativo(dados):
    """Reconstrói a subclasse correta a partir do campo ``tipo`` do JSON."""
    tipo = int(dados["tipo"])
    classe = CLASSES_DE_ATIVO.get(tipo)
    if classe is None:
        raise ValueError("Tipo de ativo inválido.")
    vulnerabilidades = [
        Vulnerabilidade.de_dicionario(vulnerabilidade)
        for vulnerabilidade in dados.get("vulnerabilidades", [])
    ]
    return classe(
        dados["id"], dados["nome"], dados["responsavel"],
        dados["localizacao"], tipo, dados["criticidade"], vulnerabilidades,
        dados.get("historico", []), dados.get("dependencias", [])
    )
