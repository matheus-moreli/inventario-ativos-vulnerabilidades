"""Repositório JSON do inventário, com gravação atômica."""

import json
import os
import tempfile

from dominio.inventario import (
    DadosInvalidosError,
    validar_ativo_carregado,
    validar_cvss_compartilhado,
)
from dominio.modelos import Ativo


class RepositorioJSON:
    """Traduz objetos de domínio para a lista JSON e de volta para objetos."""

    def __init__(self, caminho):
        self.caminho = caminho

    def carregar(self):
        """Devolve objetos indexados por ID; None representa arquivo inválido."""
        try:
            with open(self.caminho, "r", encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
            if isinstance(dados, list):
                registros = ((None, item) for item in dados)
            elif isinstance(dados, dict):
                # A primeira entrega gravava os ativos em um objeto indexado por ID.
                registros = dados.items()
            else:
                raise DadosInvalidosError("Formato inválido para a base de ativos.")
            ativos = {}
            for chave, dados_ativo in registros:
                if not isinstance(dados_ativo, dict):
                    raise ValueError("Ativo inválido no arquivo de dados.")
                ativo = Ativo.de_dicionario(dados_ativo)
                if chave is not None and ativo.id != int(chave):
                    raise ValueError("ID do ativo não corresponde à chave do arquivo.")
                if ativo.id in ativos:
                    raise ValueError("ID repetido no arquivo de dados.")
                ativos[ativo.id] = validar_ativo_carregado(ativo)
            nomes = set()
            categorias = {}
            for ativo in ativos.values():
                nome = ativo.nome.lower()
                if nome in nomes:
                    raise DadosInvalidosError(
                        "Nome ou hostname repetido no arquivo de dados."
                    )
                nomes.add(nome)
                if ativo.tipo >= 100:
                    anterior = categorias.get(ativo.tipo)
                    if anterior is not None and anterior != ativo.nome_tipo_personalizado:
                        raise DadosInvalidosError("Categoria personalizada inconsistente.")
                    categorias[ativo.tipo] = ativo.nome_tipo_personalizado
                for dependencia in ativo.dependencias:
                    if dependencia["ativo_id"] not in ativos:
                        raise DadosInvalidosError(
                            "Dependência aponta para ativo inexistente."
                        )
            validar_cvss_compartilhado(ativos)
            return ativos
        except FileNotFoundError:
            return {}
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            DadosInvalidosError,
        ):
            print("Não foi possível ler o arquivo de dados. Ele não será sobrescrito.")
            return None

    def salvar(self, ativos):
        """Grava em arquivo temporário antes de substituir a versão anterior."""
        dados = [
            ativos[identificador].para_dicionario() for identificador in sorted(ativos)
        ]
        temporario = None
        try:
            pasta = os.path.dirname(os.path.abspath(self.caminho))
            os.makedirs(pasta, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=pasta,
                prefix=".inventario-",
                suffix=".tmp",
                delete=False,
            ) as arquivo:
                temporario = arquivo.name
                json.dump(dados, arquivo, ensure_ascii=False, indent=2, allow_nan=False)
                arquivo.flush()
                os.fsync(arquivo.fileno())
            os.replace(temporario, self.caminho)
            return True
        except (OSError, ValueError, TypeError):
            print("Erro ao salvar os dados no arquivo.")
            return False
        finally:
            if temporario and os.path.exists(temporario):
                try:
                    os.unlink(temporario)
                except OSError:
                    pass


def carregar_ativos(caminho):
    """Compatibilidade com chamadas das Sprints 1 e 2."""
    return RepositorioJSON(caminho).carregar()


def salvar_ativos(ativos, caminho):
    """Compatibilidade com chamadas das Sprints 1 e 2."""
    return RepositorioJSON(caminho).salvar(ativos)
