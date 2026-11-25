"""Consulta HTTP somente leitura com auditoria e senha de acesso."""

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from apresentacao.api_v1 import ROTA_ATIVOS, ROTA_RISCOS, especificacao, listar_ativos, problema
from dominio.risco import AnalisadorRisco
from infraestrutura.auditoria import AuditoriaHTTP, ROTAS_ISCA
from infraestrutura.autenticacao import AutenticacaoHTTP
from infraestrutura.persistencia import RepositorioJSON


class ServicoInventario:
    """Expõe saúde, protege riscos por senha e audita requisições."""

    def __init__(self, ativos, host="0.0.0.0", porta=None, caminho_dados=None,
                 caminho_auditoria=None, caminho_senha=None):
        self.ativos = ativos
        self.caminho_dados = caminho_dados
        self.host = host
        self.porta = int(porta or os.environ.get("INVENTARIO_PORTA", "2217"))
        self.inicio = datetime.now(timezone.utc)
        if caminho_auditoria is None and caminho_dados is not None:
            caminho_auditoria = os.environ.get("INVENTARIO_AUDITORIA_ARQUIVO")
            if not caminho_auditoria:
                caminho_auditoria = os.path.join(
                    os.path.dirname(os.path.abspath(caminho_dados)),
                    "auditoria-acessos.jsonl",
                )
        if caminho_senha is None and caminho_dados is not None:
            caminho_senha = os.environ.get("INVENTARIO_SENHA_ARQUIVO")
            if not caminho_senha:
                caminho_senha = os.path.join(
                    os.path.dirname(os.path.abspath(caminho_dados)), "senha-acesso"
                )
        self.auditoria = AuditoriaHTTP(caminho_auditoria) if caminho_auditoria else None
        self.autenticacao = AutenticacaoHTTP(caminho_senha) if caminho_senha else None

    def resposta(self, caminho, consulta=""):
        if caminho not in {"/saude", "/riscos", ROTA_ATIVOS}:
            return 404, {"erro": "Rota não encontrada."}
        ativos = self.ativos
        if self.caminho_dados is not None:
            ativos = RepositorioJSON(self.caminho_dados).carregar()
            if ativos is None:
                if caminho == ROTA_ATIVOS:
                    return problema(503, "Inventário indisponível", "O arquivo de dados está inválido.")
                return 503, {"erro": "Arquivo de dados inválido; corrija a base JSON."}
        if caminho == ROTA_ATIVOS:
            return listar_ativos(ativos, consulta)
        if caminho == "/saude":
            agora = datetime.now(timezone.utc)
            return 200, {
                "estado": "ativo",
                "inicio_utc": self.inicio.isoformat(),
                "tempo_ativo_segundos": int((agora - self.inicio).total_seconds()),
                "ativos": len(ativos),
            }
        if caminho == "/riscos":
            try:
                analisador = AnalisadorRisco(ativos)
                lista, m, v, proprio, a, efetivo = analisador.calcular()
            except (ValueError, KeyError) as erro:
                return 422, {"erro": str(erro)}
            return 200, {
                "ids": [ativo.id for ativo in lista],
                "matriz_incidencia": m,
                "severidades": v,
                "risco_proprio": proprio,
                "matriz_dependencias": a,
                "risco_efetivo": efetivo,
                "numero_condicao_infinito": analisador.numero_condicao,
                "aviso_condicionamento": analisador.numero_condicao > 1e8,
            }

    def atender(self, metodo, caminho, autorizacao=""):
        """Decide status sem incluir ou registrar a credencial."""
        rota, _, consulta = caminho.partition("?")
        versao_um = rota == "/v1" or rota.startswith("/v1/")
        if metodo != "GET":
            if versao_um:
                return problema(405, "Método não permitido", "O método disponível é GET.")
            return 405, {"erro": "Método não permitido."}
        if rota == "/saude":
            return self.resposta(rota)
        if rota == "/openapi.json":
            return 200, especificacao()
        if rota in ROTAS_ISCA:
            return 404, {"erro": "Rota não encontrada."}
        if rota not in {"/riscos", ROTA_ATIVOS, ROTA_RISCOS}:
            if versao_um:
                return problema(404, "Rota não encontrada", "Consulte /openapi.json.")
            return 404, {"erro": "Rota não encontrada."}
        if self.autenticacao is None or not self.autenticacao.autorizada(autorizacao):
            if versao_um:
                return problema(401, "Autorização necessária", "Informe uma credencial Bearer válida.")
            return 401, {"erro": "Autorização necessária."}
        if rota == ROTA_RISCOS:
            codigo, corpo = self.resposta("/riscos")
            if codigo != 200:
                return problema(codigo, "Risco indisponível", corpo["erro"])
            return codigo, corpo
        return self.resposta(rota, consulta)

    def executar(self):
        if self.autenticacao is None or not self.autenticacao.configurada():
            raise RuntimeError(
                "A API requer um arquivo de senha não vazio. "
                "Configure INVENTARIO_SENHA_ARQUIVO antes de iniciar."
            )
        servico = self

        class Requisicao(BaseHTTPRequestHandler):
            def _responder(self, metodo):
                codigo, corpo = servico.atender(
                    metodo, self.path, self.headers.get("Authorization", "")
                )
                if servico.auditoria is not None:
                    servico.auditoria.registrar(
                        self.client_address[0], metodo, self.path, codigo
                    )
                dados = json.dumps(corpo, ensure_ascii=False).encode("utf-8")
                self.send_response(codigo)
                tipo = "application/problem+json" if "status" in corpo and "type" in corpo else "application/json"
                self.send_header("Content-Type", f"{tipo}; charset=utf-8")
                self.send_header("Content-Length", str(len(dados)))
                self.send_header("Cache-Control", "no-store")
                if codigo == 401:
                    self.send_header("WWW-Authenticate", 'Bearer realm="Inventario"')
                if codigo == 405:
                    self.send_header("Allow", "GET")
                self.end_headers()
                if metodo != "HEAD":
                    self.wfile.write(dados)

            def log_message(self, formatacao, *args):
                # Os eventos sanitizados ficam apenas no JSONL, sem query nos logs.
                pass

            def do_GET(self):
                self._responder("GET")

            def do_HEAD(self):
                self._responder("HEAD")

            def do_POST(self):
                self._responder("POST")

            def do_PUT(self):
                self._responder("PUT")

            def do_PATCH(self):
                self._responder("PATCH")

            def do_DELETE(self):
                self._responder("DELETE")

            def do_OPTIONS(self):
                self._responder("OPTIONS")

        with ThreadingHTTPServer((self.host, self.porta), Requisicao) as servidor:
            print(f"Inventário disponível na porta {self.porta}.", flush=True)
            servidor.serve_forever()
