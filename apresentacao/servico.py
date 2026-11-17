"""Consulta HTTP somente leitura para manter a aplicação verificável em Docker."""

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dominio.risco import AnalisadorRisco
from infraestrutura.auditoria import AuditoriaHTTP
from infraestrutura.persistencia import RepositorioJSON


class ServicoInventario:
    """Expõe saúde e riscos e audita requisições ao próprio serviço."""

    def __init__(self, ativos, host="0.0.0.0", porta=None, caminho_dados=None,
                 caminho_auditoria=None):
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
        self.auditoria = AuditoriaHTTP(caminho_auditoria) if caminho_auditoria else None

    def resposta(self, caminho):
        if caminho not in {"/saude", "/riscos"}:
            return 404, {"erro": "Rota não encontrada."}
        ativos = self.ativos
        if self.caminho_dados is not None:
            ativos = RepositorioJSON(self.caminho_dados).carregar()
            if ativos is None:
                return 503, {"erro": "Arquivo de dados inválido; corrija a base JSON."}
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

    def executar(self):
        servico = self

        class Requisicao(BaseHTTPRequestHandler):
            def _responder(self, metodo):
                if metodo == "GET":
                    codigo, corpo = servico.resposta(self.path)
                else:
                    codigo, corpo = 405, {"erro": "Método não permitido."}
                if servico.auditoria is not None:
                    servico.auditoria.registrar(
                        self.client_address[0], metodo, self.path, codigo
                    )
                dados = json.dumps(corpo, ensure_ascii=False).encode("utf-8")
                self.send_response(codigo)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(dados)))
                self.send_header("Cache-Control", "no-store")
                if codigo == 405:
                    self.send_header("Allow", "GET")
                self.end_headers()
                if metodo != "HEAD":
                    self.wfile.write(dados)

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
