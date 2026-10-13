"""Consulta HTTP somente leitura para manter a aplicação verificável em Docker."""

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from risco import calcular_riscos


class ServicoInventario:
    """Expõe saúde e riscos sem depender da entrada do terminal."""

    def __init__(self, ativos, host="0.0.0.0", porta=None):
        self.ativos = ativos
        self.host = host
        self.porta = int(porta or os.environ.get("INVENTARIO_PORTA", "8080"))
        self.inicio = datetime.now(timezone.utc)

    def resposta(self, caminho):
        if caminho == "/saude":
            agora = datetime.now(timezone.utc)
            return 200, {
                "estado": "ativo",
                "inicio_utc": self.inicio.isoformat(),
                "tempo_ativo_segundos": int((agora - self.inicio).total_seconds()),
                "ativos": len(self.ativos),
            }
        if caminho == "/riscos":
            try:
                lista, m, v, proprio, a, efetivo = calcular_riscos(self.ativos)
            except (ValueError, KeyError) as erro:
                return 422, {"erro": str(erro)}
            return 200, {
                "ids": [ativo.id for ativo in lista],
                "matriz_incidencia": m,
                "severidades": v,
                "risco_proprio": proprio,
                "matriz_dependencias": a,
                "risco_efetivo": efetivo,
            }
        return 404, {"erro": "Rota não encontrada."}

    def executar(self):
        servico = self

        class Requisicao(BaseHTTPRequestHandler):
            def do_GET(self):
                codigo, corpo = servico.resposta(self.path)
                dados = json.dumps(corpo, ensure_ascii=False).encode("utf-8")
                self.send_response(codigo)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(dados)))
                self.end_headers()
                self.wfile.write(dados)

        with ThreadingHTTPServer((self.host, self.porta), Requisicao) as servidor:
            print(f"Inventário disponível na porta {self.porta}.", flush=True)
            servidor.serve_forever()
