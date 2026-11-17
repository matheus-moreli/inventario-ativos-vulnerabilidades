"""Auditoria defensiva do próprio serviço HTTP (sem captura de credenciais)."""

import json
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone

# Rotas-isca de baixo impacto: nunca recebem dados ou senhas reais.
ROTAS_ISCA = frozenset({"/admin", "/login", "/wp-admin", "/.env", "/painel"})


class AuditoriaHTTP:
    """Registros JSONL rotativos, limitados em tamanho e sem rota pública."""

    def __init__(self, caminho, limite_falhas=5, janela_segundos=60,
                 tamanho_maximo=524288, backups=3):
        self.caminho = caminho
        self.limite_falhas = limite_falhas
        self.janela_segundos = janela_segundos
        self.tamanho_maximo = tamanho_maximo
        self.backups = backups
        self._lock = threading.Lock()
        self._falhas = {}
        self._ultimo_alerta = {}
        self._aviso_gravacao = False

    def registrar(self, ip, metodo, alvo, codigo):
        """Observa apenas IP de conexão, método, rota e resposta HTTP."""
        ip = str(ip)[:80]
        metodo = str(metodo)[:16]
        # Não registrar queries, fragmentos, cabeçalhos ou corpos.
        rota = str(alvo).split("?", 1)[0].split("#", 1)[0][:160] or "/"
        if (ip in {"127.0.0.1", "::1"} and metodo == "GET"
                and rota == "/saude" and codigo == 200):
            return

        agora = time.monotonic()
        with self._lock:
            classe = "consulta" if codigo < 400 else "requisicao_recusada"
            if codigo >= 400:
                # Evitar crescimento ilimitado com muitas origens diferentes.
                if ip not in self._falhas and len(self._falhas) >= 1024:
                    self._falhas.clear()
                    self._ultimo_alerta.clear()
                tentativas = self._falhas.setdefault(ip, deque())
                while tentativas and agora - tentativas[0] > self.janela_segundos:
                    tentativas.popleft()
                tentativas.append(agora)
                if (len(tentativas) >= self.limite_falhas
                        and agora - self._ultimo_alerta.get(ip, float("-inf"))
                        >= self.janela_segundos):
                    classe = "alerta_falhas_repetidas"
                    self._ultimo_alerta[ip] = agora
            if rota in ROTAS_ISCA:
                classe = "alerta_rota_isca"
            evento = {
                "data_utc": datetime.now(timezone.utc).isoformat(),
                "ip_observado": ip,
                "metodo": metodo,
                "rota": rota,
                "codigo_http": codigo,
                "classificacao": classe,
            }
            try:
                self._gravar(evento)
                self._aviso_gravacao = False
            except OSError:
                # Sem quebrar o inventário se faltar espaço para a auditoria.
                if not self._aviso_gravacao:
                    print("[AUDITORIA] Falha na escrita do log.",
                          file=sys.stderr, flush=True)
                    self._aviso_gravacao = True

    def _gravar(self, evento):
        pasta = os.path.dirname(os.path.abspath(self.caminho))
        os.makedirs(pasta, exist_ok=True)
        linha = (json.dumps(evento, ensure_ascii=False) + "\n").encode("utf-8")
        if (os.path.exists(self.caminho)
                and os.path.getsize(self.caminho) + len(linha) > self.tamanho_maximo):
            if self.backups:
                mais_antigo = f"{self.caminho}.{self.backups}"
                if os.path.exists(mais_antigo):
                    os.remove(mais_antigo)
                for indice in range(self.backups - 1, 0, -1):
                    origem = f"{self.caminho}.{indice}"
                    if os.path.exists(origem):
                        os.replace(origem, f"{self.caminho}.{indice + 1}")
                os.replace(self.caminho, f"{self.caminho}.1")
            else:
                os.remove(self.caminho)
        descritor = os.open(
            self.caminho, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        with os.fdopen(descritor, "ab") as arquivo:
            arquivo.write(linha)
