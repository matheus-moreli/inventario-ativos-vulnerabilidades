"""Autorização para API HTTP com senha lida de arquivo protegido."""

import hmac


class AutenticacaoHTTP:
    """Usa uma senha local, nunca a inclui no código-fonte ou nos logs."""

    def __init__(self, caminho):
        self.caminho = caminho

    def _senha(self):
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                senha = arquivo.read().rstrip("\r\n")
        except OSError:
            return None
        return senha if senha else None

    def configurada(self):
        """Falha fechado: o serviço não começa sem o arquivo de senha."""
        return self._senha() is not None

    def autorizada(self, cabecalho):
        if not isinstance(cabecalho, str) or not cabecalho.startswith("Bearer "):
            return False
        credencial = cabecalho[len("Bearer "):]
        if not credencial or len(credencial) > 512:
            return False
        senha = self._senha()
        if senha is None:
            return False
        return hmac.compare_digest(
            credencial.encode("utf-8"), senha.encode("utf-8")
        )
