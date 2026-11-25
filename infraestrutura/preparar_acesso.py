"""Cria o segredo inicial no volume de dados, com entrada sem eco."""

import getpass
import os
from pathlib import Path


def main():
    caminho = Path(os.environ.get("INVENTARIO_SENHA_ARQUIVO", "/app/dados/senha-acesso"))
    if caminho.exists():
        raise SystemExit("O arquivo de acesso já existe.")
    segredo = getpass.getpass("Segredo da API: ")
    if not 16 <= len(segredo) <= 512 or not segredo.isascii() or not segredo.isprintable():
        raise SystemExit("Informe de 16 a 512 caracteres ASCII imprimíveis.")
    if any(caractere.isspace() for caractere in segredo):
        raise SystemExit("O segredo não pode conter espaços.")

    def criar_exclusivo(nome, flags):
        return os.open(nome, flags, 0o600)

    try:
        with open(caminho, "x", encoding="utf-8", opener=criar_exclusivo) as arquivo:
            arquivo.write(segredo)
    except FileExistsError:
        raise SystemExit("O arquivo de acesso já existe.") from None
    print("Acesso configurado.")


if __name__ == "__main__":
    main()
