# Imagem pequena, sem dependências extras: o cálculo linear usa Python puro.
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUTF8=1
ENV PYTHONUNBUFFERED=1

COPY . /app

# O -it na execução mantém o menu interativo disponível no terminal.
CMD ["python", "app.py"]
