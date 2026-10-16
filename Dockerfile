FROM python:3.12-slim

WORKDIR /app
COPY . /app

RUN useradd --system --uid 10001 inventario && chown -R inventario:inventario /app
USER inventario
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('INVENTARIO_PORTA', '8080') + '/saude', timeout=3)" || exit 1
CMD ["python", "app.py", "--servico"]
