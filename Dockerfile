FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app
RUN useradd --system --uid 10001 inventario \
    && chown -R inventario:inventario /app
USER inventario

ENV INVENTARIO_PORTA=2217 PYTHONUNBUFFERED=1
EXPOSE 2217
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('INVENTARIO_PORTA', '2217') + '/saude', timeout=3)" || exit 1

CMD ["python", "app.py", "--servico"]
