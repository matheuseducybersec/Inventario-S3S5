# Imagem enxuta com Python 3.12
FROM python:3.12-slim

# Não gerar .pyc e mostrar logs na hora
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    INVENTARIO_DADOS=/app/data

WORKDIR /app

# 1) Dependências primeiro: esta camada fica em cache enquanto o
#    requirements.txt não mudar, então rebuilds ficam rápidos.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2) Código da aplicação
COPY app ./app
COPY tests ./tests

# 3) Segurança: a aplicação NÃO roda como root dentro do container
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app
USER appuser

# Os dados JSON ficam num volume: sobrevivem a restart/rebuild do container
VOLUME ["/app/data"]

EXPOSE 8000

# O Docker consulta /health a cada 30 s; 3 falhas seguidas = "unhealthy"
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"

# Processo principal: servidor HTTP que fica no ar indefinidamente
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
