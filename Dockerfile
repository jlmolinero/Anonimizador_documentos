FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app \
    && mkdir -p /data \
    && chown -R app:app /data /app

COPY requirements_anonimizador.txt ./
RUN pip install --no-cache-dir -r requirements_anonimizador.txt

COPY --chown=app:app anonimizar_documentos.py inspect_document_metadata.py web_metadata_app.py ./

USER app
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3).read()" || exit 1

CMD ["python", "web_metadata_app.py", "--host", "0.0.0.0", "--port", "8000", "--cache-dir", "/data"]
