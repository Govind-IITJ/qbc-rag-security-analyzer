FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY qbc_rag_security ./qbc_rag_security
COPY frontend ./frontend

RUN useradd --create-home --uid 10001 qbc     && mkdir -p /data     && chown -R qbc:qbc /app /data

USER qbc
ENV QBC_SECURITY_DB=/data/qbc_security.sqlite3

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --retries=3   CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
