FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DAEDALUS_ENV=production \
    DAEDALUS_DEMO_MODE=false \
    DAEDALUS_HOST=0.0.0.0 \
    DAEDALUS_PORT=8000 \
    DAEDALUS_DATABASE_URL=sqlite:////data/daedalus.db

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.9.5
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY scripts ./scripts
RUN uv sync --frozen --no-dev --no-editable

ENV PATH="/app/.venv/bin:${PATH}"

RUN mkdir -p /data && useradd --system --create-home --uid 10001 daedalus \
    && chown -R daedalus:daedalus /app /data
USER daedalus

EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["python", "-c", "import os,urllib.parse,urllib.request; host=urllib.parse.urlparse(os.environ['DAEDALUS_BASE_URL']).netloc; urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8000/healthz', headers={'Host':host}), timeout=3)"]
CMD ["python", "-m", "daedalus.server"]
