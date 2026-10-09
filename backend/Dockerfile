FROM python:3.12.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/backend

RUN groupadd --system --gid 10001 sentinelforge \
    && useradd --system --uid 10001 --gid sentinelforge --home-dir /app sentinelforge

WORKDIR /app
COPY requirements.txt /app/backend/requirements.txt
RUN pip install -r /app/backend/requirements.txt

COPY sentinelforge /app/backend/sentinelforge
COPY alembic /app/backend/alembic
COPY alembic.ini pyproject.toml /app/backend/
COPY docker-entrypoint.sh /usr/local/bin/sentinelforge-entrypoint
RUN chown -R sentinelforge:sentinelforge /app \
    && chmod 0555 /usr/local/bin/sentinelforge-entrypoint

FROM runtime AS test
COPY requirements-dev.txt /app/backend/requirements-dev.txt
COPY tests /app/backend/tests
RUN pip install -r /app/backend/requirements-dev.txt
RUN chown -R sentinelforge:sentinelforge /app/backend/tests
USER sentinelforge
WORKDIR /app/backend
CMD ["python", "-m", "pytest"]

FROM runtime AS production
ENV SENTINELFORGE_ENV=production SENTINELFORGE_AUTO_CREATE_SCHEMA=false
USER sentinelforge
WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
ENTRYPOINT ["/usr/local/bin/sentinelforge-entrypoint"]
CMD ["uvicorn", "sentinelforge.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
