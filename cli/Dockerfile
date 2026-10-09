FROM python:3.12.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN groupadd --system --gid 10001 sentinelctl \
    && useradd --system --uid 10001 --gid sentinelctl --home-dir /app sentinelctl
WORKDIR /app
COPY requirements.txt pyproject.toml /app/
COPY sentinelctl /app/sentinelctl
RUN pip install . && chown -R sentinelctl:sentinelctl /app

FROM runtime AS test
COPY requirements-dev.txt /app/requirements-dev.txt
COPY tests /app/tests
RUN pip install -r /app/requirements-dev.txt && chown -R sentinelctl:sentinelctl /app/tests
USER sentinelctl
CMD ["pytest"]

FROM runtime AS production
USER sentinelctl
ENTRYPOINT ["sentinelctl"]
CMD ["--help"]
