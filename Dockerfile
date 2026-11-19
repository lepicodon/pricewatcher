FROM python:3.14-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b

ARG INSTALL_PLAYWRIGHT=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PRICEWATCHER_DB_PATH=/data/prices.db \
    PRICEWATCHER_CONFIG_DIR=/app/config \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

COPY requirements.lock pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --no-deps -r requirements.lock && \
    pip install --no-cache-dir --no-deps . && \
    if [ "$INSTALL_PLAYWRIGHT" = "true" ]; then \
      pip install --no-cache-dir ".[playwright]" && \
      mkdir -p /ms-playwright && \
      playwright install --with-deps chromium && \
      chmod -R a+rX /ms-playwright; \
    fi

RUN groupadd --gid 10001 appuser && \
    useradd --create-home --uid 10001 --gid 10001 appuser && \
    mkdir -p /data /app/config/watches && \
    chown -R appuser:appuser /app /data

# Container starts as non-root appuser (USER 10001, UID/GID 10001).
# If explicitly started as root (--user 0:0), pricewatcher.main prepares bind-mounted
# /data and /app/config ownership and drops privileges to PUID/PGID (10001:10001).
USER 10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)" || exit 1

CMD ["pricewatcher", "--host", "0.0.0.0", "--port", "8080"]
