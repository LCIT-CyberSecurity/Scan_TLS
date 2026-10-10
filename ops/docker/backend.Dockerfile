FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends nmap openssl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 tlsscan && mkdir -p /var/lib/tls-scan && chown tlsscan /var/lib/tls-scan
WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY tls_scanner ./tls_scanner
COPY backend ./backend
ARG WITH_DEV=false
RUN pip install --no-cache-dir -e ".[dev]" && if [ "$WITH_DEV" = "false" ]; then pip uninstall -y pytest pytest-cov ruff aiosmtpd || true; fi
COPY tests ./tests
COPY test_tls_scanner.py tls_scan.py ./
COPY config ./config
ENV PYTHONPATH=/app/backend/src:/app PYTHONUNBUFFERED=1
USER tlsscan
CMD ["uvicorn", "--factory", "tls_scan_app.app:create_app", "--host", "0.0.0.0", "--port", "8000"]
