FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.30" "authlib>=1.3" "python-multipart>=0.0.9" \
    && useradd --create-home --uid 10001 mock
WORKDIR /app
COPY tests/lab/mock_oidc/app.py .
USER mock
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
