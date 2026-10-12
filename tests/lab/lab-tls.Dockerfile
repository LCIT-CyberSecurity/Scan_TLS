# Debian 13: nginx linked against OpenSSL 3.5, needed for the ML-KEM hybrid groups (X25519MLKEM768).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends nginx openssl python3 && rm -rf /var/lib/apt/lists/*
COPY tests/lab/nginx.conf /etc/nginx/nginx.conf
COPY tests/lab/entrypoint.sh /entrypoint.sh
COPY tests/lab/starttls_server.py /starttls_server.py
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
