#!/usr/bin/env bash
# Start the CrashTest stack (on the integration VM) and seed it. Usage: tests/crashtest/start.sh [host]
set -euo pipefail
cd "$(dirname "$0")"
export CRASHTEST_HOST="${1:-${CRASHTEST_HOST:-localhost}}"
mkdir -p certs
[ -f certs/fullchain.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout certs/privkey.pem -out certs/fullchain.pem \
  -subj "/CN=$CRASHTEST_HOST" -addext "subjectAltName=DNS:$CRASHTEST_HOST,DNS:localhost,IP:127.0.0.1" 2>/dev/null
docker compose -f compose.crashtest.yaml up -d --build
docker compose -f compose.crashtest.yaml exec -T api python - < seed.py
echo "WebUI: https://$CRASHTEST_HOST:${CRASHTEST_HTTPS_PORT:-5100}  mailbox: http://$CRASHTEST_HOST:${CRASHTEST_MAIL_PORT:-5125}/messages  SSO mock: http://$CRASHTEST_HOST:${CRASHTEST_OIDC_PORT:-5110}"
