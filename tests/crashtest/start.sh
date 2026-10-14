#!/usr/bin/env bash
# Start the CrashTest stack (on the integration VM) and seed it. Usage: tests/crashtest/start.sh [host]
set -euo pipefail
cd "$(dirname "$0")"
export CRASHTEST_HOST="${1:-${CRASHTEST_HOST:-localhost}}"
mkdir -p certs
[ -f certs/fullchain.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout certs/privkey.pem -out certs/fullchain.pem \
  -subj "/CN=$CRASHTEST_HOST" -addext "subjectAltName=DNS:$CRASHTEST_HOST,DNS:localhost,IP:127.0.0.1" 2>/dev/null
mkdir -p ldap-certs
if [ ! -f ldap-certs/ldap.crt ]; then
  ( cd ldap-certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca.key -out ca.crt -subj "/CN=TLS Scan CrashTest LDAP CA" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout ldap.key -out ldap.csr -subj "/CN=openldap" >/dev/null 2>&1
    printf 'subjectAltName=DNS:openldap\nextendedKeyUsage=serverAuth\n' > san.cnf
    openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -out ldap.crt -extfile san.cnf >/dev/null 2>&1
    openssl dhparam -out dhparam.pem 2048 >/dev/null 2>&1
    chmod 600 ca.key ldap.key
    chmod 644 ca.crt ldap.crt dhparam.pem )
fi
docker compose -f compose.crashtest.yaml up -d --build
docker compose -f compose.crashtest.yaml exec -T api python - < seed.py
echo "WebUI: https://$CRASHTEST_HOST:${CRASHTEST_HTTPS_PORT:-5100}  mailbox: http://$CRASHTEST_HOST:${CRASHTEST_MAIL_PORT:-5125}/messages  SSO mock: http://$CRASHTEST_HOST:${CRASHTEST_OIDC_PORT:-5110}"
