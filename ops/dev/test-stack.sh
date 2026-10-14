#!/usr/bin/env bash
# Runs the backend test suite against the isolated `tlsscan-test` compose project, wherever Docker is available
# (CI runner or the integration VM). Usage: ops/dev/test-stack.sh [pytest args]   (from ops/dev or the repo root)
set -uo pipefail
cd "$(dirname "$0")"
export TEST_MAX_DURATION="${TEST_MAX_DURATION:-300}" TEST_DB_PASSWORD="$(openssl rand -hex 8)" TEST_ADMIN_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=')"
compose() { docker compose -f compose.test.yaml "$@"; }
# Private CA + server certificate for the OpenLDAP lab (LDAPS / StartTLS tests validate the certificate for real).
if [ ! -f .ldap-certs/ldap.crt ]; then
  mkdir -p .ldap-certs && ( cd .ldap-certs
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca.key -out ca.crt -subj "/CN=TLS Scan LDAP test CA" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout ldap.key -out ldap.csr -subj "/CN=openldap" >/dev/null 2>&1
    printf "subjectAltName=DNS:openldap\nextendedKeyUsage=serverAuth\n" > san.cnf
    openssl x509 -req -in ldap.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -out ldap.crt -extfile san.cnf >/dev/null 2>&1
    openssl dhparam -out dhparam.pem 2048 >/dev/null 2>&1; chmod 644 *.key *.pem *.crt )
fi
compose --profile tests build >/dev/null 2>&1 && compose up -d --build postgres lab-tls lab-dns mock-oidc mock-graph openldap smtp-sink api worker scheduler >/dev/null 2>&1
compose run --rm tests pytest -p no:cacheprovider -x -q "${@:-tests/backend}"
rc=$?
compose down -v >/dev/null 2>&1
exit $rc
