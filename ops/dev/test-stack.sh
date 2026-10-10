#!/usr/bin/env bash
# Runs the backend test suite against the isolated `tlsscan-test` compose project, wherever Docker is available
# (CI runner or the integration VM). Usage: ops/dev/test-stack.sh [pytest args]   (from ops/dev or the repo root)
set -uo pipefail
cd "$(dirname "$0")"
export TEST_MAX_DURATION="${TEST_MAX_DURATION:-300}" TEST_DB_PASSWORD="$(openssl rand -hex 8)" TEST_ADMIN_PASSWORD="$(openssl rand -base64 18 | tr -d '/+=')"
compose() { docker compose -f compose.test.yaml "$@"; }
compose --profile tests build >/dev/null 2>&1 && compose up -d --build postgres lab-tls mock-oidc mock-graph openldap smtp-sink api worker scheduler >/dev/null 2>&1
compose run --rm tests pytest -p no:cacheprovider -x -q "${@:-tests/backend}"
rc=$?
compose down -v >/dev/null 2>&1
exit $rc
