#!/usr/bin/env bash
# Run the backend test suite on the integration VM in the isolated tlsscan-test project.
# Usage: ops/dev/run-tests.sh [pytest args...]   (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../.."
ops/dev/vm.sh "cd ops/dev && export TEST_DB_PASSWORD=\$(openssl rand -hex 8) TEST_ADMIN_PASSWORD=\$(openssl rand -base64 18 | tr -d '/+=') && \
  docker compose -f compose.test.yaml --profile tests build >/dev/null 2>&1 && docker compose -f compose.test.yaml up -d --build postgres lab-tls api worker scheduler >/dev/null 2>&1 && \
  docker compose -f compose.test.yaml run --rm tests pytest -p no:cacheprovider -x -q ${*:-tests/backend}; rc=\$?; \
  docker compose -f compose.test.yaml down -v >/dev/null 2>&1; exit \$rc"
