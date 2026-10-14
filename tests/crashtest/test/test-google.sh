#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/ops/dev/compose.test.yaml"
PROJECT="tlsscan-crashtest-google-$(id -u)-${BASHPID}"
ARTIFACTS="${SCRIPT_DIR}/artifacts"
mkdir -p "${ARTIFACTS}"

command -v docker >/dev/null 2>&1 || { printf 'Docker is required. Run this on the integration VM.\n' >&2; exit 2; }
docker version >/dev/null 2>&1 || { printf 'Docker Engine is not reachable.\n' >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { printf 'Docker Compose is unavailable.\n' >&2; exit 2; }

cleanup() {
  docker compose -p "${PROJECT}" -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Google Workspace flow: mock OIDC only; this does not validate Google connectivity or a real Workspace.\n'
set +e
COMPOSE_PROJECT_NAME="${PROJECT}" "${REPO_ROOT}/ops/dev/test-stack.sh" \
  tests/backend/test_auth_providers.py -k google 2>&1 | tee "${ARTIFACTS}/google-mock.log"
result=${PIPESTATUS[0]}
set -e
exit "${result}"
