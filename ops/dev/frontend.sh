#!/usr/bin/env bash
# Run a command (default: type-check + unit tests + build) in a Node container on the integration VM.
# No Node dependency is ever installed on the development machine.
set -euo pipefail
cd "$(dirname "$0")/../.."
cmd="${*:-npm install --no-audit --no-fund >/dev/null 2>&1; npx tsc -b && npx vitest run && npm run build}"
ops/dev/vm.sh "docker run --rm -u \$(id -u):\$(id -g) -e HOME=/tmp -v \$PWD/frontend:/app -w /app node:20-alpine sh -c '$cmd'"
