#!/usr/bin/env bash
# Run the backend test suite on the integration VM. Usage: ops/dev/run-tests.sh [pytest args...]  (from the repo root)
set -euo pipefail
cd "$(dirname "$0")/../.."
args=""; for a in "$@"; do args+=" $(printf '%q' "$a")"; done
ops/dev/vm.sh "TEST_MAX_DURATION=${TEST_MAX_DURATION:-300} ops/dev/test-stack.sh$args"
