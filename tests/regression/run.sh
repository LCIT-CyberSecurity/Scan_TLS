#!/usr/bin/env bash
# Standalone non-regression: run the historical engine (BASE commit) and the current engine on the same lab
# target with the same YAML configuration, then compare every exported artefact (timestamps/ids normalised).
# Runs on the integration VM (Docker). Usage: tests/regression/run.sh [BASE_COMMIT]   (default: first parent of feature branch = main)
set -euo pipefail
cd "$(dirname "$0")/../.."
BASE="${1:-$(git merge-base HEAD main)}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/base"
git archive "$BASE" tls_scanner tls_scan.py | tar -x -C "$tmp/base"
echo "Baseline engine: $BASE"
ops/dev/vm.sh >/dev/null
HOST="${VM_HOST:-vm-integrations}"; DEST="${VM_DEST:-/home/cdev/tlsscan-dev}"
rsync -rlz --delete "$tmp/base/" "$HOST:$DEST/.regression-base/"
ssh "$HOST" "cd $DEST && bash tests/regression/compare.sh"
