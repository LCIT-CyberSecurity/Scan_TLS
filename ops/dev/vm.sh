#!/usr/bin/env bash
# Sync the working tree to the integration VM and run a command there (never touches other stacks).
set -euo pipefail
HOST="${VM_HOST:-vm-integrations}"
DEST="${VM_DEST:-/home/cdev/tlsscan-dev}"
here="$(cd "$(dirname "$0")/../.." && pwd)"
rsync -rlz --omit-dir-times --no-perms --no-owner --no-group --delete --exclude .git --exclude .env --exclude .venv --exclude scan_reports --exclude logs --exclude node_modules --exclude dist \
  --exclude '__pycache__' --exclude '*.csv' --exclude '*.cbom.json' "$here/" "$HOST:$DEST/"
if [ $# -gt 0 ]; then ssh "$HOST" "cd $DEST && $*"; fi
