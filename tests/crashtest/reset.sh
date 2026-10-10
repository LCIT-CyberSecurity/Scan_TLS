#!/usr/bin/env bash
# Destroy the CrashTest stack and its volumes (only this project: tlsscan-crashtest).
set -euo pipefail
cd "$(dirname "$0")"
docker compose -f compose.crashtest.yaml down -v --remove-orphans
