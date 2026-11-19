#!/usr/bin/env bash
# Former name of bootstrap_orion-deployment.sh, kept so existing automations, cron jobs and runbooks keep working
# after the Orion rebranding. Same commands, options and exit codes: everything is forwarded unchanged.
# Deprecated: call ./bootstrap_orion-deployment.sh instead; this alias will be removed in a later major version.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
printf '%s\n' "bootstrap_tls-scan-deployment.sh est renommé bootstrap_orion-deployment.sh (alias conservé)." >&2
exec "$ROOT/bootstrap_orion-deployment.sh" "$@"
