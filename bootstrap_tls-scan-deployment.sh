#!/usr/bin/env bash
# TLS Scan deployment manager (WebUI mode). The Standalone CLI needs none of this.
#
#   ./bootstrap_tls-scan-deployment.sh <command>
#
#   install        first installation: .env + secrets, certificate, build, start, health check, initial admin password
#   update         pull code changes (git), rebuild, apply migrations, restart; data is preserved
#   status         container and health status
#   backup [DIR]   PostgreSQL dump + report files into DIR (default ./backups)
#   restore FILE   restore a backup (asks for explicit confirmation)
#   reset-admin    reset the local administrator to a new one-time password (--default: SecretPassword) for the local administrator
#   logs [SERVICE] follow technical logs
#   reinstall      stop and rebuild images, KEEPING data volumes
#   uninstall      remove containers and images; volumes only if you also confirm data deletion
#
# Needs Bash, Docker with the Compose plugin and openssl. Only ever touches the Docker project named
# by TLS_SCAN_PROJECT (default "tls-scan"). .env is created if missing and never overwritten.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1
ENV_FILE="$ROOT/.env"

if [ -t 1 ]; then BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'; else BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""; fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✔ %s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
die()  { printf '%s✖ %s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

dc() { docker compose --project-directory "$ROOT" -f "$ROOT/compose.yaml" "$@"; }
envval() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-; }
setenv() { # setenv KEY VALUE  (only when the key is empty or missing)
  if grep -qE "^$1=" "$ENV_FILE"; then
    [ -n "$(envval "$1")" ] || sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"
  else printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"; fi
}
confirm_typed() { local answer; say "Type exactly:  $1"; printf '> '; read -r answer || answer=""; [ "$answer" = "$1" ]; }

preflight() {
  command -v docker >/dev/null || die "Docker is required."
  docker compose version >/dev/null 2>&1 || die "The Docker Compose plugin is required."
  command -v openssl >/dev/null || die "openssl is required."
}

ensure_env() {
  if [ ! -f "$ENV_FILE" ]; then
    (umask 077; cp "$ROOT/.env.example" "$ENV_FILE"); ok ".env created from .env.example"
  fi
  chmod 600 "$ENV_FILE"
  setenv POSTGRES_PASSWORD "$(openssl rand -hex 24)"
  setenv TLS_SCAN_SESSION_SECRET "$(openssl rand -hex 32)"
}

ensure_certificate() {
  local dir; dir="$(envval TLS_SCAN_CERT_DIR)"; dir="${dir:-$ROOT/data/certs}"
  mkdir -p "$dir"
  if [ ! -f "$dir/fullchain.pem" ]; then
    local host; host="$(printf '%s' "$(envval TLS_SCAN_PUBLIC_BASE_URL)" | sed -E 's#^https?://##; s#[:/].*##')"; host="${host:-localhost}"
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" \
      -subj "/CN=$host" -addext "subjectAltName=DNS:$host,DNS:localhost" 2>/dev/null || die "certificate generation failed"
    chmod 600 "$dir/privkey.pem"
    warn "Self-signed certificate generated in $dir. Replace fullchain.pem / privkey.pem with your own for production."
  fi
}

wait_healthy() {
  say "Waiting for the services to become healthy..."
  for _ in $(seq 1 60); do
    if [ "$(dc ps --format '{{.Health}}' api 2>/dev/null | head -1)" = "healthy" ]; then ok "API healthy"; return 0; fi
    sleep 3
  done
  dc logs --tail 30 api; die "The API did not become healthy."
}

show_admin_password() {
  say ""; say "${BOLD}Initial administrator${RESET}"
  say "  user:      admin"
  say "  password:  SecretPassword   (default: you must change it at first sign-in)"
}

cmd_install() {
  preflight; ensure_env; ensure_certificate
  dc build || die "build failed"
  dc up -d || die "start failed"
  wait_healthy
  show_admin_password
  ok "Installed. Open $(envval TLS_SCAN_PUBLIC_BASE_URL)"
}

cmd_update() {
  preflight; [ -f "$ENV_FILE" ] || die "No .env: run install first."
  if [ -d .git ] && git diff --quiet 2>/dev/null; then git pull --ff-only || warn "git pull skipped/failed; continuing with the local code"; fi
  say "A backup is taken before updating."; cmd_backup "$ROOT/backups" || die "backup failed; update aborted"
  dc build || die "build failed"
  dc up -d || die "start failed"     # the API container runs 'alembic upgrade head' on start
  wait_healthy; ok "Updated. Data, users, policies, scans and reports are preserved."
}

cmd_status() { dc ps; curl -fsk "https://localhost:$(envval TLS_SCAN_HTTPS_PORT)/api/health/ready" 2>/dev/null && echo || warn "health endpoint not reachable"; }

cmd_backup() {
  preflight; local dir="${1:-$ROOT/backups}"; mkdir -p "$dir"; chmod 700 "$dir"
  local stamp; stamp="$(date +%Y%m%d-%H%M%S)"; local out="$dir/tls-scan-$stamp.tar"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "${tmp:-}"' RETURN
  dc exec -T postgres pg_dump -U tls_scan -Fc tls_scan > "$tmp/db.dump" || die "pg_dump failed"
  dc exec -T api tar -C /var/lib/tls-scan -cf - reports logs 2>/dev/null > "$tmp/files.tar" || true
  tar -C "$tmp" -cf "$out" db.dump files.tar && chmod 600 "$out"
  ok "Backup written: $out"
}

cmd_restore() {
  preflight; local file="${1:-}"; [ -f "$file" ] || die "Usage: restore <backup.tar>"
  warn "Restoring REPLACES the current database and report files."
  confirm_typed "RESTORE" || die "Cancelled."
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "${tmp:-}"' RETURN
  tar -C "$tmp" -xf "$file" || die "unreadable backup"
  dc stop api worker scheduler >/dev/null
  dc exec -T postgres dropdb -U tls_scan --if-exists tls_scan && dc exec -T postgres createdb -U tls_scan tls_scan || die "cannot recreate database"
  dc exec -T postgres pg_restore -U tls_scan -d tls_scan --no-owner < "$tmp/db.dump" || die "pg_restore failed"
  dc up -d >/dev/null
  wait_healthy
  if [ -s "$tmp/files.tar" ]; then dc exec -T api tar -C /var/lib/tls-scan -xf - < "$tmp/files.tar" || warn "report files could not be restored"; fi
  ok "Restore complete."
}

cmd_reset_admin() { preflight; say "New password:"; dc exec -T api python -m tls_scan_app.cli reset-admin-password "$@"; }
cmd_logs() { dc logs -f --tail 100 "${1:-}"; }

cmd_reinstall() { preflight; warn "Images are rebuilt, containers recreated. Data volumes are kept."; dc down; cmd_install; }

cmd_uninstall() {
  preflight; warn "This removes the TLS Scan containers and images."
  confirm_typed "UNINSTALL" || die "Cancelled."
  dc down --rmi local || true
  say "The data volumes (database, reports) and .env were KEPT."
  say "To also delete ALL data permanently, confirm below."
  if confirm_typed "DELETE-ALL-DATA"; then dc down -v --rmi local; ok "Data volumes deleted."; fi
}

case "${1:-}" in
  install) cmd_install ;; update) cmd_update ;; status) cmd_status ;;
  backup) shift; cmd_backup "$@" ;; restore) shift; cmd_restore "$@" ;;
  reset-admin) shift; cmd_reset_admin "$@" ;; logs) shift; cmd_logs "$@" ;;
  reinstall) cmd_reinstall ;; uninstall) cmd_uninstall ;;
  *) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
