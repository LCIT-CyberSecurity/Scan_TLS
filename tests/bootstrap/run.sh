#!/usr/bin/env bash
# Tests of bootstrap_tls-scan-deployment.sh: Docker is faked (tests/bootstrap/fake-docker.sh), Git is real
# (throw-away repositories), the PATH of each run is a private directory of links so that the host's real
# docker/nmap are never reachable. Plain Bash, no dependency. Run: tests/bootstrap/run.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
BASE_TOOLS="bash sh sed awk grep cat mktemp tr head tail cut sort uniq printf date tar gzip sha256sum chmod mkdir rm mv cp ln ls id stat dirname basename seq sleep touch timeout wc od find readlink uname env tee openssl git python3 diff cmp expr true false test tput stty"

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -z "${2:-}" ] || printf '%s\n' "$2" | sed 's/^/       | /' | tail -n 20; }
check() { # check "description" command...
  local d="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi
}
contains() { printf '%s' "$OUT" | grep -qF -- "$1"; }
has_out() { if contains "$1"; then ok "$2"; else bad "$2 (missing: $1)" "$OUT"; fi; }
no_out()  { if contains "$1"; then bad "$2 (found: $1)" "$OUT"; else ok "$2"; fi; }
rc_is()   { if [ "$RC" = "$1" ]; then ok "$2 (exit $1)"; else bad "$2 (exit $RC, expected $1)" "$OUT"; fi; }
called()  { grep -qF -- "$1" "$S/calls" 2>/dev/null; }
calls_has() { if called "$1"; then ok "$2"; else bad "$2 (no call: $1)"; fi; }
calls_not() { if called "$1"; then bad "$2 (unexpected call: $1)"; else ok "$2"; fi; }
db() { cat "$S/volumes/tls-scan_pgdata/db" 2>/dev/null | tr '\n' ' '; }

# new_sandbox NAME [tools]: a copy of the deployment files, a private PATH, an empty fake-Docker state.
new_sandbox() {
  printf '\n== %s\n' "$1"
  D="$WORK/$1"; S="$D/state"; BIN="$D/bin"; R="$D/repo"
  mkdir -p "$BIN" "$S" "$R/config" "$R/ops/docker"
  cp "$REPO/bootstrap_tls-scan-deployment.sh" "$R/"
  cp "$REPO/.gitignore" "$R/.gitignore"
  printf 'name: ${TLS_SCAN_PROJECT:-tls-scan}\nservices: {}\n' >"$R/compose.yaml"
  cp "$REPO/.env.example" "$R/.env.example"
  printf '# no dependency in the test sandbox\n' >"$R/requirements.txt"
  printf '[project]\nrequires-python = ">=3.8"\n' >"$R/pyproject.toml"
  printf 'defaults: {}\nreports:\n  - name: demo\n' >"$R/config/config.yaml"
  cat >"$R/tls_scan.py" <<'PY'
import sys
open("scan_invocations.log", "a").write(" ".join(sys.argv[1:]) + "\n")
if "--list-reports" in sys.argv: print("demo")
PY
  local t p
  for t in $BASE_TOOLS; do p="$(command -v "$t" 2>/dev/null)" && [ -n "$p" ] && ln -sf "$p" "$BIN/$t"; done
  cp "$HERE/fake-docker.sh" "$BIN/docker"
  printf '#!/bin/sh\necho "Nmap version 7.94 (fake)"\n' >"$BIN/nmap"; chmod +x "$BIN/nmap"
  export FAKE_STATE="$S" TLS_SCAN_PY_MODULES="sys" TLS_SCAN_HTTPS_PORT=18443 TLS_SCAN_HTTP_PORT=18080
  unset FAKE_NO_DAEMON FAKE_FAIL_PGDUMP FAKE_FAIL_UP FAKE_FAIL_TAR TLS_SCAN_PROJECT TLS_SCAN_VERSION
}
no_tool() { rm -f "$BIN/$1"; }
git_repo() { # turns the sandbox into a clone with an upstream
  ( cd "$R" && git init -q -b main . && git config user.email t@t && git config user.name t \
    && git add -A && git commit -q -m init && git init -q --bare -b main "$D/origin.git" \
    && git remote add origin "$D/origin.git" && git push -q -u origin main ) >/dev/null 2>&1
}
upstream_commit() { # a new commit on origin/main, from a second clone
  rm -rf "$D/other"; git clone -q -b main "$D/origin.git" "$D/other" 2>/dev/null
  ( cd "$D/other" && git config user.email t@t && git config user.name t && echo new >>README.new && git add -A && git commit -q -m "new version" && git push -q origin main ) >/dev/null 2>&1
}
# bs [--stdin TEXT] ARGS...: runs the script; sets OUT and RC. stdin defaults to empty (non-interactive).
bs() {
  local input=""
  if [ "${1:-}" = "--stdin" ]; then input="$2"; shift 2; fi
  OUT="$(cd "$R" && printf '%b' "$input" | env PATH="$BIN" HOME="$D" "$R/bootstrap_tls-scan-deployment.sh" "$@" 2>&1)"; RC=$?
}

# ---------------------------------------------------------------------------------------------------
new_sandbox syntax
check "bash -n" bash -n "$REPO/bootstrap_tls-scan-deployment.sh"
check "bash -n (tests)" bash -n "$HERE/run.sh"
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S warning "$REPO/bootstrap_tls-scan-deployment.sh" >"$WORK/sc.txt" 2>&1; then ok "shellcheck"; else bad "shellcheck" "$(cat "$WORK/sc.txt")"; fi
else printf '  skip shellcheck (not installed)\n'; fi

# ---------------------------------------------------------------------------------------------------
new_sandbox menu
bs --stdin '0\n'
has_out "TLS Scan Manager" "main menu banner"
has_out "[1] Standalone (autonome)" "main menu: Standalone"
has_out "[2] WebUI (Docker)" "main menu: WebUI"
has_out "Votre choix" "main menu prompt"
rc_is 0 "quit from the main menu"
check "main menu does not call Docker" test ! -s "$S/calls"
bs --stdin '1\n0\n0\n'
has_out "TLS Scan — Standalone" "Standalone menu"
has_out "[4] Réinstaller" "Standalone menu entries"
no_out "Sauvegarder" "no WebUI entry in the Standalone menu"
check "Standalone menu does not call Docker" test ! -s "$S/calls"
bs --stdin '2\n0\n0\n'
has_out "TLS Scan — WebUI (Docker)" "WebUI menu"
has_out "[7] Réinitialiser le compte administrateur" "WebUI menu entries"
no_out "Environnement virtuel" "no Standalone entry in the WebUI menu"
bs --stdin '9\n0\n'
has_out "Choix invalide" "invalid menu choice"
no_tool docker
bs --stdin '1\n0\n0\n'
has_out "TLS Scan — Standalone" "Standalone menu without Docker installed"
bs --stdin '2\n\n0\n'
has_out "Docker est introuvable" "WebUI mode reports a missing Docker only once chosen"

# ---------------------------------------------------------------------------------------------------
new_sandbox standalone-install
no_tool docker; printf '#!/bin/sh\necho DOCKER-CALLED >>"%s/docker-called"\nexit 99\n' "$D" >"$BIN/docker"; chmod +x "$BIN/docker"
bs --mode standalone install
rc_is 0 "Standalone install"
has_out "[1/5] Vérification des prérequis (Python, Nmap)" "numbered steps"
has_out "OK" "OK status"
has_out "python tls_scan.py --config config/config.yaml" "scan commands displayed"
check "virtualenv created" test -x "$R/.venv/bin/python"
check "Docker never called" test ! -e "$D/docker-called"
check "no .env created" test ! -e "$R/.env"
check "only validation invocations of the CLI (no scan)" bash -c "! grep -v -e '--help' -e '--list-reports' -e '--dry-run' '$R/scan_invocations.log'"
check "every report validated with --dry-run" grep -q -e '--report demo --dry-run' "$R/scan_invocations.log"
mkdir -p "$R/logs" "$R/scan_reports"; echo keep >"$R/logs/a.log"; echo keep >"$R/scan_reports/r.html"; echo "# mine" >>"$R/config/config.yaml"
bs --mode standalone install
rc_is 0 "Standalone install is idempotent"
has_out "réutilisé" "existing virtualenv reused"
check "config preserved" grep -q "# mine" "$R/config/config.yaml"
check "logs and reports preserved" test -f "$R/logs/a.log" -a -f "$R/scan_reports/r.html"
bs --mode standalone status
rc_is 0 "Standalone status"
has_out "Installation vérifiée" "installation verified"
bs --mode standalone backup
rc_is 1 "WebUI-only command refused in Standalone"
bs --mode standalone reinstall
rc_is 3 "Standalone reinstall cancelled without confirmation"
check "virtualenv kept after a cancelled reinstall" test -x "$R/.venv/bin/python"
bs --mode standalone --yes reinstall
rc_is 0 "Standalone reinstall (--yes)"
check "virtualenv recreated" test -x "$R/.venv/bin/python"
check "logs/reports still there after reinstall" test -f "$R/logs/a.log" -a -f "$R/scan_reports/r.html"
git_repo
bs --stdin 'n\nnope\n' --mode standalone uninstall
rc_is 3 "Standalone uninstall: wrong confirmation cancels"
check "virtualenv kept after cancellation" test -x "$R/.venv/bin/python"
bs --stdin 'n\nDESINSTALLER STANDALONE\n' --mode standalone uninstall
rc_is 0 "Standalone uninstall"
check "virtualenv removed" test ! -e "$R/.venv"
check "user files kept by default" test -f "$R/logs/a.log" -a -f "$R/scan_reports/r.html" -a -f "$R/config/config.yaml"
check "Git repository kept" test -d "$R/.git"
bs --yes --delete-data --mode standalone uninstall
rc_is 0 "Standalone uninstall --delete-data"
check "user files deleted only on explicit request" test ! -e "$R/logs" -a ! -e "$R/scan_reports"
check "config/ still there" test -f "$R/config/config.yaml"

# ---------------------------------------------------------------------------------------------------
new_sandbox standalone-missing
no_tool nmap
bs --mode standalone install
rc_is 1 "install fails without Nmap"
has_out "nmap" "missing Nmap named"
has_out "Aucun gestionnaire de paquets reconnu" "no package manager: nothing installed, instructions only"
check "no virtualenv created" test ! -e "$R/.venv"
printf '#!/bin/sh\necho "PM-CALLED $*" >>"%s/pm-called"\n' "$D" >"$BIN/apt-get"; chmod +x "$BIN/apt-get"
bs --mode standalone install
has_out "Rien n'a été installé" "system packages are never installed without an explicit yes"
check "package manager not run" test ! -e "$D/pm-called"
no_tool python3
bs --mode standalone install
rc_is 1 "install fails without Python"
has_out "python3" "missing Python named"

# ---------------------------------------------------------------------------------------------------
new_sandbox webui-install
no_tool python3; no_tool nmap
bs --mode webui install
rc_is 0 "WebUI install"
has_out "[1/9] Vérification des prérequis Docker" "numbered steps"
has_out "admin / SecretPassword" "initial administrator shown"
calls_has "build" "images built"
calls_has "up -d --wait" "containers started"
check ".env created, mode 600" test "$(stat -c %a "$R/.env")" = 600
check "secrets generated" bash -c "grep -q '^POSTGRES_PASSWORD=.\{20,\}' '$R/.env' && grep -q '^TLS_SCAN_SESSION_SECRET=.\{40,\}' '$R/.env'"
SECRET="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$R/.env")"
no_out "$SECRET" "no secret in the output"
check "self-signed certificate generated" test -s "$R/data/certs/fullchain.pem" -a -s "$R/data/certs/privkey.pem"
check "no native component installed" test ! -e "$R/.venv"
check "database holds the administrator only" test "$(db)" = "user:admin "
CERT_SUM="$(sha256sum "$R/data/certs/fullchain.pem" | cut -c1-64)"
echo "MARK=1" >>"$R/.env"
echo "user:alice" >>"$S/volumes/tls-scan_pgdata/db"
bs --mode webui install
rc_is 0 "WebUI install again (idempotent)"
check ".env preserved" grep -q "MARK=1" "$R/.env"
check "secrets not regenerated" test "$(sed -n 's/^POSTGRES_PASSWORD=//p' "$R/.env")" = "$SECRET"
check "certificate preserved" test "$(sha256sum "$R/data/certs/fullchain.pem" | cut -c1-64)" = "$CERT_SUM"
check "data preserved" test "$(db)" = "user:admin user:alice "
calls_not "down -v" "no volume removal on a re-install"
bs --mode webui status
rc_is 0 "WebUI status"
has_out "État : Installé" "state shown"

# ---------------------------------------------------------------------------------------------------
new_sandbox webui-safety
bs --mode webui install
cp "$R/data/certs/privkey.pem" "$D/key.bak"
openssl req -x509 -newkey rsa:2048 -nodes -days 5 -keyout "$D/other.key" -out "$R/data/certs/fullchain.pem" -subj /CN=other 2>/dev/null
bs --mode webui install
rc_is 1 "mismatched certificate and key refused"
has_out "ne correspondent pas" "mismatch explained"
check "key untouched" cmp -s "$D/key.bak" "$R/data/certs/privkey.pem"
rm -f "$R/data/certs/privkey.pem"
bs --mode webui install
rc_is 1 "certificate without key refused"
check "nothing generated over the remaining certificate" test ! -e "$R/data/certs/privkey.pem"
new_sandbox webui-env-lost
bs --mode webui install
sed -i 's/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=/' "$R/.env"
bs --mode webui install
rc_is 1 "database volume without its password refused"
has_out "rendrait la base inaccessible" "reason shown"
check "password not silently regenerated" grep -q '^POSTGRES_PASSWORD=$' "$R/.env"
new_sandbox webui-ports
no_tool docker
bs --mode webui install
rc_is 1 "install without Docker"
has_out "Docker est introuvable" "missing Docker reported"
new_sandbox webui-nodaemon
export FAKE_NO_DAEMON=1
bs --mode webui install
rc_is 1 "install with a stopped Docker daemon"
has_out "démon Docker" "stopped daemon reported"
unset FAKE_NO_DAEMON

# ---------------------------------------------------------------------------------------------------
new_sandbox isolation
export TLS_SCAN_PROJECT=tlsscan-crashtest
bs --mode webui install
rc_is 1 "CrashTest project refused"
has_out "projet de test" "reason shown"
calls_not "compose" "no Compose call for a CrashTest project"
unset TLS_SCAN_PROJECT
export TLS_SCAN_VERSION=crashtest
bs --mode webui uninstall --yes --delete-data
rc_is 1 "CrashTest image tag refused"
unset TLS_SCAN_VERSION
: >"$S/up_tlsscan-crashtest"; mkdir -p "$S/volumes/tlsscan-crashtest_pgdata"; echo "user:demo" >"$S/volumes/tlsscan-crashtest_pgdata/db"
bs --mode webui install
bs --mode webui --yes --delete-data uninstall
check "foreign/CrashTest project untouched by a WebUI uninstall" test -f "$S/up_tlsscan-crashtest" -a -f "$S/volumes/tlsscan-crashtest_pgdata/db"
check "no call names the CrashTest project" bash -c "! grep -q crashtest '$S/calls'"
bs --mode webui install
bs --mode standalone install
check "Standalone install leaves WebUI untouched" test -f "$R/.env"
bs --yes --mode standalone uninstall
check "Standalone uninstall leaves .env and certificates" test -f "$R/.env" -a -d "$R/data/certs"

# ---------------------------------------------------------------------------------------------------
new_sandbox update-git
bs --mode webui install; git_repo
echo "user:alice" >>"$S/volumes/tls-scan_pgdata/db"
echo "local edit" >>"$R/README.local"; B0="$(grep -c 'compose.* build' "$S/calls")"
bs --mode webui update
rc_is 1 "update refused with local modifications"
has_out "modifications locales" "reason shown"
check "nothing rebuilt" test "$(grep -c 'compose.* build' "$S/calls")" = "$B0"
check "local file untouched" grep -q "local edit" "$R/README.local"
rm -f "$R/README.local"
bs --mode webui update
rc_is 3 "update without a new version, not confirmed (non-interactive)"
has_out "Aucune nouvelle version" "no-update message"
check "no backup written when cancelled" test ! -d "$R/backups"
bs --mode webui --yes update
rc_is 0 "redeploy of the current version (--yes)"
check "backup written before the update" bash -c "ls '$R'/backups/tls-scan-backup-*.tar.gz >/dev/null"
check "data preserved by the update" test "$(db)" = "user:admin user:alice "
BK="$(ls "$R"/backups/*.tar.gz | head -n 1)"
check "archive holds db.dump, data.tar, SHA256SUMS, MANIFEST.txt" bash -c "tar -tzf '$BK' | LC_ALL=C sort | tr '\n' ' ' | grep -q 'MANIFEST.txt SHA256SUMS data.tar db.dump'"
check "archive mode 600" test "$(stat -c %a "$BK")" = 600
upstream_commit
HEAD0="$(git -C "$R" rev-parse HEAD)"
bs --mode webui --yes update
rc_is 0 "update with a new version"
check "fast-forwarded to origin/main" test "$(git -C "$R" rev-parse HEAD)" = "$(git -C "$R" rev-parse origin/main)" -a "$(git -C "$R" rev-parse HEAD)" != "$HEAD0"
check "branch unchanged" test "$(git -C "$R" rev-parse --abbrev-ref HEAD)" = main
echo "local commit" >"$R/local.txt"; git -C "$R" add local.txt; git -C "$R" -c user.email=t@t -c user.name=t commit -q -m local
upstream_commit2() { ( cd "$D/other" && git pull -q origin main && echo n2 >>README.new && git commit -qam n2 && git push -q origin main ) >/dev/null 2>&1; }
upstream_commit2
bs --mode webui --yes update
rc_is 1 "diverged branch refused"
has_out "divergé" "divergence explained"
check "no reset: local commit kept" test -f "$R/local.txt"
bs --mode webui --yes --no-git update
rc_is 0 "redeploy of the local code with --no-git"

# ---------------------------------------------------------------------------------------------------
new_sandbox update-backup-failure
bs --mode webui install; git_repo; upstream_commit
HEAD0="$(git -C "$R" rev-parse HEAD)"
export FAKE_FAIL_PGDUMP=1
CALLS0="$(grep -c 'compose.* build' "$S/calls")"
bs --mode webui update
rc_is 1 "update aborted when the backup fails"
has_out "La sauvegarde a échoué" "failure reported"
check "code not updated" test "$(git -C "$R" rev-parse HEAD)" = "$HEAD0"
check "no rebuild after the failed backup" test "$(grep -c 'compose.* build' "$S/calls")" = "$CALLS0"
check "no partial archive left" bash -c "! ls '$R'/backups/*.tar.gz >/dev/null 2>&1; ! ls -A '$R'/backups/.tls-scan-backup.* >/dev/null 2>&1"
unset FAKE_FAIL_PGDUMP
bs --mode webui --yes --no-backup update
rc_is 0 "explicit --no-backup lets the update go on"
has_out "IGNORÉE" "skipped backup shown"

# ---------------------------------------------------------------------------------------------------
new_sandbox backup-restore
bs --mode webui install
echo "user:alice" >>"$S/volumes/tls-scan_pgdata/db"; echo "report-1" >"$S/volumes/tls-scan_data/r1.html"
bs --mode webui backup "$D/safe"
rc_is 0 "backup to a directory outside the repository"
BK="$(ls "$D"/safe/*.tar.gz)"
check "archive verifies" bash -c "mkdir '$D/x' && tar -xzf '$BK' -C '$D/x' && cd '$D/x' && sha256sum -c --quiet SHA256SUMS"
echo "user:mallory" >>"$S/volumes/tls-scan_pgdata/db"; echo changed >"$S/volumes/tls-scan_data/r1.html"
cp "$BK" "$D/corrupt.tar.gz"; head -c 200 "$BK" >"$D/truncated.tar.gz"
bs --mode webui --yes restore "$D/truncated.tar.gz"
rc_is 1 "truncated archive refused"
has_out "illisible ou corrompue" "corruption reported"
check "database untouched by the refused restore" test "$(db)" = "user:admin user:alice user:mallory "
mkdir "$D/t"; tar -xzf "$BK" -C "$D/t"; echo tampered >>"$D/t/data.tar"; tar -czf "$D/tampered.tar.gz" -C "$D/t" db.dump data.tar SHA256SUMS MANIFEST.txt
bs --mode webui --yes restore "$D/tampered.tar.gz"
rc_is 1 "archive with a wrong checksum refused"
has_out "SHA-256 invalides" "checksum error reported"
check "data untouched by the refused restore" test "$(cat "$S/volumes/tls-scan_data/r1.html")" = changed
bs --mode webui restore
rc_is 2 "restore without a file: usage error"
bs --mode webui restore "$D/missing.tar.gz"
rc_is 1 "missing archive"
bs --stdin 'oui\n' --mode webui restore "$BK"
rc_is 3 "restore cancelled by a wrong confirmation"
check "data untouched when cancelled" test "$(db)" = "user:admin user:alice user:mallory "
bs --stdin 'o\nRESTAURER\n' --mode webui restore "$BK"
rc_is 0 "restore after the typed confirmation"
check "database restored" test "$(db)" = "user:admin user:alice "
check "data volume restored" test "$(cat "$S/volumes/tls-scan_data/r1.html")" = report-1
check "a safety backup was taken before the replacement" bash -c "[ \$(ls '$R'/backups/*.tar.gz | wc -l) -ge 1 ]"

# ---------------------------------------------------------------------------------------------------
new_sandbox destructive
bs --mode webui install
echo "user:alice" >>"$S/volumes/tls-scan_pgdata/db"
CERT_SUM="$(sha256sum "$R/data/certs/fullchain.pem" | cut -c1-64)"
bs --stdin 'n\nn\nn\n\nnon\n' --mode webui uninstall
rc_is 3 "uninstall cancelled by a wrong confirmation"
check "nothing removed (volumes, .env, certificates)" test -f "$S/up_tls-scan" -a "$(db)" = "user:admin user:alice " -a -f "$R/.env"
bs --mode webui uninstall
rc_is 3 "non-interactive uninstall without --yes is cancelled"
bs --stdin 'n\nn\nn\nDESINSTALLER TLS SCAN\n' --mode webui uninstall
rc_is 0 "uninstall keeping the data"
check "containers removed" test ! -e "$S/up_tls-scan"
check "data volumes kept" test "$(db)" = "user:admin user:alice "
check ".env and certificate kept" test -f "$R/.env" -a "$(sha256sum "$R/data/certs/fullchain.pem" | cut -c1-64)" = "$CERT_SUM"
calls_not "down -v" "no volume deletion without the data question"
calls_not "image rm -f" "images are never force-removed (they may be shared with another project)"
bs --mode webui install
check "a new install finds the kept data" test "$(db)" = "user:admin user:alice "
bs --mode webui reinstall
rc_is 3 "reinstall cancelled without confirmation"
check "data preserved when reinstall is cancelled" test "$(db)" = "user:admin user:alice "
bs --stdin 'o\nREINSTALLER\n' --mode webui reinstall
rc_is 0 "reinstall from scratch"
check "database is fresh (administrator only)" test "$(db)" = "user:admin "
check ".env and certificate preserved by the reinstall" test -f "$R/.env" -a "$(sha256sum "$R/data/certs/fullchain.pem" | cut -c1-64)" = "$CERT_SUM"
check "backup taken before the reinstall holds the old data" bash -c "mkdir '$D/rb' && tar -xzf \$(ls '$R'/backups/*.tar.gz | tail -n 1) -C '$D/rb' && grep -q alice '$D/rb/db.dump'"
echo "user:bob" >>"$S/volumes/tls-scan_pgdata/db"
bs --yes --delete-data uninstall
rc_is 0 "uninstall with --yes --delete-data"
check "data volumes deleted on explicit request" test ! -d "$S/volumes/tls-scan_pgdata"
check ".env removed only with the data request" test ! -e "$R/.env"
check "a backup exists before the deletion" bash -c "ls '$R'/backups/*.tar.gz >/dev/null"
check "Git repository untouched" test -f "$R/bootstrap_tls-scan-deployment.sh"

# ---------------------------------------------------------------------------------------------------
new_sandbox legacy
bs --mode webui install
bs install
rc_is 0 "legacy: install"
bs status
rc_is 0 "legacy: status"
bs backup "$D/b"
rc_is 0 "legacy: backup DIR"
bs reset-admin
rc_is 0 "legacy: reset-admin"
has_out "New password" "reset-admin output reaches the terminal"
bs frobnicate
rc_is 2 "unknown command"
bs --bogus status
rc_is 2 "unknown option"
bs --mode bogus status
rc_is 2 "unknown mode"
bs --help
rc_is 0 "--help"
has_out "--mode standalone|webui" "help documents the mode option"
bs logs nonsense
rc_is 1 "logs with an unknown service"

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
