#!/usr/bin/env bash
# Orion Manager: install, update, back up, restore, reinstall and remove Orion, in one of two
# independent deployment modes. (The former bootstrap_tls-scan-deployment.sh forwards here unchanged.)
#
#   ./bootstrap_orion-deployment.sh                         interactive menu (French)
#   ./bootstrap_orion-deployment.sh [--mode MODE] COMMAND [options]
#
# Modes
#   standalone   native command-line engine: Python 3.12+ + Nmap, in a dedicated virtualenv (.venv). No Docker.
#   webui        full application, ONLY through Docker Compose: API + PostgreSQL + worker + scheduler + HTTPS.
#                Nothing but Docker is needed on the host. This is the default mode of the commands below,
#                so existing automations keep working.
#
# Commands (webui unless --mode standalone)
#   install              first installation (idempotent; never overwrites .env, certificates or data)
#   update               fast-forward Git update when a new version exists, verified backup first, rebuild,
#                        migrations, health check. Data is preserved.   (also: redeploy)
#   status               state, version, branch, services (standalone: verifies the installation)  (also: verify)
#   backup [DIR]         PostgreSQL dump + persistent data in one archive with SHA-256 sums    (webui)
#   restore FILE         verify the archive, then replace the data after a typed confirmation    (webui)
#   reset-admin          reset the local administrator password (one-time or default)           (webui)
#   logs [SERVICE]       follow the technical logs                                                (webui)
#   rollback-secrets     restore legacy direct .env variables from the protected secret files     (webui)
#   migrate-config       rename the TLS_SCAN_* entries of .env to ORION_* (a copy of .env is kept) (webui)
#   migrate-orion        move a TLS Scan installation to the Orion project, database and volumes:
#                        verified backup, restore into new volumes, counts compared, automatic rollback;
#                        the TLS Scan volumes are kept untouched                                (webui)
#   rollback-orion       stop Orion and restart the kept TLS Scan installation (after migrate-orion) (webui)
#   reinstall            START FROM SCRATCH: removes the data (backup + typed confirmation)
#   uninstall            remove the mode's components; data is asked about separately
#
# Options
#   --mode standalone|webui   choose the mode (non-interactive use)
#   --yes, -y                 accept the questions AND the typed confirmations of a destructive operation
#                             (without it, a non-interactive destructive operation is cancelled)
#   --no-backup               skip the backup normally taken before update/restore/reinstall/uninstall
#   --no-git                  update: redeploy the local code without the Git checks / fast-forward
#   --delete-data             uninstall: also delete the data (requires --yes when non-interactive)
#   --default                 reset-admin: back to the deployment default password (change forced)
#
# Exit codes: 0 done, 1 failure or refusal (nothing destructive happened), 2 usage error,
#             3 cancelled (nothing was modified).
#
# The WebUI mode only ever touches the Docker project named by ORION_PROJECT (default "orion"). An installation made
# before the Orion rebranding keeps its project ("tls-scan"), database, role and volumes: they are pinned in .env
# (ORION_PROJECT, ORION_DB_NAME, ORION_DB_USER) and its TLS_SCAN_* settings keep working; migrate-orion moves it
# explicitly. The CrashTest, test and end-to-end projects are refused by name. .env is created if missing and its
# existing entries are never overwritten.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1
ENV_FILE="$ROOT/.env"
VENV="$ROOT/.venv"
BACKUP_DIR="${ORION_BACKUP_DIR:-${TLS_SCAN_BACKUP_DIR:-$ROOT/backups}}"

MODE=""
ASSUME_YES=0
NO_BACKUP=0
NO_GIT=0
DELETE_DATA=0
RESET_DEFAULT=0

# --- presentation -------------------------------------------------------------------------------

if [ -t 1 ]; then
    BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

# The technical log of the steps (never shown unless a step fails; removed on exit). It can hold command
# output, so it is private and short-lived.
LOG="$(umask 077; mktemp "${TMPDIR:-/tmp}/orion-manager.XXXXXX")"
trap 'rm -f "$LOG"' EXIT

say()  { printf '%s\n' "$*"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

banner() {
    say "${BOLD}╔══════════════════════════════════════════╗"
    say "║              Orion Manager               ║"
    say "╚══════════════════════════════════════════╝${RESET}"
    say ""
}

# ask "question" default(o|n) -> 0 when yes. An empty answer (or the end of the input) is the default.
ask() {
    local question="$1" default="$2" hint answer
    if [ "$default" = "o" ]; then hint="[O/n]"; else hint="[o/N]"; fi
    printf '%s %s ' "$question" "$hint"
    read -r answer || answer=""
    answer="$(printf '%s' "$answer" | tr '[:upper:]' '[:lower:]')"
    [ -n "$answer" ] || answer="$default"
    case "$answer" in o|oui|y|yes) return 0 ;; *) return 1 ;; esac
}

# ask_go "question": a "do you want to continue?" question whose default is no; --yes answers yes.
ask_go() { [ "$ASSUME_YES" = 1 ] && return 0; ask "$1" n; }

# confirm_typed "TEXT": the operator must type it exactly. --yes accepts it (explicit, non-interactive use).
confirm_typed() {
    local expected="$1" answer
    [ "$ASSUME_YES" = 1 ] && return 0
    say "Tapez exactement :"
    say ""
    say "    $expected"
    say ""
    printf '> '
    read -r answer || answer=""
    [ "$answer" = "$expected" ]
}

cancelled() {
    say "Annulé, rien n'a été modifié."
    [ -t 0 ] || say "(mode non interactif : ajoutez --yes pour confirmer une opération destructive)"
    exit 3
}

# Progress lines: "[3/8] Label ............ OK". Numbered while STEP_TOTAL is set, plain otherwise.
STEP_TOTAL=0
STEP_NO=0
lead() {
    local head dots
    if [ "$STEP_TOTAL" -gt 0 ]; then
        STEP_NO=$((STEP_NO + 1))
        head="[$STEP_NO/$STEP_TOTAL] $1 "
    else
        head="$1 "
    fi
    dots="$(printf '%*s' $((52 - ${#head})) '' | tr ' ' '.')"
    printf '%s%s ' "$head" "$dots"
}
# Runs a command; its output goes to the log, and its tail is shown when it fails.
step() {
    local label="$1"; shift
    lead "$label"
    if "$@" >"$LOG" 2>&1; then
        say "${GREEN}OK${RESET}"
        return 0
    fi
    say "${RED}ÉCHEC${RESET}"
    tail -n 25 "$LOG" | sed 's/^/    /'
    return 1
}
step_skipped() { lead "$1"; say "${YELLOW}IGNORÉ${RESET}"; }
begin_steps() { STEP_TOTAL="$1"; STEP_NO=0; }

# --- environment (.env) ---------------------------------------------------------------------------

# env_get KEY: the value Compose will see: the shell's own variable first, else the one in .env.
env_get() {
    if [ -n "${!1-}" ]; then printf '%s' "${!1}"; return 0; fi
    [ -f "$ENV_FILE" ] || return 0
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

# env_set KEY VALUE: replace the KEY= line of .env, or append it. The value never goes to the log.
env_set() {
    local key="$1" value="$2" tmp
    tmp="$(mktemp "$ROOT/.env.XXXXXX")"
    if grep -q "^$key=" "$ENV_FILE"; then
        awk -v k="$key" -v v="$value" 'index($0, k "=") == 1 { print k "=" v; next } { print }' \
            "$ENV_FILE" >"$tmp"
    else
        cat "$ENV_FILE" >"$tmp"
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
    fi
    chmod 600 "$tmp"
    mv "$tmp" "$ENV_FILE"
}

random_hex() {
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"; else
        head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; fi
}

# cfg_get NAME: ORION_NAME, else the pre-rebranding TLS_SCAN_NAME, the way compose.yaml resolves them.
cfg_get() {
    local v; v="$(env_get "ORION_$1")"
    [ -n "$v" ] || v="$(env_get "TLS_SCAN_$1")"
    printf '%s' "$v"
}

NEW_PROJECT="orion"
LEGACY_PROJECT="tls-scan"
LEGACY_DB="tls_scan"
PROJECT="$(cfg_get PROJECT)"
PROJECT="${PROJECT:-$NEW_PROJECT}"

# compose.override.yaml (site-specific, not versioned) is read when present, like plain `docker compose`.
dc() {
    local files=(-f "$ROOT/compose.yaml")
    [ -f "$ROOT/compose.override.yaml" ] && files+=(-f "$ROOT/compose.override.yaml")
    docker compose -p "$PROJECT" --project-directory "$ROOT" "${files[@]}" "$@"
}

https_port() { local p; p="$(cfg_get HTTPS_PORT)"; printf '%s' "${p:-8443}"; }
http_port()  { local p; p="$(cfg_get HTTP_PORT)"; printf '%s' "${p:-8080}"; }
cert_dir()   { local d; d="$(cfg_get CERT_DIR)"; printf '%s' "${d:-$ROOT/data/certs}"; }
image_tag()  { local v; v="$(cfg_get VERSION)"; printf '%s' "${v:-local}"; }
db_name()    { local v; v="$(cfg_get DB_NAME)"; printf '%s' "${v:-orion}"; }
db_user()    { local v; v="$(cfg_get DB_USER)"; printf '%s' "${v:-orion}"; }

public_url() {
    local u
    u="$(cfg_get PUBLIC_BASE_URL)"
    printf '%s' "${u:-https://localhost:$(https_port)}"
}

# --- Git (shared by both modes) -------------------------------------------------------------------

git_branch()  { git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "(inconnue)"; }
git_version() { git -C "$ROOT" log -1 --format='%h %s' 2>/dev/null || echo "(pas un dépôt Git)"; }
git_upstream() { git -C "$ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null; }

remote_version() {
    local up sha
    up="$(git_upstream)" || { printf '(aucune branche distante suivie)'; return; }
    sha="$(timeout 10 git -C "$ROOT" ls-remote --heads origin "${up#origin/}" 2>/dev/null | cut -c1-7)"
    if [ -n "$sha" ]; then printf '%s' "$sha"; else printf '(inaccessible)'; fi
}

# Update checks. The branch is never changed and nothing is reset, cleaned or merged by force.
git_checks() {
    git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
        || { echo "Ce dossier n'est pas un dépôt Git : la mise à jour du code est impossible (--no-git pour redéployer le code local)."; return 1; }
    local branch dirty
    branch="$(git_branch)"
    [ "$branch" != "HEAD" ] || { echo "HEAD est détaché : mise à jour refusée (placez-vous sur une branche vous-même)."; return 1; }
    dirty="$(git -C "$ROOT" status --porcelain)"
    if [ -n "$dirty" ]; then
        echo "Des modifications locales existent, mise à jour refusée (rien n'est modifié) :"
        printf '%s\n' "$dirty" | sed 's/^/    /'
        echo "Validez-les ou remisez-les, ou utilisez --no-git pour redéployer le code local tel quel."
        return 1
    fi
    git_upstream >/dev/null || { echo "La branche « $branch » ne suit aucune branche distante : rien à récupérer."; return 1; }
    git -C "$ROOT" fetch origin || { echo "git fetch origin a échoué (réseau ?)."; return 1; }
}

# git_relation -> prints new | same | ahead | diverged (HEAD against its upstream)
git_relation() {
    local head up
    head="$(git -C "$ROOT" rev-parse HEAD)"
    up="$(git -C "$ROOT" rev-parse '@{u}')"
    if [ "$head" = "$up" ]; then echo same
    elif git -C "$ROOT" merge-base --is-ancestor "$up" "$head"; then echo ahead
    elif git -C "$ROOT" merge-base --is-ancestor "$head" "$up"; then echo new
    else echo diverged; fi
}

# Shared Git phase of an update. Prints the situation and sets NEW_VERSION=oui|non.
NEW_VERSION="non"
update_git_phase() {
    NEW_VERSION="non"
    if [ "$NO_GIT" = 1 ]; then
        step_skipped "Vérification Git (--no-git)"
        return 0
    fi
    step "Vérification Git" git_checks || return 1
    local rel
    rel="$(git_relation)"
    case "$rel" in
        new)      NEW_VERSION="oui" ;;
        same)     say ""; say "Aucune nouvelle version : $(git_upstream) est identique à la version installée."
                  ask_go "Redéployer la version actuelle ?" || cancelled ;;
        ahead)    say ""; say "Votre branche est en avance sur $(git_upstream) : rien à récupérer."
                  ask_go "Redéployer la version locale ?" || cancelled ;;
        diverged) die "Votre branche a divergé de $(git_upstream) : résolvez-le vous-même (rien n'est modifié)." ;;
    esac
}

git_fast_forward() { git -C "$ROOT" merge --ff-only '@{u}'; }

# --- safety: project and mode isolation ------------------------------------------------------------

check_project_name() {
    case "$PROJECT" in
        *crashtest*|*e2e*|tlsscan-test*|tls-scan-test*|orion-test*)
            die "Refusé : « $PROJECT » est un projet de test (CrashTest / end-to-end), pas une installation." ;;
    esac
    [[ "$PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "Nom de projet invalide : $PROJECT"
    case "$(image_tag)" in
        *crashtest*) die "Refusé : l'étiquette d'image « $(image_tag) » appartient au CrashTest." ;;
    esac
    adopt_legacy_install || die "Impossible d'enregistrer l'installation TLS Scan existante dans .env."
    if [ "$PROJECT" = "$LEGACY_PROJECT" ]; then
        say "Installation TLS Scan conservée (projet « $PROJECT », base « $(db_name) ») : migrate-orion la déplace vers Orion."
    elif [ "$PROJECT" != "$NEW_PROJECT" ]; then
        warn "Projet Docker alternatif : $PROJECT (ORION_PROJECT)."
    fi
}

# An installation made before the Orion rebranding keeps its names: without ORION_DB_NAME in .env, a .env holding
# TLS_SCAN_* entries, or volumes of the project, means its PostgreSQL database and role are still "tls_scan". They
# are pinned (appended to .env, nothing else changes) so that Orion never starts on an empty database next to it.
legacy_install() {
    [ -z "$(env_get ORION_DB_NAME)" ] || return 1
    if [ -f "$ENV_FILE" ] && grep -q '^TLS_SCAN_' "$ENV_FILE"; then return 0; fi
    project_has_volumes "$PROJECT"
}

project_has_volumes() {
    command -v docker >/dev/null 2>&1 || return 1
    [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null)" ]
}

adopt_legacy_install() {
    # No project configured (e.g. .env lost) but the volumes of a TLS Scan installation exist: that is the installation.
    if [ -z "$(cfg_get PROJECT)" ] && [ "$PROJECT" = "$NEW_PROJECT" ] && ! project_has_volumes "$NEW_PROJECT" \
        && project_has_volumes "$LEGACY_PROJECT"; then
        PROJECT="$LEGACY_PROJECT"
    fi
    legacy_install || return 0
    if [ ! -f "$ENV_FILE" ]; then
        [ -f "$ROOT/.env.example" ] || { echo ".env.example est introuvable."; return 1; }
        ( umask 077; grep -v -E '^ORION_(PROJECT|DB_NAME|DB_USER)=' "$ROOT/.env.example" >"$ENV_FILE" ) || return 1
    fi
    [ -n "$(env_get ORION_PROJECT)" ] || env_set ORION_PROJECT "$PROJECT"
    env_set ORION_DB_NAME "$LEGACY_DB"
    [ -n "$(env_get ORION_DB_USER)" ] || env_set ORION_DB_USER "$LEGACY_DB"
    warn "Installation antérieure à Orion détectée : projet « $PROJECT » et base « $LEGACY_DB » conservés (.env complété)."
}

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

# --- WebUI mode: detection ------------------------------------------------------------------------

project_containers() { docker ps -a -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null; }
project_volumes()    { docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" 2>/dev/null; }

web_installed() {
    command -v docker >/dev/null 2>&1 || return 1
    [ -n "$(project_containers)" ] || [ -n "$(project_volumes)" ]
}

web_check_prerequisites() {
    command -v docker >/dev/null 2>&1 || { echo "Docker est introuvable."; return 1; }
    docker info >/dev/null 2>&1 || { echo "Le démon Docker ne répond pas (droits ou service arrêté)."; return 1; }
    docker compose version >/dev/null 2>&1 || { echo "Le plugin Docker Compose est introuvable."; return 1; }
    command -v openssl >/dev/null 2>&1 || { echo "openssl est introuvable (certificat HTTPS et secrets)."; return 1; }
    [ -f "$ROOT/compose.yaml" ] || { echo "compose.yaml est introuvable à côté de ce script."; return 1; }
}

web_check_ports() {
    web_installed && return 0   # our own containers hold the ports
    local p
    for p in "$(https_port)" "$(http_port)"; do
        if port_busy "$p"; then echo "Le port $p est déjà utilisé : modifiez ORION_HTTPS_PORT / ORION_HTTP_PORT dans .env."; return 1; fi
    done
}

web_show_status() {
    say "Installation        : projet Docker « $PROJECT »"
    say "Version locale      : $(git_version)"
    say "Branche             : $(git_branch)"
    say "Version distante    : $(remote_version)"
    say "Services            :"
    local services
    services="$(dc ps -a --format '{{.Service}}|{{.Status}}' 2>/dev/null)"
    if [ -n "$services" ]; then
        printf '%s\n' "$services" | while IFS='|' read -r name state; do
            printf '    %-10s %s\n' "$name" "$state"
        done
    else
        say "    (aucun conteneur)"
    fi
    say "URL                 : $(public_url)"
    say ""
}

# --- WebUI mode: building blocks --------------------------------------------------------------------

secret_dir() {
    local dir; dir="$(cfg_get SECRET_DIR)"; dir="${dir:-./data/secrets}"
    case "$dir" in /*) printf '%s' "$dir" ;; *) printf '%s/%s' "$ROOT" "$dir" ;; esac
}

secret_gid() { local gid; gid="$(cfg_get SECRET_GID)"; printf '%s' "${gid:-$(id -g)}"; }

secret_file_path() { printf '%s/%s' "$(secret_dir)" "$1"; }

# Create a host file readable only by the deploying user's group. Compose grants that numeric group
# to only the services that need the file; Docker Compose file secrets preserve host bind-mount mode.
protect_secret_file() {
    local file="$1" gid; gid="$(secret_gid)"
    chgrp "$gid" "$file" 2>/dev/null || { echo "Impossible d'attribuer le groupe $gid au fichier secret (vérifiez ORION_SECRET_GID)."; return 1; }
    chmod 0440 "$file" || return 1
}

write_secret_value() {
    local file="$1" value="$2" tmp
    mkdir -p "$(dirname "$file")" || return 1
    tmp="$(mktemp "$(dirname "$file")/.secret.XXXXXX")" || return 1
    ( umask 077; printf '%s' "$value" >"$tmp" ) || { rm -f "$tmp"; return 1; }
    chmod 0600 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$file" || return 1
    protect_secret_file "$file"
}

copy_secret_file() {
    local source="$1" dest="$2" tmp
    [ -f "$source" ] && [ -r "$source" ] || { echo "Un fichier secret configuré est inaccessible; copiez-le dans $(secret_dir) et relancez."; return 1; }
    mkdir -p "$(dirname "$dest")" || return 1
    tmp="$(mktemp "$(dirname "$dest")/.secret.XXXXXX")" || return 1
    ( umask 077; cat -- "$source" >"$tmp" ) || { rm -f "$tmp"; return 1; }
    chmod 0600 "$tmp" || { rm -f "$tmp"; return 1; }
    mv -f "$tmp" "$dest" || return 1
    protect_secret_file "$dest"
}

resolve_host_secret_path() {
    local configured="$1" name="$2" dir
    [ -n "$configured" ] || return 1
    dir="$(secret_dir)"
    case "$configured" in
        /run/secrets/*) printf '%s/%s' "$dir" "${configured##*/}" ;;
        /*) printf '%s' "$configured" ;;
        *) printf '%s/%s' "$ROOT" "$configured" ;;
    esac
}

# Direct .env credentials are copied only after an explicit confirmation, then their .env values are
# blanked. Existing files are never silently overwritten or rotated.
migrate_env_secrets() {
    # Each credential may be written with the Orion prefix or the pre-rebranding TLS_SCAN_ one; both are migrated.
    local direct_suffixes=(SESSION_SECRET LOCAL_ADMIN_PASSWORD OIDC_CLIENT_SECRET GOOGLE_CLIENT_SECRET DIRECTORY_CLIENT_SECRET \
        LDAP_BIND_PASSWORD GREENBONE_PASSWORD SMTP_PASSWORD GRAPH_CLIENT_SECRET SNMP_V3_AUTH_KEY SNMP_V3_PRIV_KEY)
    local direct_files=(session_secret local_admin_password oidc_client_secret google_client_secret directory_client_secret \
        ldap_bind_password greenbone_password smtp_password graph_client_secret snmp_v3_auth_key snmp_v3_priv_key)
    local path_suffixes=(SESSION_SECRET_FILE LOCAL_ADMIN_PASSWORD_FILE OIDC_CLIENT_SECRET_FILE GOOGLE_CLIENT_SECRET_FILE \
        DIRECTORY_CLIENT_SECRET_FILE LDAP_BIND_PASSWORD_FILE GREENBONE_PASSWORD_FILE SMTP_PASSWORD_FILE GRAPH_CLIENT_SECRET_FILE \
        SNMP_V3_AUTH_KEY_FILE SNMP_V3_PRIV_KEY_FILE GREENBONE_CA_FILE GREENBONE_CLIENT_CERT_FILE GREENBONE_CLIENT_KEY_FILE \
        GOOGLE_DIRECTORY_KEY_FILE)
    local path_files=(session_secret local_admin_password oidc_client_secret google_client_secret directory_client_secret \
        ldap_bind_password greenbone_password smtp_password graph_client_secret snmp_v3_auth_key snmp_v3_priv_key \
        greenbone_ca.pem greenbone_client.crt greenbone_client.key google_directory_key.json)
    local direct=(POSTGRES_PASSWORD) names=(postgres_password) path_keys=() path_names=() prefix j
    for prefix in ORION_ TLS_SCAN_; do
        for j in "${!direct_suffixes[@]}"; do direct+=("$prefix${direct_suffixes[$j]}"); names+=("${direct_files[$j]}"); done
        for j in "${!path_suffixes[@]}"; do path_keys+=("$prefix${path_suffixes[$j]}"); path_names+=("${path_files[$j]}"); done
    done
    local i value file source pending=0
    for i in "${!direct[@]}"; do
        value="$(env_get "${direct[$i]}")"; file="$(secret_file_path "${names[$i]}")"
        if [ -n "$value" ]; then
            pending=1
            if [ -s "$file" ] && ! printf '%s' "$value" | cmp -s - "$file"; then
                echo "La valeur de ${direct[$i]} diffère déjà du fichier protégé ${names[$i]} ; aucune valeur n'a été remplacée."
                return 1
            fi
        fi
    done
    for i in "${!path_keys[@]}"; do
        value="$(env_get "${path_keys[$i]}")"
        [ -n "$value" ] || continue
        source="$(resolve_host_secret_path "$value" "${path_names[$i]}")"
        file="$(secret_file_path "${path_names[$i]}")"
        if [ "$value" = "/run/secrets/${path_names[$i]}" ] && [ ! -f "$source" ]; then
            echo "Le fichier protégé configuré pour ${path_keys[$i]} est absent (${path_names[$i]}); restaurez-le avant de continuer."
            return 1
        fi
        if [ "$value" != "/run/secrets/${path_names[$i]}" ] || { [ "$source" != "$file" ] && [ -f "$source" ]; }; then pending=1; fi
    done
    [ "$pending" = 1 ] || return 0
    echo "Migration explicite des secrets .env/fichiers vers $(secret_dir) : les identifiants restent inchangés; .env sera expurgé après copie."
    ask_go "Copier et protéger les fichiers secrets maintenant ?" || { echo "Migration refusée : aucune modification des identifiants n'a été faite."; return 1; }
    mkdir -p "$(secret_dir)" || return 1
    chmod 0710 "$(secret_dir)" || return 1
    local gid; gid="$(secret_gid)"
    chgrp "$gid" "$(secret_dir)" 2>/dev/null || { echo "Impossible d'attribuer le groupe $gid au répertoire secret."; return 1; }

    for i in "${!direct[@]}"; do
        value="$(env_get "${direct[$i]}")"; file="$(secret_file_path "${names[$i]}")"
        if [ -n "$value" ]; then
            if [ ! -s "$file" ]; then write_secret_value "$file" "$value" || return 1; fi
            env_set "${direct[$i]}" ""
            unset "${direct[$i]}" || true
        fi
    done
    for i in "${!path_keys[@]}"; do
        value="$(env_get "${path_keys[$i]}")"; [ -n "$value" ] || continue
        source="$(resolve_host_secret_path "$value" "${path_names[$i]}")"
        file="$(secret_file_path "${path_names[$i]}")"
        if [ "$source" != "$file" ]; then
            [ -f "$source" ] || { echo "Le fichier associé à ${path_keys[$i]} est absent; placez-le sous $(secret_dir) et relancez."; return 1; }
            [ -s "$file" ] || copy_secret_file "$source" "$file" || return 1
        fi
        env_set "${path_keys[$i]}" "/run/secrets/${path_names[$i]}"
        unset "${path_keys[$i]}" || true
    done
    return 0
}

prepare_secret_files() {
    local dir gid file direct_value
    dir="$(secret_dir)"; gid="$(secret_gid)"
    mkdir -p "$dir" || return 1
    chmod 0710 "$dir" || return 1
    chgrp "$gid" "$dir" 2>/dev/null || { echo "Impossible d'attribuer le groupe $gid au répertoire secret."; return 1; }

    # A fresh install gets new credentials only if no password volume already exists.
    file="$dir/postgres_password"
    if [ ! -s "$file" ]; then
        direct_value="$(env_get POSTGRES_PASSWORD)"
        if [ -n "$direct_value" ]; then write_secret_value "$file" "$direct_value" || return 1
        elif docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | grep -q 'pgdata$'; then
            echo "Un volume PostgreSQL existe mais aucun secret postgres_password n'est disponible. Restaurez le mot de passe existant; aucune rotation ne sera faite."
            return 1
        else write_secret_value "$file" "$(random_hex 24)" || return 1; echo "Secret PostgreSQL créé dans le répertoire protégé"; fi
    fi
    file="$dir/session_secret"
    if [ ! -s "$file" ]; then
        direct_value="$(cfg_get SESSION_SECRET)"
        if [ -n "$direct_value" ]; then write_secret_value "$file" "$direct_value" || return 1
        else write_secret_value "$file" "$(random_hex 32)" || return 1; echo "Secret de session créé dans le répertoire protégé"; fi
    fi
    protect_secret_file "$dir/postgres_password" || return 1
    protect_secret_file "$dir/session_secret" || return 1
    file="$dir/database_password"
    if [ ! -s "$file" ]; then copy_secret_file "$dir/postgres_password" "$file" || return 1
    elif ! cmp -s "$dir/postgres_password" "$file"; then
        echo "Les copies de mot de passe PostgreSQL ne correspondent pas. Vérifiez les deux fichiers avant tout redémarrage."
        return 1
    fi

    file="$dir/greenbone_credential_key"
    if [ ! -e "$file" ]; then
        write_secret_value "$file" "$(random_hex 32)" || return 1
    fi
    protect_secret_file "$file" || return 1

    local name
    local names=(local_admin_password oidc_client_secret google_client_secret directory_client_secret ldap_bind_password \
        greenbone_password smtp_password graph_client_secret snmp_v3_auth_key snmp_v3_priv_key \
        greenbone_ca.pem greenbone_client.crt greenbone_client.key google_directory_key.json)
    for name in "${names[@]}"; do
        file="$dir/$name"
        [ -e "$file" ] || ( umask 077; : >"$file" ) || return 1
        protect_secret_file "$file" || return 1
    done
}

# Rebuild the legacy Compose env-file values into protected files; this reverses the migration without
# inventing or rotating credentials, for rollback to a version that still uses direct variables.
rollback_env_secrets() {
    local keys=(POSTGRES_PASSWORD TLS_SCAN_SESSION_SECRET TLS_SCAN_LOCAL_ADMIN_PASSWORD TLS_SCAN_OIDC_CLIENT_SECRET \
        TLS_SCAN_GOOGLE_CLIENT_SECRET TLS_SCAN_DIRECTORY_CLIENT_SECRET TLS_SCAN_LDAP_BIND_PASSWORD \
        TLS_SCAN_GREENBONE_PASSWORD TLS_SCAN_SMTP_PASSWORD TLS_SCAN_GRAPH_CLIENT_SECRET \
        TLS_SCAN_SNMP_V3_AUTH_KEY TLS_SCAN_SNMP_V3_PRIV_KEY)
    local names=(postgres_password session_secret local_admin_password oidc_client_secret google_client_secret \
        directory_client_secret ldap_bind_password greenbone_password smtp_password graph_client_secret \
        snmp_v3_auth_key snmp_v3_priv_key)
    local i file value
    [ -f "$ENV_FILE" ] || { echo ".env introuvable."; return 1; }
    echo "Cette commande réinscrit explicitement les secrets dans .env pour un ancien Compose. Protégez ensuite .env (0600)."
    ask_go "Restaurer les variables secrètes directes dans .env ?" || return 1
    for i in "${!keys[@]}"; do
        file="$(secret_file_path "${names[$i]}")"
        [ -f "$file" ] || { echo "Fichier protégé absent : ${names[$i]}"; return 1; }
        value="$(cat -- "$file")"
        env_set "${keys[$i]}" "$value"
    done
    chmod 600 "$ENV_FILE"
}

# Refuses to start with a stale/unredacted runtime configuration or a missing secret file. Values in
# .env are always host-only interpolation inputs; only explicit non-secret compose environment entries reach services.
create_env() {
    if [ ! -f "$ENV_FILE" ]; then
        [ -f "$ROOT/.env.example" ] || { echo ".env.example est introuvable."; return 1; }
        ( umask 077; cp "$ROOT/.env.example" "$ENV_FILE" )
        echo ".env créé à partir de .env.example"
    fi
    chmod 600 "$ENV_FILE"
    [ -n "$(cfg_get SECRET_DIR)" ] || env_set ORION_SECRET_DIR "./data/secrets"
    [ -n "$(cfg_get SECRET_GID)" ] || env_set ORION_SECRET_GID "$(id -g)"
    migrate_env_secrets || return 1
    prepare_secret_files || return 1
    local secret_key prefix suffix
    [ -z "$(env_get POSTGRES_PASSWORD)" ] || { echo "La variable POSTGRES_PASSWORD doit être migrée hors de .env; aucune valeur directe ne sera transmise."; return 1; }
    for prefix in ORION_ TLS_SCAN_; do for suffix in SESSION_SECRET LOCAL_ADMIN_PASSWORD OIDC_CLIENT_SECRET GOOGLE_CLIENT_SECRET \
        DIRECTORY_CLIENT_SECRET LDAP_BIND_PASSWORD GREENBONE_PASSWORD SMTP_PASSWORD GRAPH_CLIENT_SECRET SNMP_V3_AUTH_KEY SNMP_V3_PRIV_KEY; do
        secret_key="$prefix$suffix"
        [ -z "$(env_get "$secret_key")" ] || { echo "La variable $secret_key doit être migrée hors de .env; aucune valeur directe ne sera transmise."; return 1; }
    done; done
    return 0
}

# HTTPS certificate: existing ones are kept. A self-signed one is created only when BOTH files are absent.
CERT_WARNING=""
check_certificate() {
    local dir cert key; dir="$(cert_dir)"; cert="$dir/fullchain.pem"; key="$dir/privkey.pem"
    CERT_WARNING=""
    mkdir -p "$dir" || return 1
    if [ ! -f "$cert" ] && [ ! -f "$key" ]; then
        local host; host="$(public_url | sed -E 's#^https?://##; s#[:/].*##')"; host="${host:-localhost}"
        openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout "$key" -out "$cert" \
            -subj "/CN=$host" -addext "subjectAltName=DNS:$host,DNS:localhost" 2>/dev/null \
            || { echo "La génération du certificat a échoué."; return 1; }
        chmod 600 "$key"
        CERT_WARNING="Certificat autosigné généré dans $dir : remplacez fullchain.pem / privkey.pem par les vôtres en production."
        echo "$CERT_WARNING"
        return 0
    fi
    [ -f "$cert" ] || { echo "$cert est absent alors que la clé existe : rien n'est remplacé, restaurez-le."; return 1; }
    [ -f "$key" ]  || { echo "$key est absente alors que le certificat existe : rien n'est remplacé, restaurez-la."; return 1; }
    local a b
    a="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null)"
    b="$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl sha256 2>/dev/null)"
    [ -n "$a" ] && [ "$a" = "$b" ] || { echo "Le certificat et la clé privée ne correspondent pas (ou sont illisibles)."; return 1; }
    local mode; mode="$(stat -c '%a' "$key" 2>/dev/null || echo 600)"
    case "$mode" in ?00) ;; *) chmod 600 "$key"; echo "Permissions de privkey.pem ramenées à 600 (étaient $mode)." ;; esac
    if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then
        CERT_WARNING="Le certificat HTTPS de $dir est EXPIRÉ : remplacez-le."
        echo "$CERT_WARNING"
    elif ! openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1; then
        CERT_WARNING="Le certificat HTTPS de $dir expire dans moins de 30 jours."
        echo "$CERT_WARNING"
    fi
    return 0
}

check_compose() { dc config -q; }
build_images()  { dc build; }
start_stack()   { dc up -d --wait --wait-timeout 300; }

# The API container runs `alembic upgrade head` when it starts; this verifies the result.
check_migrations() {
    local out
    out="$(dc exec -T api sh -c 'cd backend && alembic current' 2>&1)" || { echo "$out"; return 1; }
    printf '%s\n' "$out"
    printf '%s' "$out" | grep -q '(head)' || { echo "Le schéma PostgreSQL n'est pas à la dernière migration."; return 1; }
}

api_health() {
    local tries="${ORION_HEALTH_TRIES:-${TLS_SCAN_HEALTH_TRIES:-40}}" i
    for ((i = 0; i < tries; i++)); do
        if dc exec -T api curl -fs http://localhost:8000/api/health/ready >/dev/null 2>&1; then break; fi
        [ "$i" -lt $((tries - 1)) ] || { echo "L'API ne répond pas sur /api/health/ready."; return 1; }
        sleep 3
    done
    local running svc
    running="$(dc ps --status running --format '{{.Service}}' 2>/dev/null)"
    for svc in postgres api worker scheduler webui; do
        printf '%s\n' "$running" | grep -qx "$svc" || { echo "Le service « $svc » n'est pas démarré."; return 1; }
    done
}

# A fresh database holds the local administrator only.
check_fresh_bootstrap() {
    local q
    q="$(dc exec -T postgres psql -U "$(db_user)" -d "$(db_name)" -Atc "select count(*) from users")" || return 1
    [ "$q" = "1" ] || { echo "Base inattendue : $q utilisateur(s) au lieu de 1 (l'administrateur local seul)."; return 1; }
}

# --- WebUI mode: backup / restore ----------------------------------------------------------------------

data_volume() { printf '%s_data' "$PROJECT"; }

# make_backup [DIR]: one archive orion-backup-<UTC>.tar.gz holding db.dump (pg_dump -Fc), data.tar (the
# persistent data volume: reports, logs), SHA256SUMS and MANIFEST.txt. It is verified before it is kept.
# Prints "Sauvegarde écrite : <file>". .env and the HTTPS certificate are NOT in it (keep them in your own
# secret backup).
make_backup() {
    local rc
    BACKUP_WORK=""
    _make_backup "$@"; rc=$?
    [ -z "$BACKUP_WORK" ] || rm -rf "$BACKUP_WORK"
    return "$rc"
}
BACKUP_WORK=""
BACKUP_ARCHIVE=""
_make_backup() {
    local dir="${1:-$BACKUP_DIR}" stamp archive work
    docker volume inspect "$(data_volume)" >/dev/null 2>&1 || { echo "Le volume de données $(data_volume) n'existe pas : rien à sauvegarder."; return 1; }
    dc up -d --wait postgres >/dev/null 2>&1 || { echo "PostgreSQL ne démarre pas."; return 1; }
    ( umask 077; mkdir -p "$dir" ) || { echo "Impossible de créer $dir."; return 1; }
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    archive="$dir/orion-backup-$stamp.tar.gz"
    work="$(umask 077; mktemp -d "$dir/.orion-backup.XXXXXX")" || return 1
    BACKUP_WORK="$work"
    dc exec -T postgres pg_dump -U "$(db_user)" -Fc "$(db_name)" >"$work/db.dump" || { echo "pg_dump a échoué."; return 1; }
    [ -s "$work/db.dump" ] || { echo "Le dump PostgreSQL est vide."; return 1; }
    docker run --rm --entrypoint tar -v "$(data_volume)":/data:ro "$(postgres_image)" -C /data -cf - . >"$work/data.tar" \
        || { echo "La sauvegarde du volume de données a échoué."; return 1; }
    ( cd "$work" && sha256sum db.dump data.tar >SHA256SUMS )
    cat >"$work/MANIFEST.txt" <<MANIFEST
Orion backup
created_utc: $stamp
git: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
project: $PROJECT
database: $(db_name)
format: tar.gz archive; db.dump = pg_dump -Fc; data.tar = raw archive of the data volume (reports, logs)
contents: db.dump, data.tar, SHA256SUMS, MANIFEST.txt
excluded: .env and the HTTPS certificate (keep them in your own secret backup)
MANIFEST
    tar -czf "$work/archive.tmp" -C "$work" db.dump data.tar SHA256SUMS MANIFEST.txt || return 1
    verify_archive "$work/archive.tmp" || { echo "L'archive écrite ne passe pas la vérification d'intégrité."; return 1; }
    mv "$work/archive.tmp" "$archive"
    chmod 600 "$archive"
    BACKUP_ARCHIVE="$archive"
    echo "Sauvegarde écrite : $archive"
}

postgres_image() { dc config --images 2>/dev/null | grep '^postgres' | head -n 1 | grep . || echo "postgres:16-alpine"; }

# verify_archive FILE [OUTDIR]: the archive is readable, holds the expected files and the sums match.
# Without OUTDIR it is extracted to a temporary directory. Legacy archives (db.dump + files.tar, no sums)
# are readable but reported as unverified.
verify_archive() {
    local file="$1" out="${2:-}" own=0
    [ -f "$file" ] || { echo "Archive introuvable : $file"; return 1; }
    if [ -z "$out" ]; then out="$(mktemp -d)"; own=1; fi
    if ! tar -xf "$file" -C "$out" 2>/dev/null; then
        echo "Archive illisible ou corrompue : $file"; [ "$own" = 1 ] && rm -rf "$out"; return 1
    fi
    local rc=0
    if [ -f "$out/SHA256SUMS" ]; then
        ( cd "$out" && sha256sum -c --quiet SHA256SUMS ) >/dev/null 2>&1 || { echo "Sommes SHA-256 invalides : l'archive est corrompue ou modifiée."; rc=1; }
        [ -s "$out/db.dump" ] || { echo "db.dump manque ou est vide."; rc=1; }
    elif [ -f "$out/db.dump" ]; then
        echo "Ancienne archive sans sommes SHA-256 : l'intégrité ne peut pas être prouvée."
        ARCHIVE_UNVERIFIED=1
        [ -s "$out/db.dump" ] || rc=1
    else
        echo "Archive inattendue : db.dump est absent."; rc=1
    fi
    [ "$own" = 1 ] && rm -rf "$out"
    return "$rc"
}
ARCHIVE_UNVERIFIED=0

# offer_backup "operation": 0 when done or declined, 1 when it failed.
offer_backup() {
    if [ "$NO_BACKUP" = 1 ]; then
        lead "Sauvegarde"; say "${YELLOW}IGNORÉE${RESET}"
        warn "Sauvegarde ignorée (--no-backup)."
        return 0
    fi
    if ask "Créer une sauvegarde avant $1 ?" o; then
        lead "Sauvegarde"
        if make_backup >"$LOG" 2>&1; then
            say "${GREEN}OK${RESET}"
            grep '^Sauvegarde écrite' "$LOG" | sed 's/^/    /'
            warn "    Rappel : .env et le certificat HTTPS ne sont pas dans la sauvegarde ; conservez-les ailleurs."
            return 0
        fi
        say "${RED}ÉCHEC${RESET}"
        tail -n 15 "$LOG" | sed 's/^/    /'
        return 1
    fi
    lead "Sauvegarde"; say "${YELLOW}IGNORÉE${RESET}"
    warn "Sauvegarde ignorée à la demande de l'utilisateur."
    return 0
}

web_final_summary() {
    say ""
    say "${GREEN}Terminé.${RESET}"
    say "URL : $(public_url)"
}

admin_info() {
    say "Compte initial : admin / SecretPassword (à changer à la première connexion)."
    say "Aucune donnée de démonstration : configurez SSO, SMTP et utilisateurs dans Administration."
}

# --- WebUI mode: operations ---------------------------------------------------------------------------------

web_do_install() {
    banner
    say "Installation d'Orion — WebUI (projet Docker « $PROJECT »)."
    web_installed && say "Une installation existe : .env, certificats et données sont conservés."
    say ""
    local new_env="non"
    [ -f "$ENV_FILE" ] || new_env="oui"
    begin_steps 9
    step "Vérification des prérequis Docker" web_check_prerequisites || return 1
    step "Projet Docker et ports" web_check_ports || return 1
    step "Fichier .env et secrets" create_env || return 1
    step "Certificat HTTPS" check_certificate || return 1
    [ -z "$CERT_WARNING" ] || warn "    $CERT_WARNING"
    step "Validation Docker Compose" check_compose || return 1
    step "Construction des images" build_images || return 1
    step "Démarrage des conteneurs" start_stack || return 1
    step "Migrations PostgreSQL" check_migrations || return 1
    step "Santé des services" api_health || return 1
    web_final_summary
    say ""
    admin_info
    [ "$new_env" = "oui" ] && warn "Conservez .env (secrets) et data/certs dans votre propre sauvegarde sécurisée."
    return 0
}

web_do_update() {
    banner
    say "MISE À JOUR / REDÉPLOIEMENT — les données sont conservées."
    say ""
    begin_steps 11
    step "Vérification des prérequis Docker" web_check_prerequisites || return 1
    [ -f "$ENV_FILE" ] || die "Aucun .env : lancez d'abord l'installation."
    update_git_phase || return 1
    say ""
    offer_backup "la mise à jour" || die "La sauvegarde a échoué : mise à jour interrompue, rien n'a été modifié."
    if [ "$NEW_VERSION" = "oui" ]; then
        step "Mise à jour du code (fast-forward)" git_fast_forward || return 1
    else
        step_skipped "Mise à jour du code (aucune nouvelle version)"
    fi
    step "Migration/protection des fichiers secrets" create_env || return 1
    step "Certificat HTTPS" check_certificate || return 1
    step "Validation Docker Compose" check_compose || return 1
    step "Construction des images" build_images || return 1
    step "Redémarrage et migrations" start_stack || return 1
    step "Migrations PostgreSQL" check_migrations || return 1
    step "Santé des services" api_health || return 1
    web_final_summary
}

web_do_status() {
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    if web_installed; then
        say "État : Installé"
        web_show_status
        api_health >"$LOG" 2>&1 && say "Santé : OK" || { warn "Santé : problème détecté"; tail -n 5 "$LOG" | sed 's/^/    /'; return 1; }
    else
        say "État : Non installé"
        say "Version locale : $(git_version)"
        say "Branche        : $(git_branch)"
    fi
}

web_do_backup() {
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    [ -f "$ENV_FILE" ] || die "Aucun .env : rien à sauvegarder."
    if make_backup "${1:-$BACKUP_DIR}" >"$LOG" 2>&1; then
        sed 's/^/  /' "$LOG"
        warn "Rappel : .env et le certificat HTTPS ne sont pas dans la sauvegarde ; conservez-les ailleurs."
    else
        cat "$LOG" >&2; die "La sauvegarde a échoué."
    fi
}

web_do_restore() {
    local file="${1:-}"
    [ -n "$file" ] || { echo "Usage : restore FICHIER_ARCHIVE" >&2; exit 2; }
    banner
    say "${RED}${BOLD}ATTENTION — RESTAURATION${RESET}"
    say ""
    say "La base PostgreSQL ET les données persistantes (rapports, journaux) actuelles seront REMPLACÉES"
    say "par le contenu de l'archive. .env et le certificat HTTPS ne sont pas modifiés."
    say ""
    begin_steps 10
    step "Vérification des prérequis Docker" web_check_prerequisites || return 1
    local tmp; tmp="$(mktemp -d)"; chmod 700 "$tmp"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'; rm -f '$LOG'" EXIT
    ARCHIVE_UNVERIFIED=0
    step "Intégrité de l'archive (SHA-256)" verify_archive "$file" "$tmp" || return 1
    if [ "$ARCHIVE_UNVERIFIED" = 1 ]; then
        warn "    Cette archive n'a pas de sommes SHA-256 : seule sa lisibilité a pu être vérifiée."
        ask_go "Restaurer quand même ?" || cancelled
    fi
    [ -f "$ENV_FILE" ] || die "Aucun .env : lancez d'abord l'installation, puis restaurez."
    step "Lecture du dump PostgreSQL" web_check_dump "$tmp/db.dump" || return 1
    say ""
    offer_backup "la restauration" || die "La sauvegarde a échoué : restauration interrompue, rien n'a été modifié."
    say ""
    confirm_typed "RESTAURER" || cancelled
    say ""
    step "Arrêt de l'API, du worker et du planificateur" dc stop api worker scheduler || return 1
    step "Remplacement de la base PostgreSQL" web_replace_database "$tmp" || { warn "La base a pu être modifiée : l'état n'est pas garanti, utilisez la sauvegarde de sécurité."; return 1; }
    step "Redémarrage des services" start_stack || return 1
    if [ -s "$tmp/data.tar" ] || [ -s "$tmp/files.tar" ]; then
        step "Restauration des données persistantes" web_restore_data "$tmp" || return 1
    else
        step_skipped "Restauration des données persistantes (absentes de l'archive)"
    fi
    step "Santé des services" api_health || return 1
    say ""
    say "${GREEN}Restauration terminée.${RESET}"
}

web_check_dump() {
    dc up -d --wait postgres || return 1
    dc exec -T postgres pg_restore -l <"$1" >/dev/null || { echo "Le dump PostgreSQL est illisible."; return 1; }
}

web_replace_database() {
    dc up -d --wait postgres || return 1
    local user name; user="$(db_user)"; name="$(db_name)"
    dc exec -T postgres dropdb -U "$user" --if-exists "$name" || return 1
    dc exec -T postgres createdb -U "$user" "$name" || return 1
    # Objects belong to the restoring role: an archive of a TLS Scan installation (role tls_scan) restores into Orion.
    dc exec -T postgres pg_restore -U "$user" -d "$name" --no-owner --no-privileges <"$1/db.dump" || return 1
}

web_restore_data() {
    local f="$1/data.tar"; [ -s "$f" ] || f="$1/files.tar"
    dc exec -T api tar -C /var/lib/orion -xf - <"$f"
}

web_do_reset_admin() {
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    web_installed || die "Orion n'est pas installé."
    local args=()
    [ "$RESET_DEFAULT" = 1 ] && args+=(--default)
    # Run directly (not through the step log): the one-time password is shown on the terminal only.
    dc exec -T api python -m orion_app.cli reset-admin-password ${args[@]+"${args[@]}"}
}

web_do_rollback_secrets() {
    rollback_env_secrets || die "Restauration des variables .env interrompue."
    say "Variables directes restaurées dans .env. Revenez au Compose précédent et protégez .env (0600)."
}

web_do_logs() {
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    local svc="${1:-}"
    case "$svc" in ""|api|worker|scheduler|postgres|webui) ;; *) die "Service inconnu : $svc (api, worker, scheduler, postgres, webui)." ;; esac
    trap ':' INT
    dc logs -f --tail 100 ${svc:+"$svc"}
    trap - INT
    return 0
}

web_do_reinstall() {
    banner
    say "${RED}${BOLD}ATTENTION — RÉINSTALLATION À NEUF (WebUI)${RESET}"
    say ""
    say "Seront supprimés :"
    say "  - la base PostgreSQL (utilisateurs, profils, politiques, cibles, scans, planifications)"
    say "  - les rapports et journaux du volume de données"
    say "  - les conteneurs du projet « $PROJECT »"
    say ""
    say "Seront conservés :"
    say "  - .env (secrets, ports)"
    say "  - les certificats HTTPS"
    say "  - les sauvegardes ($BACKUP_DIR)"
    say ""
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG"; return 1; }
    offer_backup "la suppression" || die "La sauvegarde a échoué : réinstallation interrompue, rien n'a été modifié."
    say ""
    confirm_typed "REINSTALLER" || cancelled
    say ""
    begin_steps 9
    step "Suppression des conteneurs et volumes de $PROJECT" dc down -v --remove-orphans || return 1
    step "Fichier .env et secrets" create_env || return 1
    step "Certificat HTTPS" check_certificate || return 1
    step "Validation Docker Compose" check_compose || return 1
    step "Construction des images" build_images || return 1
    step "Démarrage des conteneurs" start_stack || return 1
    step "Migrations PostgreSQL" check_migrations || return 1
    step "Santé des services" api_health || return 1
    step "Base neuve (administrateur seul, aucune donnée)" check_fresh_bootstrap || return 1
    web_final_summary
    admin_info
}

# The images of this version and those built under their pre-rebranding names; a missing one is not an error.
remove_images() {
    local image
    for image in orion-backend orion-webui tls-scan-backend tls-scan-webui; do
        docker image inspect "$image:$(image_tag)" >/dev/null 2>&1 || continue
        docker image rm "$image:$(image_tag)" || return 1
    done
}

web_do_uninstall() {
    banner
    say "${RED}${BOLD}ATTENTION — DÉSINSTALLATION (WebUI)${RESET}"
    say ""
    say "Seront supprimés :"
    say "  - les conteneurs du projet « $PROJECT »"
    say "  - ses images (orion-backend:$(image_tag), orion-webui:$(image_tag), et leurs anciens noms tls-scan-*)"
    say ""
    say "Conservés par défaut (questions séparées ci-dessous) : les données (volumes PostgreSQL et rapports),"
    say ".env, les certificats HTTPS, les sauvegardes et le dépôt Git."
    say ""
    local remove_data="non" remove_env="non" remove_certs="non"
    if [ "$ASSUME_YES" = 1 ]; then
        [ "$DELETE_DATA" = 1 ] && { remove_data="oui"; remove_env="oui"; remove_certs="oui"; }
    else
        ask "Supprimer aussi les DONNÉES (volumes PostgreSQL et rapports) ?" n && remove_data="oui"
        ask "Supprimer aussi .env ?" n && remove_env="oui"
        ask "Supprimer aussi les certificats HTTPS ($(cert_dir)) ?" n && remove_certs="oui"
    fi
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG"; return 1; }
    if [ "$remove_data" = "oui" ]; then
        say ""
        say "${RED}Les données seront supprimées définitivement.${RESET}"
        offer_backup "la suppression" || die "La sauvegarde a échoué : désinstallation interrompue, rien n'a été modifié."
    fi
    say ""
    confirm_typed "DESINSTALLER ORION" || cancelled
    if [ "$remove_data" = "oui" ]; then
        say ""
        confirm_typed "SUPPRIMER LES DONNEES" || cancelled
    fi
    say ""
    begin_steps 4
    if [ "$remove_data" = "oui" ]; then
        step "Suppression des conteneurs et des volumes de $PROJECT" dc down -v --remove-orphans || return 1
    else
        step "Suppression des conteneurs de $PROJECT (volumes conservés)" dc down --remove-orphans || return 1
    fi
    step "Suppression des images" remove_images || true
    if [ "$remove_certs" = "oui" ] && [ -d "$(cert_dir)" ] && [ ! -L "$(cert_dir)" ]; then
        step "Suppression des certificats" rm -rf -- "$(cert_dir)" || warn "Certificats non supprimés (droits ?)."
    else
        step_skipped "Suppression des certificats (conservés)"
    fi
    if [ "$remove_env" = "oui" ]; then
        step "Suppression de .env" rm -f -- "$ENV_FILE" || return 1
    else
        step_skipped "Suppression de .env (conservé)"
    fi
    say ""
    say "${GREEN}Orion WebUI est désinstallé.${RESET} Le dépôt Git ($ROOT) est conservé."
    [ "$remove_data" = "oui" ] || say "Les données sont conservées : une nouvelle installation les retrouvera."
}

# --- WebUI mode: Orion transition (installations made before the rebranding) -----------------------------------

ENV_BACKUP_GLOB=".env.pre-orion-*"
# Target project of migrate-orion; another name only for a rehearsal next to a real installation.
MIGRATION_PROJECT="${ORION_MIGRATION_PROJECT:-$NEW_PROJECT}"

# Copies .env (mode 600) before the transition changes it; prints the copy's path.
save_env_copy() {
    local copy; copy="$ROOT/.env.pre-orion-$(date -u +%Y%m%dT%H%M%SZ)"
    ( umask 077; cp -p "$ENV_FILE" "$copy" ) || return 1
    chmod 600 "$copy" && printf '%s' "$copy"
}

latest_env_copy() { find "$ROOT" -maxdepth 1 -name "$ENV_BACKUP_GLOB" -type f 2>/dev/null | sort | tail -n 1; }

# migrate-config: every TLS_SCAN_X=value line becomes ORION_X=value unless ORION_X is already set (an explicit
# ORION_ entry wins); values are never printed. The copy of .env is restored if Compose rejects the result.
rename_env_keys() {
    local tmp
    tmp="$(mktemp "$ROOT/.env.XXXXXX")" || return 1
    awk '
        /^ORION_[A-Za-z0-9_]*=/ { split($0, kv, "="); have[kv[1]] = 1 }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                line = lines[i]
                if (line ~ /^TLS_SCAN_[A-Za-z0-9_]*=/) {
                    key = substr(line, 1, index(line, "=") - 1); name = "ORION_" substr(key, 10)
                    if (name in have) continue
                    have[name] = 1; print "ORION_" substr(line, 10); continue
                }
                print line
            }
        }' "$ENV_FILE" >"$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp" && mv "$tmp" "$ENV_FILE"
}

web_do_migrate_config() {
    [ -f "$ENV_FILE" ] || die "Aucun .env : rien à migrer."
    local legacy copy
    legacy="$(sed -n 's/^\(TLS_SCAN_[A-Za-z0-9_]*\)=.*/\1/p' "$ENV_FILE")"
    [ -n "$legacy" ] || { say "Aucune variable TLS_SCAN_* dans .env : la configuration utilise déjà ORION_*."; return 0; }
    say "Variables renommées en ORION_* (les valeurs ne changent pas et ne sont pas affichées) :"
    printf '%s\n' "$legacy" | sed 's/^/    /'
    ask_go "Renommer ces variables dans .env (une copie est conservée) ?" || cancelled
    copy="$(save_env_copy)" || die "Impossible de copier .env."
    rename_env_keys || { cp -p "$copy" "$ENV_FILE"; die "Échec du renommage : .env restauré."; }
    if command -v docker >/dev/null 2>&1 && ! check_compose >"$LOG" 2>&1; then
        cp -p "$copy" "$ENV_FILE"; cat "$LOG" >&2
        die "Docker Compose refuse la configuration renommée : .env a été restauré à l'identique."
    fi
    say "${GREEN}Configuration migrée.${RESET} Copie de l'ancien .env : $copy (à supprimer après vérification)."
}

# Row count of every table of the database, one "table|count" line each, sorted: the integrity evidence.
table_counts() {
    dc exec -T postgres psql -U "$(db_user)" -d "$(db_name)" -At -c \
        "select table_name || '|' || (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', table_schema, table_name), false, true, '')))[1]::text
         from information_schema.tables where table_schema = 'public' and table_type = 'BASE TABLE' order by 1"
}

# Number of entries of the project's data volume (reports, logs).
data_entries() {
    docker run --rm --entrypoint tar -v "$(data_volume)":/data:ro "$(postgres_image)" -C /data -cf - . | tar -tf - | wc -l | tr -d ' '
}

restore_data_volume() {
    docker run --rm -i --entrypoint tar -v "$(data_volume)":/data "$(postgres_image)" -C /data -xf - <"$1"
}

MIGRATION_WORK=""
MIGRATION_ARCHIVE=""
MIGRATION_ENV_COPY=""

migration_backup() {
    make_backup "$BACKUP_DIR" || return 1
    MIGRATION_ARCHIVE="$BACKUP_ARCHIVE"
}
migration_inventory() {
    table_counts >"$MIGRATION_WORK/legacy.counts" || return 1
    [ -s "$MIGRATION_WORK/legacy.counts" ] || { echo "Inventaire vide."; return 1; }
    data_entries >"$MIGRATION_WORK/legacy.data" || return 1
    echo "$(wc -l <"$MIGRATION_WORK/legacy.counts" | tr -d ' ') table(s), $(cat "$MIGRATION_WORK/legacy.data") entrée(s) de données."
}
migration_extract() { mkdir -p "$MIGRATION_WORK/archive" && verify_archive "$MIGRATION_ARCHIVE" "$MIGRATION_WORK/archive"; }
migration_switch_env() {
    MIGRATION_ENV_COPY="$(save_env_copy)" || return 1
    env_set ORION_PROJECT "$MIGRATION_PROJECT"
    env_set ORION_DB_NAME orion
    env_set ORION_DB_USER orion
    PROJECT="$MIGRATION_PROJECT"
    echo "Copie de l'ancien .env : $MIGRATION_ENV_COPY"
}
migration_create() { dc up --no-start && dc up -d --wait postgres; }
migration_restore() {
    web_replace_database "$MIGRATION_WORK/archive" || return 1
    if [ -s "$MIGRATION_WORK/archive/data.tar" ]; then restore_data_volume "$MIGRATION_WORK/archive/data.tar" || return 1; fi
}
# The copy must be exact BEFORE Orion starts (its scheduler could legitimately add rows afterwards).
migration_compare() {
    table_counts >"$MIGRATION_WORK/orion.counts" || return 1
    if ! cmp -s "$MIGRATION_WORK/legacy.counts" "$MIGRATION_WORK/orion.counts"; then
        echo "Les comptages diffèrent (TLS Scan → Orion) :"; diff "$MIGRATION_WORK/legacy.counts" "$MIGRATION_WORK/orion.counts"; return 1
    fi
    local data; data="$(data_entries)" || return 1
    [ "$data" = "$(cat "$MIGRATION_WORK/legacy.data")" ] || { echo "Données persistantes : $data entrée(s) au lieu de $(cat "$MIGRATION_WORK/legacy.data")."; return 1; }
    echo "$(wc -l <"$MIGRATION_WORK/orion.counts" | tr -d ' ') table(s) et $data entrée(s) de données identiques." | tee "$MIGRATION_WORK/compare.txt"
}

# Back to the TLS Scan installation exactly as it was: Orion is stopped (its volumes are kept for analysis), the
# previous .env is put back and the untouched TLS Scan project is started again.
restart_legacy() {
    local copy="$1" legacy="$2"
    PROJECT="$MIGRATION_PROJECT"; dc stop || true
    cp -p "$copy" "$ENV_FILE" || return 1
    PROJECT="$legacy"
    start_stack && api_health
}

# Failure before .env is switched: TLS Scan is restarted unchanged.
migration_abort() {
    step "Redémarrage de TLS Scan" start_stack || die "$1, et TLS Scan ne redémarre pas : sauvegarde ${MIGRATION_ARCHIVE:-non prise}."
    die "$1 : TLS Scan redémarré, rien n'a été modifié."
}

web_do_migrate_orion() {
    banner
    say "${BOLD}MIGRATION VERS ORION${RESET} (projet, base PostgreSQL et volumes)"
    say ""
    say "L'installation TLS Scan « $PROJECT » (base « $(db_name) ») est copiée vers le projet « $MIGRATION_PROJECT » (base « orion »)"
    say "par une sauvegarde vérifiée puis une restauration, et les comptages de chaque table sont comparés."
    say "Les volumes TLS Scan ne sont ni modifiés ni supprimés : rollback-orion y revient à tout moment."
    say "Interruption de service : de l'arrêt de TLS Scan jusqu'au démarrage d'Orion."
    say ""
    [[ "$MIGRATION_PROJECT" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "Nom de projet cible invalide : $MIGRATION_PROJECT"
    [ "$PROJECT" != "$MIGRATION_PROJECT" ] || die "L'installation utilise déjà le projet « $MIGRATION_PROJECT »."
    [ "$(db_name)" != orion ] || die "La base s'appelle déjà « orion » : rien à migrer."
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    [ -f "$ENV_FILE" ] || die "Aucun .env : rien à migrer."
    web_installed || die "Aucune installation TLS Scan dans le projet « $PROJECT »."
    local legacy="$PROJECT"
    PROJECT="$MIGRATION_PROJECT"
    if web_installed; then die "Le projet « $MIGRATION_PROJECT » existe déjà (conteneurs ou volumes) : rien n'est écrasé. Vérifiez-le avant de relancer."; fi
    PROJECT="$legacy"
    confirm_typed "MIGRER VERS ORION" || cancelled
    say ""
    MIGRATION_WORK="$(mktemp -d)"; chmod 700 "$MIGRATION_WORK"
    # shellcheck disable=SC2064
    trap "rm -rf '$MIGRATION_WORK'; rm -f '$LOG'" EXIT
    begin_steps 14
    # Nothing may write between the backup, the inventory and the copy: the application is stopped first, PostgreSQL
    # alone keeps running for the dump. Until .env is switched, any failure restarts TLS Scan as it was.
    # Images first, while TLS Scan still serves: rebuilding a tag leaves the running containers alone.
    step "Construction des images Orion" build_images || die "Construction impossible : TLS Scan reste en service, rien n'a été modifié."
    step "Arrêt de l'application TLS Scan (PostgreSQL conservé)" dc stop webui api worker scheduler \
        || { start_stack >/dev/null 2>&1; die "Arrêt impossible : TLS Scan redémarré, rien n'a été modifié."; }
    step "Sauvegarde vérifiée de TLS Scan" migration_backup || migration_abort "Sauvegarde impossible"
    say "    $MIGRATION_ARCHIVE"
    step "Inventaire des données TLS Scan" migration_inventory || migration_abort "Inventaire impossible"
    sed -n '$p' "$LOG" | sed 's/^/    /'
    step "Lecture de la sauvegarde" migration_extract || migration_abort "Sauvegarde illisible"
    step "Arrêt de PostgreSQL TLS Scan (volumes conservés)" dc stop || migration_abort "Arrêt impossible"
    if step "Configuration Orion (.env copié)" migration_switch_env \
        && step "Validation Docker Compose" check_compose \
        && step "Création des volumes et de la base Orion" migration_create \
        && step "Restauration des données dans Orion" migration_restore \
        && step "Contrôle d'intégrité (comptages)" migration_compare \
        && step "Démarrage d'Orion et migrations" start_stack \
        && step "Migrations PostgreSQL" check_migrations \
        && step "Santé des services" api_health; then
        say ""
        say "${GREEN}Migration terminée.${RESET} URL : $(public_url)"
        say "Contrôle            : $(cat "$MIGRATION_WORK/compare.txt")"
        say "Sauvegarde TLS Scan : $MIGRATION_ARCHIVE"
        say "Ancien .env         : $MIGRATION_ENV_COPY"
        say "Les volumes de « $legacy » sont conservés : rollback-orion revient à TLS Scan tant qu'ils existent."
        say "Après recette, ils peuvent être supprimés manuellement (voir docs/admin/orion-migration.md)."
        return 0
    fi
    say ""
    warn "Échec de la migration : retour automatique à TLS Scan."
    if [ -n "$MIGRATION_ENV_COPY" ]; then
        step "Retour à TLS Scan" restart_legacy "$MIGRATION_ENV_COPY" "$legacy" \
            || die "Le retour automatique a échoué : sauvegarde $MIGRATION_ARCHIVE, ancien .env $MIGRATION_ENV_COPY."
    else
        PROJECT="$legacy"; step "Redémarrage de TLS Scan" start_stack || die "Redémarrage impossible : sauvegarde $MIGRATION_ARCHIVE."
    fi
    say "TLS Scan est de nouveau en service, inchangé. Les volumes Orion créés sont conservés pour analyse."
    return 1
}

web_do_rollback_orion() {
    banner
    local copy; copy="$(latest_env_copy)"
    [ -n "$copy" ] || die "Aucune copie .env.pre-orion-* : pas de migration à annuler."
    local legacy; legacy="$(sed -n 's/^ORION_PROJECT=//p; s/^TLS_SCAN_PROJECT=//p' "$copy" | tail -n 1)"; legacy="${legacy:-$LEGACY_PROJECT}"
    [ "$PROJECT" = "$MIGRATION_PROJECT" ] || die "L'installation n'utilise pas le projet « $MIGRATION_PROJECT » : rien à annuler."
    say "${RED}${BOLD}RETOUR À TLS SCAN${RESET}"
    say ""
    say "Orion est arrêté (ses volumes sont conservés) et l'installation TLS Scan « $legacy » redémarre avec $copy."
    say "Les modifications faites dans Orion depuis la migration ne sont PAS reportées dans TLS Scan."
    say ""
    PROJECT="$legacy"
    web_installed || die "Les volumes du projet « $legacy » n'existent plus : retour impossible, restaurez une sauvegarde."
    PROJECT="$MIGRATION_PROJECT"
    web_check_prerequisites >"$LOG" 2>&1 || { cat "$LOG" >&2; return 1; }
    offer_backup "le retour à TLS Scan" || die "La sauvegarde a échoué : rien n'a été modifié."
    confirm_typed "RETOUR TLS SCAN" || cancelled
    begin_steps 1
    step "Arrêt d'Orion et redémarrage de TLS Scan" restart_legacy "$copy" "$legacy" || return 1
    say "${GREEN}TLS Scan est de nouveau en service.${RESET} URL : $(public_url)"
}

# --- Standalone mode --------------------------------------------------------------------------------------------

MIN_PYTHON="$(sed -n 's/^requires-python *= *">=\([0-9.]*\)".*/\1/p' "$ROOT/pyproject.toml" 2>/dev/null | head -n 1)"
MIN_PYTHON="${MIN_PYTHON:-3.12}"
PYTHON=""

find_python() {
    local py
    for py in python3 python3.14 python3.13 python3.12; do
        command -v "$py" >/dev/null 2>&1 || continue
        if "$py" -c "import sys; sys.exit(0 if sys.version_info >= tuple(map(int, '$MIN_PYTHON'.split('.'))) else 1)" 2>/dev/null; then
            PYTHON="$py"; return 0
        fi
    done
    return 1
}

# Missing pieces (name list), without changing anything.
standalone_missing() {
    local missing=()
    find_python || missing+=("python3 >= $MIN_PYTHON")
    if [ -n "$PYTHON" ] && ! "$PYTHON" -c 'import venv, ensurepip' 2>/dev/null; then missing+=("python3-venv"); fi
    command -v nmap >/dev/null 2>&1 || missing+=("nmap")
    printf '%s\n' ${missing[@]+"${missing[@]}"}
}

package_manager() {
    local pm
    for pm in apt-get dnf yum zypper; do command -v "$pm" >/dev/null 2>&1 && { printf '%s' "$pm"; return 0; }; done
    return 1
}

# Proposes the system installation of what is missing; nothing is installed without an explicit yes.
standalone_offer_packages() {
    local missing pm pkgs=() item
    missing="$(standalone_missing)"
    [ -n "$missing" ] || return 0
    say ""
    say "Dépendances manquantes :"
    printf '%s\n' "$missing" | sed 's/^/    - /'
    pm="$(package_manager)" || { say "Aucun gestionnaire de paquets reconnu : installez-les vous-même."; return 1; }
    while IFS= read -r item; do
        case "$item" in
            python3*) case "$pm" in apt-get) pkgs+=(python3 python3-venv python3-pip) ;; *) pkgs+=(python3 python3-pip) ;; esac ;;
            nmap) pkgs+=(nmap) ;;
        esac
    done <<<"$missing"
    local cmd=("$pm" install -y "${pkgs[@]}") sudo=""
    [ "$(id -u)" = 0 ] || sudo="sudo"
    ask "Installer ${pkgs[*]} avec « ${sudo:+$sudo }${cmd[*]} » ?" n || { say "Rien n'a été installé."; return 1; }
    # shellcheck disable=SC2086
    $sudo "${cmd[@]}" || return 1
    find_python && [ -z "$(standalone_missing)" ]
}

standalone_check_prerequisites() {
    local missing; find_python; missing="$(standalone_missing)"
    if [ -n "$missing" ]; then
        echo "Dépendances manquantes :"; printf '%s\n' "$missing" | sed 's/^/    - /'
        return 1
    fi
    [ -f "$ROOT/requirements.txt" ] && [ -f "$ROOT/orion.py" ] || { echo "requirements.txt ou orion.py est introuvable à côté de ce script."; return 1; }
    echo "Python : $("$PYTHON" --version 2>&1) ; Nmap : $(nmap --version 2>/dev/null | head -n 1)"
}

# Advanced (tests of this script): ORION_PY_MODULES lists the modules proving the dependencies are installed.
PY_MODULES="${ORION_PY_MODULES:-${TLS_SCAN_PY_MODULES:-yaml, nmap, cryptography, prettytable, tqdm, certifi}}"
standalone_installed() { [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import $PY_MODULES" 2>/dev/null; }
standalone_partial()   { [ -d "$VENV" ] && ! standalone_installed; }

standalone_create_venv() {
    if [ -x "$VENV/bin/python" ]; then echo "Environnement virtuel existant réutilisé : $VENV"; return 0; fi
    find_python || return 1
    "$PYTHON" -m venv "$VENV"
}
standalone_install_deps() { "$VENV/bin/python" -m pip install --disable-pip-version-check -r "$ROOT/requirements.txt"; }
standalone_check_cli()    { "$VENV/bin/python" "$ROOT/orion.py" --help >/dev/null && echo "CLI opérationnelle"; }

# YAML configuration: reports are listed and each one is validated with --dry-run (no Nmap, no network).
standalone_check_config() {
    local cfg="$ROOT/config/config.yaml" reports name n=0
    [ -f "$cfg" ] || { echo "$cfg est introuvable."; return 1; }
    reports="$("$VENV/bin/python" "$ROOT/orion.py" --config "$cfg" --list-reports)" || { echo "$reports"; return 1; }
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        "$VENV/bin/python" "$ROOT/orion.py" --config "$cfg" --report "$name" --dry-run --no-log-file >/dev/null 2>"$LOG.err" \
            || { echo "Rapport « $name » invalide :"; tail -n 5 "$LOG.err"; rm -f "$LOG.err"; return 1; }
        n=$((n + 1))
    done <<<"$reports"
    rm -f "$LOG.err"
    echo "$n rapport(s) de config/config.yaml validé(s)"
}

standalone_show_status() {
    if standalone_installed; then say "État : Installé"
    elif standalone_partial; then say "État : Incomplet (environnement virtuel présent, dépendances manquantes)"
    else say "État : Non installé"; fi
    say "Version : $(git_version)"
    say "Branche : $(git_branch)"
    say ""
}

standalone_usage() {
    say "Lancer un scan (l'environnement virtuel est $VENV) :"
    say ""
    say "    source .venv/bin/activate"
    say "    python orion.py --config config/config.yaml --list-reports"
    say "    python orion.py --config config/config.yaml --report <nom> --dry-run   # validation sans scan"
    say "    python orion.py --config config/config.yaml --report <nom>"
    say "    python orion.py -p fast ma-cible.example.org                           # scan ponctuel"
    say ""
    say "Aucun scan n'a été lancé par l'installation."
}

standalone_do_install() {
    banner
    say "Installation d'Orion — Standalone (natif, sans Docker)."
    standalone_installed && say "Une installation existe : l'environnement virtuel est réutilisé, configurations et rapports conservés."
    say ""
    if [ -n "$(standalone_missing)" ]; then standalone_offer_packages || true; fi
    begin_steps 5
    step "Vérification des prérequis (Python, Nmap)" standalone_check_prerequisites || return 1
    step "Environnement virtuel" standalone_create_venv || return 1
    step "Dépendances Python" standalone_install_deps || return 1
    step "Exécution de la CLI" standalone_check_cli || return 1
    step "Configuration YAML" standalone_check_config || return 1
    say ""
    say "${GREEN}Terminé.${RESET}"
    say ""
    standalone_usage
    if ! command -v openssl >/dev/null 2>&1 || ! openssl version 2>/dev/null | grep -Eq 'OpenSSL (3\.([5-9]|[1-9][0-9])|[4-9])'; then
        warn "Note : le profil de chiffrement « pqc » nécessite OpenSSL 3.5 ou plus récent."
    fi
}

standalone_do_update() {
    banner
    say "MISE À JOUR / REDÉPLOIEMENT — Standalone. Configurations, rapports et journaux ne sont pas touchés."
    say ""
    begin_steps 7
    step "Vérification des prérequis (Python, Nmap)" standalone_check_prerequisites || return 1
    update_git_phase || return 1
    if [ "$NEW_VERSION" = "oui" ]; then
        step "Mise à jour du code (fast-forward)" git_fast_forward || return 1
    else
        step_skipped "Mise à jour du code (aucune nouvelle version)"
    fi
    step "Environnement virtuel" standalone_create_venv || return 1
    step "Dépendances Python" standalone_install_deps || return 1
    step "Exécution de la CLI" standalone_check_cli || return 1
    step "Configuration YAML" standalone_check_config || return 1
    say ""
    say "${GREEN}Terminé.${RESET}"
}

standalone_do_status() {
    standalone_show_status
    standalone_installed || { warn "Installez d'abord le mode Standalone."; return 1; }
    begin_steps 4
    step "Prérequis (Python, Nmap)" standalone_check_prerequisites || return 1
    step "Dépendances Python" "$VENV/bin/python" -c "import $PY_MODULES" || return 1
    step "Exécution de la CLI" standalone_check_cli || return 1
    step "Configuration YAML" standalone_check_config || return 1
    say ""
    say "${GREEN}Installation vérifiée.${RESET}"
}

standalone_do_reinstall() {
    banner
    say "${RED}${BOLD}ATTENTION — RÉINSTALLATION (Standalone)${RESET}"
    say ""
    say "Sera supprimé puis recréé : l'environnement virtuel ($VENV)."
    say "Seront conservés : config/, logs/, scan_reports/, le dépôt Git, tout fichier utilisateur."
    say ""
    confirm_typed "REINSTALLER" || cancelled
    say ""
    [ -d "$VENV" ] && [ ! -L "$VENV" ] && { rm -rf -- "$VENV" || die "Impossible de supprimer $VENV."; }
    standalone_do_install
}

standalone_do_uninstall() {
    banner
    say "${RED}${BOLD}ATTENTION — DÉSINSTALLATION (Standalone)${RESET}"
    say ""
    say "Sera supprimé : l'environnement virtuel ($VENV)."
    say "Conservés par défaut : config/, logs/, scan_reports/ (vos fichiers), le dépôt Git, l'éventuelle installation WebUI."
    say ""
    local remove_files="non"
    if [ "$ASSUME_YES" = 1 ]; then
        [ "$DELETE_DATA" = 1 ] && remove_files="oui"
    else
        ask "Supprimer aussi logs/ et scan_reports/ (journaux et rapports générés) ?" n && remove_files="oui"
    fi
    confirm_typed "DESINSTALLER STANDALONE" || cancelled
    if [ "$remove_files" = "oui" ]; then
        say ""
        say "${RED}logs/ et scan_reports/ seront supprimés définitivement.${RESET}"
        confirm_typed "SUPPRIMER MES FICHIERS" || cancelled
    fi
    say ""
    begin_steps 2
    if [ -d "$VENV" ] && [ ! -L "$VENV" ]; then
        step "Suppression de l'environnement virtuel" rm -rf -- "$VENV" || return 1
    else
        step_skipped "Suppression de l'environnement virtuel (absent)"
    fi
    if [ "$remove_files" = "oui" ]; then
        step "Suppression de logs/ et scan_reports/" rm -rf -- "$ROOT/logs" "$ROOT/scan_reports" || return 1
    else
        step_skipped "Suppression de logs/ et scan_reports/ (conservés)"
    fi
    say ""
    say "${GREEN}Orion Standalone est désinstallé.${RESET} Le dépôt Git ($ROOT) est conservé."
}

# --- interactive menus ------------------------------------------------------------------------------------------

pause() { printf '\nAppuyez sur Entrée pour revenir au menu... '; read -r _ || true; }

# Runs an operation in a subshell so that a failure (die, exit) returns to the menu.
run_op() { ( "$@" ); local rc=$?; [ "$rc" -eq 0 ] || say "(opération terminée avec le code $rc)"; pause; }

menu_standalone() {
    local choice
    while true; do
        say ""
        banner
        say "Orion — Standalone"
        say ""
        standalone_show_status
        say "[1] Installer"
        say "[2] Mettre à jour / redéployer"
        say "[3] Vérifier l'installation"
        say "[4] Réinstaller"
        say "[5] Désinstaller"
        say "[0] Retour"
        say ""
        printf 'Votre choix : '
        read -r choice || choice="0"
        say ""
        case "$choice" in
            1) run_op standalone_do_install ;;
            2) run_op standalone_do_update ;;
            3) run_op standalone_do_status ;;
            4) run_op standalone_do_reinstall ;;
            5) run_op standalone_do_uninstall ;;
            0|"") return 0 ;;
            *) warn "Choix invalide." ;;
        esac
    done
}

menu_webui() {
    local choice svc
    # Docker is only checked now that the WebUI mode is chosen.
    if ! web_check_prerequisites >"$LOG" 2>&1; then
        cat "$LOG" >&2
        warn "Prérequis Docker manquants : le mode WebUI n'est pas utilisable pour l'instant."
        pause
        return 0
    fi
    while true; do
        say ""
        banner
        say "Orion — WebUI (Docker)"
        say ""
        if web_installed; then
            say "État : Installé"
            web_show_status
        else
            say "État : Non installé"
            say "Version : $(git_version)"
            say "Branche : $(git_branch)"
            say ""
        fi
        say "[1] Installer"
        say "[2] Mettre à jour / redéployer"
        say "[3] Vérifier l'installation"
        say "[4] Sauvegarder"
        say "[5] Restaurer"
        say "[6] Consulter les logs"
        say "[7] Réinitialiser le compte administrateur"
        say "[8] Réinstaller à neuf"
        say "[9] Désinstaller"
        say "[0] Retour"
        say ""
        printf 'Votre choix : '
        read -r choice || choice="0"
        say ""
        case "$choice" in
            1) run_op web_do_install ;;
            2) run_op web_do_update ;;
            3) run_op web_do_status ;;
            4) run_op web_do_backup ;;
            5) printf "Chemin de l'archive à restaurer : "; read -r svc || svc=""
               run_op web_do_restore "$svc" ;;
            6) printf 'Service (api, worker, scheduler, postgres, webui ; vide = tous) : '; read -r svc || svc=""
               ( web_do_logs "$svc" ) ;;
            7) ask "Revenir au mot de passe par défaut (SecretPassword, changement forcé) ?" n && RESET_DEFAULT=1
               run_op web_do_reset_admin; RESET_DEFAULT=0 ;;
            8) run_op web_do_reinstall ;;
            9) run_op web_do_uninstall ;;
            0|"") return 0 ;;
            *) warn "Choix invalide." ;;
        esac
    done
}

menu_main() {
    local choice
    while true; do
        banner
        say "Bienvenue dans l'assistant Orion."
        say ""
        say "Choisissez votre mode de déploiement :"
        say ""
        say "[1] Standalone (autonome)"
        say "    Moteur TLS en ligne de commande"
        say "    Installation native : Python + Nmap"
        say "    Sans Docker ni PostgreSQL"
        say ""
        say "[2] WebUI (Docker)"
        say "    Application complète avec interface web"
        say "    API + PostgreSQL + Worker + Scheduler"
        say "    Déploiement Docker Compose"
        say ""
        say "[0] Quitter"
        say ""
        printf 'Votre choix : '
        read -r choice || choice="0"
        case "$choice" in
            1) menu_standalone ;;
            2) check_project_name; menu_webui ;;
            0|"") say "Au revoir."; return 0 ;;
            *) warn "Choix invalide." ;;
        esac
    done
}

# --- command line --------------------------------------------------------------------------------------------------

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

COMMAND=""
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)       [ $# -ge 2 ] || { echo "--mode attend standalone ou webui." >&2; exit 2; }; MODE="$2"; shift ;;
        --mode=*)     MODE="${1#--mode=}" ;;
        --yes|-y)     ASSUME_YES=1 ;;
        --no-backup)  NO_BACKUP=1 ;;
        --no-git)     NO_GIT=1 ;;
        --delete-data) DELETE_DATA=1 ;;
        --default)    RESET_DEFAULT=1 ;;
        -h|--help)    usage; exit 0 ;;
        -*)           echo "Option inconnue : $1" >&2; usage >&2; exit 2 ;;
        *)            if [ -z "$COMMAND" ]; then COMMAND="$1"; else ARGS+=("$1"); fi ;;
    esac
    shift
done

case "$MODE" in ""|standalone|webui) ;; *) echo "Mode inconnu : $MODE (standalone ou webui)." >&2; exit 2 ;; esac

if [ -z "$COMMAND" ]; then
    [ -z "$MODE" ] || { case "$MODE" in standalone) menu_standalone ;; webui) check_project_name; menu_webui ;; esac; exit 0; }
    menu_main
    exit 0
fi

MODE="${MODE:-webui}"   # historical commands address the WebUI

if [ "$MODE" = "standalone" ]; then
    case "$COMMAND" in
        install)            standalone_do_install ;;
        update|redeploy)    standalone_do_update ;;
        status|verify)      standalone_do_status ;;
        reinstall)          standalone_do_reinstall ;;
        uninstall)          standalone_do_uninstall ;;
        backup|restore|reset-admin|logs|migrate-config|migrate-orion|rollback-orion) die "La commande « $COMMAND » n'existe qu'en mode WebUI (--mode webui)." ;;
        *) echo "Commande inconnue : $COMMAND" >&2; usage >&2; exit 2 ;;
    esac
    exit $?
fi

case "$COMMAND" in
    install|update|redeploy|status|verify|backup|restore|reset-admin|logs|reinstall|uninstall|rollback-secrets|migrate-config|migrate-orion|rollback-orion) check_project_name ;;
    *) echo "Commande inconnue : $COMMAND" >&2; usage >&2; exit 2 ;;
esac
case "$COMMAND" in
    install)         web_do_install ;;
    update|redeploy) web_do_update ;;
    status|verify)   web_do_status ;;
    backup)          web_do_backup "${ARGS[0]:-}" ;;
    restore)         web_do_restore "${ARGS[0]:-}" ;;
    reset-admin)     web_do_reset_admin ;;
    rollback-secrets) web_do_rollback_secrets ;;
    migrate-config)  web_do_migrate_config ;;
    migrate-orion)   web_do_migrate_orion ;;
    rollback-orion)  web_do_rollback_orion ;;
    logs)            web_do_logs "${ARGS[0]:-}" ;;
    reinstall)       web_do_reinstall ;;
    uninstall)       web_do_uninstall ;;
esac
exit $?
