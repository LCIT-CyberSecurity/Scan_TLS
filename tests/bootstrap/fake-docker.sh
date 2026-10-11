#!/usr/bin/env bash
# Fake `docker` for the bootstrap tests. State lives in $FAKE_STATE:
#   calls                    one line per invocation (the tests grep it)
#   up_<project>             present while the project's containers exist
#   volumes/<project>_pgdata/db     the "database": one "user:<name>" line per user
#   volumes/<project>_data/...      the persistent data volume
# Failure injection: FAKE_NO_DAEMON, FAKE_FAIL_PGDUMP, FAKE_FAIL_UP.
S="${FAKE_STATE:?}"; mkdir -p "$S/volumes"; ALL="$*"
echo "docker $*" >>"$S/calls"
vol() { printf '%s/volumes/%s' "$S" "$1"; }
ensure_project() {
  mkdir -p "$(vol "$1_pgdata")" "$(vol "$1_data")"
  [ -f "$(vol "$1_pgdata")/db" ] || echo "user:admin" >"$(vol "$1_pgdata")/db"
  : >"$S/up_$1"
}
case "${1:-}" in
  info) [ -z "${FAKE_NO_DAEMON:-}" ] || { echo "Cannot connect to the Docker daemon" >&2; exit 1; }; exit 0 ;;
  ps) p="${ALL##*project=}"; { [ -f "$S/up_$p" ] && echo "abc123"; } || true; exit 0 ;;
  volume)
    case "$2" in
      ls) p="${ALL##*project=}"; for d in "$S"/volumes/"$p"_*; do [ -d "$d" ] && basename "$d"; done; exit 0 ;;
      inspect) [ -d "$(vol "$3")" ] ;; esac; exit $? ;;
  image) exit 0 ;;
  run)
    [ -z "${FAKE_FAIL_TAR:-}" ] || exit 1
    v="$(printf '%s\n' "$@" | sed -n 's#^\(.*\):/data:ro$#\1#p')"
    tar -C "$(vol "$v")" -cf - . ; exit $? ;;
  compose)
    shift; [ "${1:-}" != version ] || exit 0
    P=""; while [ $# -gt 0 ]; do case "$1" in -p) P="$2"; shift 2 ;; --project-directory|-f) shift 2 ;; *) break ;; esac; done
    sub="$1"; shift
    case "$sub" in
      config) case "$*" in *--images*) printf 'postgres:16-alpine\ntls-scan-backend:local\n' ;; esac; exit 0 ;;
      build) exit 0 ;;
      up) [ -z "${FAKE_FAIL_UP:-}" ] || { echo "up failed" >&2; exit 1; }; ensure_project "$P"; exit 0 ;;
      down) case "$*" in *-v*) rm -rf "$S"/volumes/"$P"_*;; esac; rm -f "$S/up_$P"; exit 0 ;;
      stop) exit 0 ;;
      logs) echo "log line"; exit 0 ;;
      ps) if [ -f "$S/up_$P" ]; then case "$*" in
            *"--status running"*) printf 'postgres\napi\nworker\nscheduler\nwebui\n' ;;
            *) printf 'api|Up 2 minutes (healthy)\npostgres|Up 2 minutes (healthy)\n' ;; esac; fi; exit 0 ;;
      exec)
        shift; [ "${1:-}" != -T ] || shift
        svc="$1"; shift
        db="$(vol "${P}_pgdata")/db"
        case "$svc:$1" in
          postgres:pg_dump) [ -z "${FAKE_FAIL_PGDUMP:-}" ] || { echo "pg_dump: connection failed" >&2; exit 1; }
                            echo DUMP; cat "$db" ;;
          postgres:pg_restore) case "$*" in *" -l"*) read -r h; [ "$h" = DUMP ] || exit 1 ;;
                                  *) read -r h; [ "$h" = DUMP ] || exit 1; cat >"$db" ;; esac ;;
          postgres:dropdb) rm -f "$db" ;;
          postgres:createdb) : >"$db" ;;
          postgres:psql) wc -l <"$db" | tr -d ' ' ;;
          api:curl) exit 0 ;;
          api:sh) echo "0003_target_name (head)" ;;
          api:tar) tar -C "$(vol "${P}_data")" -xf - ;;
          api:python) echo "New password: ExamplePassword-1" ;;
          *) exit 0 ;;
        esac ;;
    esac ;;
esac
exit 0
