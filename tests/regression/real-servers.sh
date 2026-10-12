#!/usr/bin/env bash
# STARTTLS adapters and lot 2 checks against REAL daemons (Postfix, Dovecot, vsftpd, OpenLDAP, PostgreSQL, Prosody) on their
# standard ports. Needs Docker; run from the repo root (on the VM: ops/dev/vm.sh "bash tests/regression/real-servers.sh").
set -euo pipefail
docker build -q -t tlsscan-regression -f ops/docker/backend.Dockerfile --build-arg WITH_DEV=true . >/dev/null
docker build -q -t tlsscan-real -f tests/lab/real-services.Dockerfile . >/dev/null
docker network rm tlsscan-real-net >/dev/null 2>&1 || true
docker network create tlsscan-real-net >/dev/null
trap 'docker rm -f regress-real >/dev/null 2>&1; docker network rm tlsscan-real-net >/dev/null 2>&1' EXIT
docker run -d --rm --name regress-real --network tlsscan-real-net --network-alias lab-real tlsscan-real >/dev/null
for _ in $(seq 1 60); do docker logs regress-real 2>&1 | grep -q "\[real-services\] ready" && break; sleep 1; done
sleep 3
docker run --rm -i --network tlsscan-real-net -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/app" -w /app -e PYTHONPATH=/app tlsscan-regression python - <<'PY'
import socket, sys
from tls_scanner.checks.catalog import run_complementary_checks

host = socket.gethostbyname("lab-real")
COMMON = ("tls_compression", "extended_master_secret", "session_resumption", "session_tickets", "client_auth", "hostname_san")
SERVICES = [  # (port, protocol check)
    (143, "starttls_imap"), (110, "starttls_pop3"), (21, "starttls_ftp"), (389, "starttls_ldap"), (5432, "starttls_postgres"),
    (5222, "starttls_xmpp"), (5269, "starttls_xmpp_server"),
]
failed = False
for port, check in SERVICES:
    results = {r.check_id: r for r in run_complementary_checks((check, *COMMON), host, port, reference_names=("lab-real",), sni="lab-real", timeout_seconds=8, options={})}
    protocol = results[check]
    ok = protocol.status == "PASS" and protocol.observations.get("confirmed") and protocol.observations.get("upgraded")
    failed |= not ok
    print(f"{'OK  ' if ok else 'FAIL'} {check:22} :{port:<5} {protocol.status:14} {protocol.observations.get('tls_version')} | {protocol.message[:100]}")
    for other in COMMON:
        r = results[other]
        print(f"       {other:24} {r.status:15} {r.observations.get('outcome', '')} {r.message[:90]}")
# SMTP keeps its historical handling on 25 / 587 (Postfix)
for port in (25, 587):
    r = {x.check_id: x for x in run_complementary_checks(("tls_compression", "extended_master_secret", "session_resumption"), host, port, reference_names=("lab-real",), sni="lab-real", timeout_seconds=8, observed_versions=("TLSv1.2", "TLSv1.3"), options={})}
    ok = r["tls_compression"].status == "PASS" and r["extended_master_secret"].status == "PASS"
    failed |= not ok
    print(f"{'OK  ' if ok else 'FAIL'} smtp                   :{port:<5} compression={r['tls_compression'].status} ems={r['extended_master_secret'].status} resumption={r['session_resumption'].observations.get('outcome')}")
sys.exit(1 if failed else 0)
PY
