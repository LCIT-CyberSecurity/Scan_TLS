#!/usr/bin/env bash
# Standalone check of the complementary TLS checks (lots 1 and 2) on the lab: the same scan with and without `checks.tls` must give
# identical CSV, findings CSV and CBOM, for direct TLS and for SMTP; Markdown/HTML only gain the "Complementary TLS Checks" section.
# A third scan goes through STARTTLS (IMAP, POP3, LDAP, FTP, PostgreSQL, XMPP) on their standard ports. Needs Docker; run from the repo root
# (on the VM: ops/dev/vm.sh "bash tests/regression/checks.sh").
set -euo pipefail
docker build -q -t tlsscan-regression -f ops/docker/backend.Dockerfile --build-arg WITH_DEV=true . >/dev/null
docker build -q -t tlsscan-lab -f tests/lab/lab-tls.Dockerfile . >/dev/null
docker network rm tlsscan-regress2 >/dev/null 2>&1 || true
docker network create tlsscan-regress2 >/dev/null
# KEEP=1 keeps .regression-checks (the exports of every scan) for inspection
trap 'docker rm -f regress2-lab >/dev/null 2>&1; docker network rm tlsscan-regress2 >/dev/null 2>&1; [ -n "${KEEP:-}" ] || docker run --rm -v $PWD:/w alpine rm -rf /w/.regression-checks' EXIT
docker run -d --rm --name regress2-lab --network tlsscan-regress2 --network-alias lab-tls tlsscan-lab >/dev/null
sleep 4
rm -rf .regression-checks; mkdir -p .regression-checks/plain .regression-checks/checks .regression-checks/smtp_plain .regression-checks/smtp_checks .regression-checks/starttls; chmod 777 .regression-checks/*
run() { # run <report> <outdir>
  docker run --rm --network tlsscan-regress2 -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD:/app" -v "$PWD/tests/regression/config:/app/config:ro" \
    -v "$PWD/.regression-checks/$2:/out" -w /app -e PYTHONPATH=/app tlsscan-regression python tls_scan.py --config config/config_checks.yaml --report "$1" >/dev/null 2>&1
}
run lab_plain plain
run lab_checks checks
run smtp_plain smtp_plain
run smtp_checks smtp_checks
run starttls_checks starttls
python3 - <<'PY'
import pathlib, re, sys
root = pathlib.Path(".regression-checks")
def read(kind, name, rel): return (root / kind / name / rel).read_text(errors="replace")
def norm(text, name):
    text = text.replace(name, "<NAME>")
    text = re.sub(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d(:\d\d(\.\d+)?)?(Z|[+-]\d\d:?\d\d)?", "<TS>", text)
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<UUID>", text)
    text = re.sub(r"tls-scan-pki-[a-z0-9_]+", "tls-scan-pki-<TMP>", text)
    text = re.sub(r"(?i)(duration[^\n|]*?)\d+(\.\d+)?", r"\1<N>", text)
    # the identity check settles "Hostname validation" / "SAN validation" for the endpoints where it ran: the only intended difference
    text = re.sub(r"(Checks Not Tested \| )\d+", r"\1<N>", text)
    # the identity check settles "Hostname validation" / "SAN validation" where it ran: the only intended difference in the statistics
    text = re.sub(r"(Checks Not Tested \| )\d+", r"\1<N>", text)
    return re.sub(r"\d+ days?", "<N> days", text)
fail = False
def compare(kind_a, name_a, kind_b, name_b, label):
    global fail
    for rel in ("csv/{n}.csv", "csv/{n}_findings.csv", "cbom/{n}.cbom.json"):
        a, b = norm(read(kind_a, name_a, rel.format(n=name_a)), name_a), norm(read(kind_b, name_b, rel.format(n=name_b)), name_b)
        print(("identical: " if a == b else "DIFFERENT: ") + label + " " + rel); fail |= a != b
def section_of(markdown):
    return re.search(r"\n## Complementary TLS Checks\n.*?(?=\n## |\Z)", markdown, re.S)
compare("plain", "lab_plain", "checks", "lab_checks", "direct TLS")
compare("smtp_plain", "smtp_plain", "smtp_checks", "smtp_checks", "SMTP")
for plain_kind, plain, checks_kind, checked, label in (("plain", "lab_plain", "checks", "lab_checks", "direct TLS"), ("smtp_plain", "smtp_plain", "smtp_checks", "smtp_checks", "SMTP")):
    md_plain = norm(read(plain_kind, plain, f"markdown/{plain}.md"), plain)
    md_checks = norm(read(checks_kind, checked, f"markdown/{checked}.md"), checked)
    section = section_of(md_checks)
    stripped = md_checks.replace(section.group(0), "", 1) if section else md_checks
    print(("identical: " if stripped == md_plain else "DIFFERENT: ") + label + " markdown without the new section"); fail |= stripped != md_plain
    print(label + " markdown has the section:", bool(section)); fail |= not section
    html = read(checks_kind, checked, f"html/{checked}.html")
    has = 'report-chapter" id="tlschecks"' in html
    print(label + " html has the section:", has, "| plain html has none:", 'report-chapter" id="tlschecks"' not in read(plain_kind, plain, f"html/{plain}.html"))
    fail |= not has
    if section and label == "direct TLS":
        print("\n".join(l[:200] for l in section.group(0).splitlines()[:60]))
starttls = section_of(read("starttls", "starttls_checks", "markdown/starttls_checks.md"))
text = starttls.group(0) if starttls else ""
for check in ("starttls_imap", "starttls_pop3", "starttls_ldap", "starttls_ftp", "starttls_postgres", "starttls_xmpp"):
    label = {"starttls_imap": "IMAP STARTTLS", "starttls_pop3": "POP3 STLS", "starttls_ldap": "LDAP StartTLS", "starttls_ftp": "FTP AUTH TLS", "starttls_postgres": "PostgreSQL SSLRequest", "starttls_xmpp": "XMPP STARTTLS"}[check]
    ok = bool(re.search(r"\|[^\n]*" + re.escape(label) + r"[^\n]*\| PASS \|", text))
    print(("STARTTLS ok: " if ok else "STARTTLS MISSING: ") + label); fail |= not ok
sys.exit(1 if fail else 0)
PY
