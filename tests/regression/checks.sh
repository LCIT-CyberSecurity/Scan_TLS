#!/usr/bin/env bash
# Standalone check of the complementary TLS checks on the lab: the same scan with and without `checks.tls` must give identical
# CSV, findings CSV and CBOM; Markdown/HTML only gain the "Complementary TLS Checks" section. Needs Docker; run from the repo root
# (on the VM: ops/dev/vm.sh "bash tests/regression/checks.sh").
set -euo pipefail
docker build -q -t tlsscan-regression -f ops/docker/backend.Dockerfile --build-arg WITH_DEV=true . >/dev/null
docker build -q -t tlsscan-lab -f tests/lab/lab-tls.Dockerfile . >/dev/null
docker network rm tlsscan-regress2 >/dev/null 2>&1 || true
docker network create tlsscan-regress2 >/dev/null
trap 'docker rm -f regress2-lab >/dev/null 2>&1; docker network rm tlsscan-regress2 >/dev/null 2>&1; docker run --rm -v $PWD:/w alpine rm -rf /w/.regression-checks' EXIT
docker run -d --rm --name regress2-lab --network tlsscan-regress2 --network-alias lab-tls tlsscan-lab >/dev/null
sleep 4
rm -rf .regression-checks; mkdir -p .regression-checks/plain .regression-checks/checks; chmod 777 .regression-checks/plain .regression-checks/checks
run() { # run <report> <outdir>
  docker run --rm --network tlsscan-regress2 -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD:/app" -v "$PWD/tests/regression/config:/app/config:ro" \
    -v "$PWD/.regression-checks/$2:/out" -w /app -e PYTHONPATH=/app tlsscan-regression python tls_scan.py --config config/config_checks.yaml --report "$1" >/dev/null 2>&1
}
run lab_plain plain
run lab_checks checks
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
    return re.sub(r"\d+ days?", "<N> days", text)
fail = False
for rel in ("csv/{n}.csv", "csv/{n}_findings.csv", "cbom/{n}.cbom.json"):
    a, b = norm(read("plain", "lab_plain", rel.format(n="lab_plain")), "lab_plain"), norm(read("checks", "lab_checks", rel.format(n="lab_checks")), "lab_checks")
    print(("identical: " if a == b else "DIFFERENT: ") + rel); fail |= a != b
md_plain = norm(read("plain", "lab_plain", "markdown/lab_plain.md"), "lab_plain")
md_checks = norm(read("checks", "lab_checks", "markdown/lab_checks.md"), "lab_checks")
section = re.search(r"\n## Complementary TLS Checks\n.*?(?=\n## )", md_checks, re.S)
stripped = md_checks.replace(section.group(0), "", 1) if section else md_checks
print(("identical: " if stripped == md_plain else "DIFFERENT: ") + "markdown without the new section"); fail |= stripped != md_plain
print("markdown has the section:", bool(section)); fail |= not section
html = read("checks", "lab_checks", "html/lab_checks.html")
print("html has the section:", 'report-chapter" id="tlschecks"' in html, "| plain html has none:", 'report-chapter" id="tlschecks"' not in read("plain", "lab_plain", "html/lab_plain.html"))
fail |= 'report-chapter" id="tlschecks"' not in html
if section:
    print("\n".join(l[:200] for l in section.group(0).splitlines()[:40]))
sys.exit(1 if fail else 0)
PY
